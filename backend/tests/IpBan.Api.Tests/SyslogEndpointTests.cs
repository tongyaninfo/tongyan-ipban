using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Serialization;
using IpBan.Shared.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IpBan.Api.Tests;

public sealed class SyslogEndpointTests
{
    private const string Root = "/api/admin/v1/syslog";

    [Fact]
    public async Task SettingsRequireSessionAndSameOriginAndKeepDeliveryVersionUntilEndpointChanges()
    {
        await using var fixture = await Fixture.StartAsync();
        using var unauthenticated = await fixture.Client.GetAsync(Root + "/settings");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        var candidate = new SyslogSettings(Targets: [new("", "", "本机测试接收器", "127.0.0.1", 514, "udp")]);
        using var foreignOrigin = await fixture.SaveAsync(candidate, "http://other.invalid");
        Assert.Equal(HttpStatusCode.Forbidden, foreignOrigin.StatusCode);

        using var first = await fixture.SaveAsync(candidate);
        var configured = await ReadSettingsAsync(first);
        var target = Assert.Single(configured.Targets!);
        Assert.NotEmpty(target.Id);
        Assert.NotEmpty(target.DeliveryTargetVersion);

        using var stale = await fixture.SaveAsync(candidate);
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);

        using var filtered = await fixture.SaveAsync(configured with { Targets = [target with { MaxSeverity = 2, Enabled = false }] });
        var filteredSettings = await ReadSettingsAsync(filtered);
        Assert.NotEqual(configured.ConfigRevision, filteredSettings.ConfigRevision);
        Assert.Equal(target.DeliveryTargetVersion, Assert.Single(filteredSettings.Targets!).DeliveryTargetVersion);

        using var replaced = await fixture.SaveAsync(filteredSettings with { Targets = [target with { Port = 1514 }] });
        var replacedSettings = await ReadSettingsAsync(replaced);
        Assert.NotEqual(target.DeliveryTargetVersion, Assert.Single(replacedSettings.Targets!).DeliveryTargetVersion);

        using var invalid = await fixture.SaveAsync(replacedSettings with { Targets = [target with { IgnoreSslErrors = true }] });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using var reserved = await fixture.WriteAsync(HttpMethod.Put, "/api/admin/v1/settings/syslog.settings", """{"value":"{}"}""");
        Assert.Equal(HttpStatusCode.BadRequest, reserved.StatusCode);

        var audit = await fixture.Store.ListAuditAsync();
        Assert.Equal(3, audit.Count(row => row.Action == "syslog.settings.update" && row.ActorUsername == "synthetic-admin"));
    }

    [Fact]
    public async Task TestUsesSavedTargetAndReturnsPacketIdentifierWithoutClaimingUdpReceipt()
    {
        await using var fixture = await Fixture.StartAsync();
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;
        // 旧版本可能已保存非默认设施。新版读取原记录并使用固定报文头。
        var legacy = $$"""{"configRevision":"0","targets":[{"id":"receiver","deliveryTargetVersion":"v1","name":"本机接收器","host":"127.0.0.1","port":{{port}},"protocol":"udp","facility":23}]}""";
        await fixture.Store.UpsertSettingAsync(SyslogConfiguration.SettingKey, legacy, false, "synthetic-admin");
        using var saved = await fixture.WriteAsync(HttpMethod.Get, Root + "/settings", "");
        var settings = await ReadSettingsAsync(saved);
        using var savedJson = JsonDocument.Parse(await saved.Content.ReadAsStringAsync());
        Assert.False(savedJson.RootElement.GetProperty("data").GetProperty("targets")[0].TryGetProperty("facility", out _));
        var targetId = Assert.Single(settings.Targets!).Id;
        var json = $$"""{"targetId":"{{targetId}}","configRevision":"{{settings.ConfigRevision}}"}""";

        using var response = await fixture.WriteAsync(HttpMethod.Post, Root + "/test", json);
        response.EnsureSuccessStatusCode();
        using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var data = result.RootElement.GetProperty("data");
        Assert.Equal("udpSent", data.GetProperty("stage").GetString());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var packet = Encoding.UTF8.GetString((await receiver.ReceiveAsync(timeout.Token)).Buffer);
        Assert.StartsWith("<133>1 ", packet, StringComparison.Ordinal);
        Assert.Contains("syslog-test-host ipban-syslog", packet, StringComparison.Ordinal);
        Assert.Contains(data.GetProperty("testId").GetString()!, packet, StringComparison.Ordinal);

        using var repeated = await fixture.WriteAsync(HttpMethod.Post, Root + "/test", json);
        Assert.Equal(HttpStatusCode.TooManyRequests, repeated.StatusCode);
    }

    private static async Task<SyslogSettings> ReadSettingsAsync(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return JsonSerializer.Deserialize(json.RootElement.GetProperty("data"), SyslogJsonContext.Default.SyslogSettings)!;
    }

    private sealed class Fixture(WebApplication app, HttpClient client) : IAsyncDisposable
    {
        public HttpClient Client { get; } = client;
        public SqliteAdminStore Store => app.Services.GetRequiredService<SqliteAdminStore>();

        public static async Task<Fixture> StartAsync()
        {
            var directory = Path.Combine(AppContext.BaseDirectory, "syslog-endpoint-data", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing", ContentRootPath = directory });
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();
            await new SqliteDatabaseInitializer(Microsoft.Extensions.Options.Options.Create(new AgentOptions
                { DataDirectory = directory, DatabaseFileName = "test.sqlite3" }), builder.Environment).InitializeAsync();
            builder.Services.Configure<ManagementDataOptions>(options => { options.DataDirectory = directory; options.DatabaseFileName = "test.sqlite3"; });
            builder.Services.AddSingleton<SqliteAdminStore>();
            builder.Services.AddSingleton<ISyslogSettingsReader, SyslogSettingsReader>();
            builder.Services.AddSingleton<SyslogManagementService>();
            builder.Services.AddSingleton<IIdService, SequentialIds>();
            builder.Services.AddSingleton(TimeProvider.System);
            builder.Services.AddSingleton(new FileLogStore(new FileLoggingOptions(), directory));
            builder.Services.AddIpBanAgentIpc();
            builder.Services.AddIpBanSyslog(builder.Logging, "api", directory, "test-host");
            builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpBanJsonContext.Default));

            var application = builder.Build();
            application.Use(async (context, next) =>
            {
                if (context.Request.Headers["X-Synthetic-Session"] == "1") context.Items["ipban.user"] = "synthetic-admin";
                await next().ConfigureAwait(false);
            });
            application.MapManagementEndpoints();
            application.MapSyslogEndpoints();
            await application.StartAsync();
            return new(application, new HttpClient { BaseAddress = new Uri(application.Urls.Single()) });
        }

        public Task<HttpResponseMessage> SaveAsync(SyslogSettings settings, string? origin = null) =>
            WriteAsync(HttpMethod.Put, Root + "/settings", JsonSerializer.Serialize(settings, SyslogJsonContext.Default.SyslogSettings), origin);

        public async Task<HttpResponseMessage> WriteAsync(HttpMethod method, string path, string body, string? origin = null)
        {
            using var request = new HttpRequestMessage(method, path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            request.Headers.Add("X-Synthetic-Session", "1");
            request.Headers.Add("X-IPBan-Management", "1");
            request.Headers.Add("Origin", origin ?? Client.BaseAddress!.GetLeftPart(UriPartial.Authority));
            return await Client.SendAsync(request).ConfigureAwait(false);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed class SequentialIds : IIdService
    {
        private long nextId;
        public long NewId => Interlocked.Increment(ref nextId);
    }
}
