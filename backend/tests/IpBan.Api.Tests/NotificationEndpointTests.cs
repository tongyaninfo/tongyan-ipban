using System.Net;
using System.Text;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging;
using IpBan.Shared.Models;
using IpBan.Shared.Serialization;
using IpBan.Shared.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IpBan.Api.Tests;

/// <summary>仅在 loopback 和独立测试目录验证 HTTP 合同；不启动投递 Worker，不访问真实 SMTP 或 Agent。</summary>
public sealed class NotificationEndpointTests
{
    private const string Root = "/api/admin/v1/notifications";
    private const string SyntheticCredential = "synthetic-notification-authorization-code";

    [Fact]
    public async Task DefaultsUseUnifiedContractAndDoNotExposeCredentialFields()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        using var response = await fixture.Client.GetAsync(Root + "/settings");
        using var body = await AssertResultAsync(response, HttpStatusCode.OK, true, "OK");
        var settings = body.RootElement.GetProperty("data");
        Assert.False(settings.GetProperty("enabled").GetBoolean());
        Assert.False(settings.GetProperty("hasCredential").GetBoolean());
        Assert.Equal("ssl", settings.GetProperty("security").GetString());
        Assert.Equal(465, settings.GetProperty("port").GetInt32());
        Assert.Equal(4, settings.GetProperty("rules").GetArrayLength());
        Assert.False(settings.TryGetProperty("credential", out _));
        Assert.False(settings.TryGetProperty("password", out _));
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Theory]
    [InlineData("PUT", "/settings", false, null, null)]
    [InlineData("POST", "/test", false, null, null)]
    [InlineData("PUT", "/settings", true, "https://foreign.example", null)]
    [InlineData("POST", "/test", true, "https://foreign.example", null)]
    [InlineData("PUT", "/settings", true, null, "cross-site")]
    public async Task WriteBoundaryRejectsMissingHeaderAndCrossOriginBeforeAnyMutation(string method, string path, bool header, string? origin, string? fetchSite)
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var before = await fixture.Client.GetStringAsync(Root + "/settings");
        using var request = new HttpRequestMessage(new HttpMethod(method), Root + path) { Content = Content("{}") };
        if (header) request.Headers.Add("X-IPBan-Management", "1");
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (fetchSite is not null) request.Headers.Add("Sec-Fetch-Site", fetchSite);
        using var response = await fixture.Client.SendAsync(request);
        using var result = await AssertResultAsync(response, HttpStatusCode.Forbidden, false, "NOTIFICATION_ORIGIN_REQUIRED");
        Assert.Equal(before, await fixture.Client.GetStringAsync(Root + "/settings"));
        Assert.Equal(0, await fixture.CountAsync("notification_outbox"));
        Assert.Equal(0, fixture.Sender.Calls);
    }

    [Theory]
    [InlineData("null", "INVALID_JSON")]
    [InlineData("{", "INVALID_JSON")]
    [InlineData("[]", "INVALID_JSON")]
    [InlineData("{}", "INVALID_NOTIFICATION_SETTINGS")]
    [InlineData("{\"settings\":{\"port\":0}}", "INVALID_NOTIFICATION_SETTINGS")]
    public async Task InvalidSettingsReturnJson400AndPreserveConfiguration(string input, string expectedCode)
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var before = await fixture.Client.GetStringAsync(Root + "/settings");
        using var response = await fixture.WriteAsync(HttpMethod.Put, Root + "/settings", input);
        using var result = await AssertResultAsync(response, HttpStatusCode.BadRequest, false, expectedCode);
        Assert.Equal(before, await fixture.Client.GetStringAsync(Root + "/settings"));
    }

    [Fact]
    public async Task CredentialIsWriteOnlyAndBlankUpdatePreservesItWithRevisionConflictProtection()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var settings = await fixture.SaveConfiguredAsync();
        Assert.True(settings.HasCredential);
        Assert.NotEmpty(settings.Revision);
        var responseText = await fixture.Client.GetStringAsync(Root + "/settings");
        Assert.DoesNotContain(SyntheticCredential, responseText, StringComparison.Ordinal);
        using var parsed = JsonDocument.Parse(responseText);
        Assert.False(parsed.RootElement.GetProperty("data").TryGetProperty("credential", out _));

        using var update = await fixture.WriteAsync(HttpMethod.Put, Root + "/settings", Serialize(new(settings with { FromName = "Changed sender" }, "")));
        using var updated = await AssertResultAsync(update, HttpStatusCode.OK, true, "OK");
        Assert.True(updated.RootElement.GetProperty("data").GetProperty("hasCredential").GetBoolean());
        Assert.DoesNotContain(SyntheticCredential, updated.RootElement.GetRawText(), StringComparison.Ordinal);

        using var stale = await fixture.WriteAsync(HttpMethod.Put, Root + "/settings", Serialize(new(settings)));
        using var conflict = await AssertResultAsync(stale, HttpStatusCode.Conflict, false, "NOTIFICATION_SETTINGS_CHANGED");
        var genericSettings = await fixture.Client.GetStringAsync("/api/admin/v1/settings");
        Assert.DoesNotContain(SyntheticCredential, genericSettings, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("notifications.settings")]
    [InlineData("notifications.credential")]
    [InlineData("NOTIFICATIONS.future")]
    public async Task GenericSettingsCannotBypassNotificationValidation(string key)
    {
        await using var fixture = await EndpointFixture.StartAsync();
        using var response = await fixture.WriteAsync(HttpMethod.Put, "/api/admin/v1/settings/" + key, "{\"value\":\"{}\",\"isSecret\":false}");
        using var result = await AssertResultAsync(response, HttpStatusCode.BadRequest, false, "NOTIFICATION_SETTINGS_RESERVED");
        Assert.Equal(0, await fixture.CountAsync("system_settings"));
    }

    [Theory]
    [InlineData("/messages/9223372036854775807", 404, "NOTIFICATION_NOT_FOUND")]
    [InlineData("/messages/not-an-id", 400, "INVALID_NOTIFICATION_ID")]
    [InlineData("/messages?page=0", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?page=abc", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?page=99999999999999999999", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?pageSize=abc", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?pageSize=99999999999999999999", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?pageSize=101", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?status=invalid", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/messages?eventType=invalid", 400, "INVALID_NOTIFICATION_FILTER")]
    [InlineData("/preview/unknown", 400, "INVALID_NOTIFICATION_TYPE")]
    public async Task HistoryAndPreviewFailuresReturnExpectedStatusAndUnifiedBody(string path, int status, string code)
    {
        await using var fixture = await EndpointFixture.StartAsync();
        using var response = await fixture.Client.GetAsync(Root + path);
        using var result = await AssertResultAsync(response, (HttpStatusCode)status, false, code);
    }

    [Theory]
    [InlineData("loginSuccess")]
    [InlineData("loginFailure")]
    [InlineData("ban")]
    [InlineData("unban")]
    [InlineData("summary")]
    public async Task PreviewReadsTemplateWithoutQueuingEmailCreatingCredentialOrInvokingSender(string eventType)
    {
        await using var fixture = await EndpointFixture.StartAsync();
        var before = await fixture.Client.GetStringAsync(Root + "/settings");
        using var response = await fixture.Client.GetAsync(Root + "/preview/" + eventType);
        using var result = await AssertResultAsync(response, HttpStatusCode.OK, true, "OK");
        var rendered = result.RootElement.GetProperty("data");
        Assert.StartsWith("通研IPBan-", rendered.GetProperty("subject").GetString(), StringComparison.Ordinal);
        Assert.Contains("<!doctype html>", rendered.GetProperty("htmlBody").GetString(), StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(rendered.GetProperty("textBody").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(rendered.GetProperty("templateVersion").GetString()));
        Assert.Equal(before, await fixture.Client.GetStringAsync(Root + "/settings"));
        Assert.Equal(0, await fixture.CountAsync("notification_outbox"));
        Assert.Equal(0, await fixture.CountAsync("notification_events"));
        Assert.Equal(0, fixture.Sender.Calls);
        Assert.False(File.Exists(Path.Combine(fixture.Directory, "notifications-key-protection.bin")));
    }

    [Fact]
    public async Task TestMailQueuesWithHistoryAndEnforces429WithoutSynchronousDelivery()
    {
        await using var fixture = await EndpointFixture.StartAsync();
        await fixture.SaveConfiguredAsync();
        using var response = await fixture.WriteAsync(HttpMethod.Post, Root + "/test", "{\"recipient\":\"operator@example.com\"}");
        using var result = await AssertResultAsync(response, HttpStatusCode.OK, true, "OK");
        var id = result.RootElement.GetProperty("data").GetProperty("messageIds")[0].GetString();
        Assert.NotNull(id);
        Assert.Equal(0, fixture.Sender.Calls);
        using var detailResponse = await fixture.Client.GetAsync(Root + "/messages/" + id);
        using var detail = await AssertResultAsync(detailResponse, HttpStatusCode.OK, true, "OK");
        var data = detail.RootElement.GetProperty("data");
        Assert.Equal(id, data.GetProperty("message").GetProperty("id").GetString());
        Assert.Equal("queued", data.GetProperty("message").GetProperty("status").GetString());
        Assert.Equal("operator@example.com", data.GetProperty("message").GetProperty("recipient").GetString());
        Assert.Equal("通研IPBan-邮件服务测试", data.GetProperty("message").GetProperty("subject").GetString());
        Assert.Equal(1, data.GetProperty("events").GetArrayLength());
        Assert.DoesNotContain(SyntheticCredential, data.GetRawText(), StringComparison.Ordinal);
        using var repeated = await fixture.WriteAsync(HttpMethod.Post, Root + "/test", "{\"recipient\":\"operator@example.com\"}");
        using var limited = await AssertResultAsync(repeated, HttpStatusCode.TooManyRequests, false, "NOTIFICATION_TEST_RATE_LIMITED");
        Assert.Equal(TimeSpan.FromSeconds(60), repeated.Headers.RetryAfter?.Delta);
        Assert.Equal(1, await fixture.CountAsync("notification_outbox"));
    }

    private static string Serialize(UpdateNotificationSettingsRequest value) => JsonSerializer.Serialize(value, NotificationJsonContext.Default.UpdateNotificationSettingsRequest);
    private static StringContent Content(string value) => new(value, Encoding.UTF8, "application/json");
    private static async Task<JsonDocument> AssertResultAsync(HttpResponseMessage response, HttpStatusCode status, bool success, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(success, json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
        Assert.False(string.IsNullOrWhiteSpace(json.RootElement.GetProperty("message").GetString()));
        Assert.True(json.RootElement.TryGetProperty("data", out _));
        return json;
    }

    private sealed class EndpointFixture(WebApplication app, HttpClient client, string directory, CountingSender sender) : IAsyncDisposable
    {
        public HttpClient Client { get; } = client;
        public string Directory { get; } = directory;
        public CountingSender Sender { get; } = sender;

        public static async Task<EndpointFixture> StartAsync()
        {
            var directory = Path.Combine(AppContext.BaseDirectory, "notification-endpoint-data", Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing", ContentRootPath = directory });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            await new SqliteDatabaseInitializer(Microsoft.Extensions.Options.Options.Create(new AgentOptions
                { DataDirectory = directory, DatabaseFileName = "test.sqlite3" }), builder.Environment).InitializeAsync();
            builder.Services.Configure<ManagementDataOptions>(options => { options.DataDirectory = directory; options.DatabaseFileName = "test.sqlite3"; });
            builder.Services.AddSingleton<SqliteAdminStore>();
            builder.Services.AddSingleton<NotificationCredentialProtector>();
            builder.Services.AddSingleton<NotificationTemplateRenderer>();
            builder.Services.AddSingleton<NotificationService>();
            builder.Services.AddSingleton<IIdService>(new SequentialIds());
            builder.Services.AddSingleton(TimeProvider.System);
            var sender = new CountingSender();
            builder.Services.AddSingleton<INotificationEmailSender>(sender);
            builder.Services.AddSingleton(new FileLogStore(new FileLoggingOptions(), directory));
            builder.Services.AddIpBanAgentIpc();
            builder.Services.ConfigureHttpJsonOptions(options =>
            {
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpBanJsonContext.Default);
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, NotificationJsonContext.Default);
            });
            var app = builder.Build();
            // 全局账号会话由生产 Program 负责；这里聚焦端点自己的同源、校验与 JSON 合同。
            app.MapManagementEndpoints();
            app.MapNotificationEndpoints();
            await app.StartAsync();
            return new(app, new HttpClient { BaseAddress = new Uri(app.Urls.Single()) }, directory, sender);
        }

        public async Task<HttpResponseMessage> WriteAsync(HttpMethod method, string path, string body)
        {
            using var request = new HttpRequestMessage(method, path) { Content = Content(body) };
            request.Headers.Add("X-IPBan-Management", "1");
            request.Headers.Add("Origin", Client.BaseAddress!.GetLeftPart(UriPartial.Authority));
            return await Client.SendAsync(request);
        }

        public async Task<NotificationSettings> SaveConfiguredAsync()
        {
            var settings = new NotificationSettings { Host = "smtp.example.com", FromAddress = "ipban@example.com", Recipients = ["admin@example.com"] };
            using var response = await WriteAsync(HttpMethod.Put, Root + "/settings", Serialize(new(settings, SyntheticCredential)));
            using var result = await AssertResultAsync(response, HttpStatusCode.OK, true, "OK");
            Assert.DoesNotContain(SyntheticCredential, result.RootElement.GetRawText(), StringComparison.Ordinal);
            return JsonSerializer.Deserialize(result.RootElement.GetProperty("data"), NotificationJsonContext.Default.NotificationSettings)!;
        }

        public async Task<long> CountAsync(string table)
        {
            Assert.True(table is "notification_outbox" or "notification_events" or "system_settings");
            await using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(Directory, "test.sqlite3") }.ToString());
            await db.OpenAsync();
            await using var command = db.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM " + table + ";";
            return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
            // 按项目约定保留本次隔离测试目录，不自动删除文件。
        }
    }

    private sealed class SequentialIds : IIdService
    {
        private long current = 9007199254740992;
        public long NewId => Interlocked.Increment(ref current);
    }

    private sealed class CountingSender : INotificationEmailSender
    {
        public int Calls { get; private set; }
        public Task<NotificationSendResult> SendAsync(NotificationSettings settings, string credential, NotificationEmailEnvelope mail, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("HTTP 端点验证不应触发邮件发送。");
        }
    }
}
