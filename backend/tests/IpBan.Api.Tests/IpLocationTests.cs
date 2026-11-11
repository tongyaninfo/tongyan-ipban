using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Models;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Api.Workers;
using IpBan.Shared.Logging;
using IpBan.Shared.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace IpBan.Api.Tests;

public sealed class IpLocationTests
{
    [Theory]
    [InlineData("CZ88")]
    [InlineData("ip2location")]
    [InlineData("ip2region")]
    [InlineData("dbip")]
    [InlineData("ipinfo")]
    [InlineData("geolite2")]
    public async Task ProviderUsesSelectedDatabaseAndPreservesAttribution(string database)
    {
        Uri? requested = null;
        using var provider = new TongYanIPLocation(new HttpClient(new Handler((request, _) =>
        {
            requested = request.RequestUri;
            return Task.FromResult(JsonResponse(Fixture(database)));
        })));
        var result = await provider.ResolveAsync("1.1.1.1", new(Database: database), CancellationToken.None);
        Assert.Equal($"https://ip.tongyaninfo.com/?ip=1.1.1.1&db={database}&format=json", requested!.AbsoluteUri);
        Assert.Equal("resolved", result.Status);
        Assert.Equal("澳大利亚", result.Country);
        Assert.Equal("昆士兰", result.Province);
        Assert.Equal("昆士兰", result.Region);
        Assert.Equal("Brisbane", result.City);
        Assert.Equal("AS13335", result.Asn);
        Assert.Equal("2026-10-31T18:21:41Z", result.Version);
        Assert.Equal("Database attribution", result.Attribution);
        Assert.Equal("https://example.com/license", result.LicenseUrl);
    }

    [Theory]
    [InlineData("{", "failed")]
    [InlineData("{\"success\":false}", "failed")]
    [InlineData("{\"success\":true,\"data\":{\"ip\":\"8.8.8.8\",\"sources\":[]}}", "failed")]
    [InlineData("{\"success\":true,\"data\":{\"ip\":\"1.1.1.1\",\"sources\":[{\"id\":\"CZ88\",\"status\":\"success\",\"fields\":{\"country\":null,\"region\":null}}]}}", "notFound")]
    [InlineData("{\"success\":true,\"data\":{\"ip\":\"1.1.1.1\",\"sources\":[{\"id\":\"ipinfo\",\"status\":\"success\",\"fields\":{\"country\":\"other\"}}]}}", "notFound")]
    public async Task ProviderRejectsMalformedMismatchAndEmptyPayloads(string body, string expected)
    {
        using var provider = new TongYanIPLocation(new HttpClient(new Handler((_, _) => Task.FromResult(JsonResponse(body)))));
        Assert.Equal(expected, (await provider.ResolveAsync("1.1.1.1", new(), CancellationToken.None)).Status);
    }

    [Fact]
    public async Task ProviderHonorsTimeoutAndDoesNotConvertCallerCancellationToResult()
    {
        using var provider = new TongYanIPLocation(new HttpClient(new Handler(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return JsonResponse("{}");
        })));
        Assert.Equal("timeout", (await provider.ResolveAsync("1.1.1.1", new(TimeoutSeconds: 0.1), CancellationToken.None)).Status);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.ResolveAsync("1.1.1.1", new(), cancellation.Token));
    }

    [Fact]
    public async Task ProviderBoundsResponseAndDoesNotAcceptRedirectResponse()
    {
        using var oversized = new TongYanIPLocation(new HttpClient(new Handler((_, _) => Task.FromResult(JsonResponse(new string('x', 131073))))));
        Assert.Equal("failed", (await oversized.ResolveAsync("1.1.1.1", new(), CancellationToken.None)).Status);
        using var redirect = new TongYanIPLocation(new HttpClient(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect)))));
        Assert.Equal("failed", (await redirect.ResolveAsync("1.1.1.1", new(), CancellationToken.None)).Status);
    }

    [Theory]
    [InlineData("file", "example.com", 443, "CZ88", 2)]
    [InlineData("https", "https://example.com/", 443, "CZ88", 2)]
    [InlineData("https", "user@example.com", 443, "CZ88", 2)]
    [InlineData("https", "example.com?a=1", 443, "CZ88", 2)]
    [InlineData("https", "example.com", 0, "CZ88", 2)]
    [InlineData("https", "example.com", 65536, "CZ88", 2)]
    [InlineData("https", "example.com", 443, "unknown", 2)]
    [InlineData("https", "example.com", 443, "CZ88", 0)]
    [InlineData("https", "example.com", 443, "CZ88", 31)]
    public void ConfigurationValidationRejectsInvalidBoundaries(string protocol, string host, int port, string database, double timeout)
        => Assert.False(IpLocationService.TryValidate(new(true, protocol, host, port, database, timeout), out _, out _));

    [Fact]
    public async Task DefaultDisabledAndSpecialAddressesNeverCallProvider()
    {
        await using var fixture = await TestFixture.CreateAsync();
        Assert.Equal(new IpLocationSettings(), await fixture.Service.GetSettingsAsync(CancellationToken.None));
        Assert.Equal("disabled", fixture.Service.Lookup(["1.1.1.1"]).Items[0].Status);
        await fixture.EnableAsync();
        var results = fixture.Service.Lookup(["192.168.1.2", "127.0.0.1", "::1", "fc00::1", "192.0.2.1", "2001:db8::1", "2001:2::1", "3fff::1", "1.2.3.0/24", "invalid"]);
        Assert.Equal(["private", "private", "private", "private", "reserved", "reserved", "reserved", "reserved", "network", "invalid"], results.Items.Select(item => item.Status));
        var provider = new Provider((ip, _, _) => Task.FromResult(new IpLocationResult(ip, "resolved")));
        await fixture.StartWorkerAsync(provider);
        await Task.Delay(25);
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public async Task QueueIsBoundedAndLookupDoesNotWaitForNetwork()
    {
        await using var fixture = await TestFixture.CreateAsync();
        await fixture.EnableAsync();
        var stopwatch = Stopwatch.StartNew();
        var first = fixture.Service.Lookup(Enumerable.Range(0, IpLocationService.QueueCapacity).Select(Address).ToArray());
        Assert.All(first.Items, item => Assert.Equal("queued", item.Status));
        Assert.Equal("busy", fixture.Service.Lookup(["8.8.8.8"]).Items[0].Status);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task WorkerUsesTwoConsumersDeduplicatesAndCancelsWhenDisabled()
    {
        await using var fixture = await TestFixture.CreateAsync();
        await fixture.EnableAsync();
        var cancelled = 0;
        var provider = new Provider(async (ip, _, token) =>
        {
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            finally { Interlocked.Increment(ref cancelled); }
            return new(ip, "resolved");
        });
        await fixture.StartWorkerAsync(provider);
        fixture.Service.Lookup(["1.1.1.1", "1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        await WaitUntilAsync(() => provider.Calls == 2);
        Assert.Equal(2, provider.MaximumActive);
        await fixture.Service.UpdateSettingsAsync(new(), "tester", null, CancellationToken.None);
        await WaitUntilAsync(() => Volatile.Read(ref cancelled) == 2);
        Assert.Equal(2, provider.Calls);
        Assert.Equal("disabled", fixture.Service.Lookup(["1.1.1.1"]).Items[0].Status);
    }

    [Fact]
    public async Task CacheNormalizesAddressesPreservesInputAndExpiresWithSeparateTtls()
    {
        await using var fixture = await TestFixture.CreateAsync();
        await fixture.EnableAsync();
        var provider = new Provider((ip, _, _) => Task.FromResult(new IpLocationResult(ip, ip == "8.8.8.8" ? "failed" : "resolved", Country: "Australia")));
        await fixture.StartWorkerAsync(provider);
        fixture.Service.Lookup(["::ffff:1.1.1.1", "1.1.1.1", "8.8.8.8"]);
        await WaitUntilAsync(() => fixture.Service.Lookup(["1.1.1.1", "8.8.8.8"]).Items.All(item => item.Status != "queued"));
        Assert.Equal(2, provider.Calls);
        Assert.Equal("::ffff:1.1.1.1", fixture.Service.Lookup(["::ffff:1.1.1.1"]).Items[0].Ip);
        fixture.Clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal("resolved", fixture.Service.Lookup(["1.1.1.1"]).Items[0].Status);
        Assert.Equal("queued", fixture.Service.Lookup(["8.8.8.8"]).Items[0].Status);
        await WaitUntilAsync(() => provider.Calls == 3);
        fixture.Clock.Advance(TimeSpan.FromDays(1));
        Assert.Equal("queued", fixture.Service.Lookup(["1.1.1.1"]).Items[0].Status);
    }

    [Fact]
    public async Task ChangedConfigurationDoesNotPublishOldInFlightResult()
    {
        await using var fixture = await TestFixture.CreateAsync();
        await fixture.EnableAsync();
        var oldResult = new TaskCompletionSource<IpLocationResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new Provider((ip, settings, _) => settings.Database == "CZ88" ? oldResult.Task
            : Task.FromResult(new IpLocationResult(ip, "resolved", Country: "New", Database: settings.Database)));
        await fixture.StartWorkerAsync(provider);
        var revision = fixture.Service.Lookup(["1.1.1.1"]).Revision;
        await WaitUntilAsync(() => provider.Calls == 1);
        await fixture.Service.UpdateSettingsAsync(new(Enabled: true, Database: "ipinfo"), "tester", null, CancellationToken.None);
        oldResult.SetResult(new("1.1.1.1", "resolved", Country: "Old", Database: "CZ88"));
        await WaitUntilAsync(() => fixture.Service.Lookup(["1.1.1.1"]).Items[0].Status == "resolved");
        var result = fixture.Service.Lookup(["1.1.1.1"]);
        Assert.NotEqual(revision, result.Revision);
        Assert.Equal("New", result.Items[0].Country);
        Assert.Equal("ipinfo", result.Items[0].Database);
    }

    [Fact]
    public async Task CacheCapacityEvictsAnEntryAfterTenThousandResults()
    {
        await using var fixture = await TestFixture.CreateAsync();
        await fixture.EnableAsync();
        var provider = new Provider((ip, _, _) => Task.FromResult(new IpLocationResult(ip, "resolved")));
        await fixture.StartWorkerAsync(provider);
        for (var start = 0; start < IpLocationService.CacheCapacity; start += 100)
        {
            var batch = Enumerable.Range(start, 100).Select(Address).ToArray();
            fixture.Service.Lookup(batch);
            await WaitUntilAsync(() => fixture.Service.Lookup(batch).Items.All(item => item.Status == "resolved"));
        }
        Assert.Equal(IpLocationService.CacheCapacity, provider.Calls);
        fixture.Service.Lookup([Address(IpLocationService.CacheCapacity)]);
        await WaitUntilAsync(() => fixture.Service.Lookup([Address(IpLocationService.CacheCapacity)]).Items[0].Status == "resolved");
        // 两个消费者完成的先后顺序不固定；验证容量而非假定某个 IP 必须先被淘汰。
        var previous = fixture.Service.Lookup(Enumerable.Range(0, IpLocationService.CacheCapacity).Select(Address).ToArray());
        Assert.Single(previous.Items, item => item.Status == "queued");
    }

    [Fact]
    public async Task SettingsAndAuditCommitTogetherAndReloadWithoutSchemaChange()
    {
        await using var fixture = await TestFixture.CreateAsync();
        await fixture.EnableAsync();
        using var connection = new SqliteConnection($"Data Source={fixture.Store.DatabasePath}");
        await connection.OpenAsync();
        using var actor = connection.CreateCommand();
        actor.CommandText = "SELECT actor_username FROM audit_records WHERE action='ip-location.settings.update';";
        Assert.Equal("tester", await actor.ExecuteScalarAsync());
        var saved = await fixture.Store.GetIpLocationSettingsAsync(CancellationToken.None);
        Assert.True(JsonSerializer.Deserialize(saved!, IpLocationJsonContext.Default.IpLocationSettings)!.Enabled);
        using var reloaded = new IpLocationService(fixture.Store, fixture.Clock);
        Assert.True((await reloaded.GetSettingsAsync(CancellationToken.None)).Enabled);
    }

    [Fact]
    public async Task StorageFailureDoesNotActivateNewConfiguration()
    {
        await using var fixture = await TestFixture.CreateAsync();
        using var service = new IpLocationService(fixture.CreateUnavailableStore(), fixture.Clock);
        await Assert.ThrowsAsync<SqliteException>(() => service.UpdateSettingsAsync(new(Enabled: true), "tester", null, CancellationToken.None));
        Assert.False(service.Lookup(["1.1.1.1"]).Enabled);
        Assert.Equal("disabled", service.Lookup(["1.1.1.1"]).Items[0].Status);
        Assert.Null(await fixture.Store.GetIpLocationSettingsAsync(CancellationToken.None));
    }

    [Fact]
    public async Task EndpointValidatesBoundariesUsesAotContractAndProtectsReservedSetting()
    {
        await using var fixture = await TestFixture.CreateAsync(withHttp: true);
        var client = fixture.Client!;
        using var get = JsonDocument.Parse(await client.GetStringAsync("/api/admin/v1/ip-location/settings"));
        Assert.False(get.RootElement.GetProperty("data").GetProperty("enabled").GetBoolean());
        Assert.Equal(2, get.RootElement.GetProperty("data").GetProperty("timeoutSeconds").GetDouble());
        using var missingHeader = await client.PostAsync("/api/admin/v1/ip-location/lookup", Content("{\"ips\":[\"1.1.1.1\"]}"));
        Assert.Equal(HttpStatusCode.Forbidden, missingHeader.StatusCode);
        client.DefaultRequestHeaders.Add("X-IPBan-Management", "1");
        using var badSettings = await client.PutAsync("/api/admin/v1/ip-location/settings", Content("{\"timeoutSeconds\":0}"));
        Assert.Equal(HttpStatusCode.BadRequest, badSettings.StatusCode);
        using var nullBody = await client.PostAsync("/api/admin/v1/ip-location/lookup", Content("null"));
        Assert.Equal(HttpStatusCode.BadRequest, nullBody.StatusCode);
        using var tooMany = await client.PostAsync("/api/admin/v1/ip-location/lookup", Content("{\"ips\":[" + string.Join(',', Enumerable.Repeat("\"1.1.1.1\"", 101)) + "]}"));
        Assert.Equal(HttpStatusCode.BadRequest, tooMany.StatusCode);
        using var reserved = await client.PutAsync("/api/admin/v1/settings/ip-location", Content("{\"value\":\"{}\"}"));
        Assert.Equal(HttpStatusCode.BadRequest, reserved.StatusCode);
        using var post = await client.PostAsync("/api/admin/v1/ip-location/lookup", Content("{\"ips\":[\"1.1.1.1\"]}"));
        using var result = JsonDocument.Parse(await post.Content.ReadAsStringAsync());
        Assert.True(result.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("disabled", result.RootElement.GetProperty("data").GetProperty("items")[0].GetProperty("status").GetString());
        client.DefaultRequestHeaders.Add("Origin", "https://foreign.example");
        using var foreign = await client.PutAsync("/api/admin/v1/ip-location/settings", Content("{}"));
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
    }

    private static string Address(int index) => $"11.{index >> 16}.{index >> 8 & 255}.{index & 255}";
    private static StringContent Content(string body) => new(body, Encoding.UTF8, "application/json");
    private static HttpResponseMessage JsonResponse(string body) => new(HttpStatusCode.OK) { Content = Content(body) };
    private static string Fixture(string database) => $$$"""
        {"success":true,"code":"OK","data":{"ip":"1.1.1.1","sources":[{"id":"{{{database}}}","status":"success","version":"2026-10-31T18:21:41Z","fields":{"country":"澳大利亚","region":"昆士兰","city":"Brisbane","asn":"AS13335"},"attribution":"Database attribution","licenseUrl":"https://example.com/license"}]}}
        """;
    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        var watch = Stopwatch.StartNew();
        while (!predicate())
        {
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), "后台工作未在预期时间完成。");
            await Task.Delay(5);
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => handler(request, cancellationToken);
    }

    private sealed class Provider(Func<string, IpLocationSettings, CancellationToken, Task<IpLocationResult>> resolve) : IIPLocation
    {
        private int _calls;
        private int _active;
        private int _maximumActive;
        public int Calls => Volatile.Read(ref _calls);
        public int MaximumActive => Volatile.Read(ref _maximumActive);
        public async Task<IpLocationResult> ResolveAsync(string ip, IpLocationSettings settings, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            var active = Interlocked.Increment(ref _active);
            int observed;
            do { observed = MaximumActive; }
            while (active > observed && Interlocked.CompareExchange(ref _maximumActive, active, observed) != observed);
            try { return await resolve(ip, settings, cancellationToken); }
            finally { Interlocked.Decrement(ref _active); }
        }
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 10, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    /// <summary>仅随机回环端口和专属临时 SQLite；不启动 Agent，不触及防火墙，不删除测试文件。</summary>
    private sealed class TestFixture(WebApplication app, SqliteAdminStore store, IpLocationService service, TestClock clock, HttpClient? client) : IAsyncDisposable
    {
        public SqliteAdminStore Store { get; } = store;
        public IpLocationService Service { get; } = service;
        public TestClock Clock { get; } = clock;
        public HttpClient? Client { get; } = client;
        private IpLocationWorker? _worker;

        public static async Task<TestFixture> CreateAsync(bool withHttp = false)
        {
            var directory = Path.Combine(Path.GetTempPath(), "ipban-ip-location-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing", ContentRootPath = directory });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            await new SqliteDatabaseInitializer(Microsoft.Extensions.Options.Options.Create(new AgentOptions
                { DataDirectory = directory, DatabaseFileName = "test.sqlite3" }), builder.Environment).InitializeAsync();
            builder.Services.Configure<ManagementDataOptions>(options => { options.DataDirectory = directory; options.DatabaseFileName = "test.sqlite3"; });
            builder.Services.AddSingleton<SqliteAdminStore>();
            var clock = new TestClock();
            builder.Services.AddSingleton<TimeProvider>(clock);
            builder.Services.AddSingleton<IpLocationService>();
            builder.Services.AddSingleton(new FileLogStore(new FileLoggingOptions(), directory));
            builder.Services.AddIpBanAgentIpc();
            builder.Services.ConfigureHttpJsonOptions(options =>
            {
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpBanJsonContext.Default);
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpLocationJsonContext.Default);
            });
            var app = builder.Build();
            HttpClient? client = null;
            if (withHttp)
            {
                app.MapManagementEndpoints();
                app.MapIpLocationEndpoints();
                await app.StartAsync();
                client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
            }
            return new(app, app.Services.GetRequiredService<SqliteAdminStore>(), app.Services.GetRequiredService<IpLocationService>(), clock, client);
        }

        public Task<IpLocationSettings> EnableAsync() => Service.UpdateSettingsAsync(new(Enabled: true), "tester", null, CancellationToken.None);
        public SqliteAdminStore CreateUnavailableStore() => new(Microsoft.Extensions.Options.Options.Create(new ManagementDataOptions
            { DataDirectory = Path.Combine(Store.DatabasePath, "unavailable") }), app.Environment);
        public async Task StartWorkerAsync(IIPLocation provider)
        {
            _worker = new IpLocationWorker(Service, provider, NullLogger<IpLocationWorker>.Instance);
            await _worker.StartAsync(CancellationToken.None);
        }
        public async ValueTask DisposeAsync()
        {
            if (_worker is not null) { await _worker.StopAsync(CancellationToken.None); _worker.Dispose(); }
            Client?.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }
}
