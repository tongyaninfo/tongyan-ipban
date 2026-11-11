using System.Net;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Shared.Logging;
using IpBan.Shared.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IpBan.Api.Tests;

/// <summary>仅验证不执行物理删除的拒绝路径；夹具文件完整保留，测试不调用成功删除分支。</summary>
public sealed class LogFileDeletionTests
{
    private const string Archive = "ipban-20261109.ndjson.120000001";

    [Theory]
    [InlineData("ipban-20261109.ndjson", 409, "LOG_FILE_PROTECTED")]
    [InlineData("ipban-20261108.ndjson", 409, "LOG_FILE_PROTECTED")]
    [InlineData("other.txt", 400, "LOG_FILE_INVALID")]
    [InlineData("..\\ipban-20261109.ndjson.120000001", 400, "LOG_FILE_INVALID")]
    [InlineData("ipban-20261399.ndjson.120000001", 400, "LOG_FILE_INVALID")]
    [InlineData("ipban-20261109.ndjson.990000001", 400, "LOG_FILE_INVALID")]
    [InlineData(Archive, 404, "LOG_FILE_NOT_FOUND")]
    public async Task RejectionReturnsUnifiedResponseAndAuditsActualActor(string name, int status, string code)
    {
        await using var host = await LogTestHost.StartAsync();
        using var response = await host.DeleteAsync(name);
        Assert.Equal((HttpStatusCode)status, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
        Assert.True(json.RootElement.TryGetProperty("data", out _));
        var audits = await host.Store.ListAuditAsync();
        Assert.Equal(2, audits.Count);
        Assert.All(audits, audit => Assert.Equal("regression-admin", audit.ActorUsername));
        Assert.Contains(audits, audit => audit.Action == "logs.file.delete.request" && audit.Success);
        Assert.Contains(audits, audit => audit.Action == "logs.file.delete" && !audit.Success);
        Assert.All(audits, audit => Assert.DoesNotContain(host.Directory, audit.Target ?? string.Empty));
    }

    [Fact]
    public async Task MissingAuthenticationCannotReachDeletionOrAudit()
    {
        await using var host = await LogTestHost.StartAsync(authenticated: false);
        var path = await host.CreateAsync(Archive);
        using var response = await host.DeleteAsync(Archive);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(File.Exists(path));
        Assert.Empty(await host.Store.ListAuditAsync());
    }

    [Fact]
    public async Task UnavailableIntentAuditPreservesEligibleArchive()
    {
        await using var host = await LogTestHost.StartAsync(auditAvailable: false);
        var path = await host.CreateAsync(Archive);
        using var response = await host.DeleteAsync(Archive);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("LOG_DELETE_AUDIT_UNAVAILABLE", json.RootElement.GetProperty("code").GetString());
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task WriterHeldArchiveIsRejectedBeforePhysicalDeletion()
    {
        await using var host = await LogTestHost.StartAsync();
        var path = await host.CreateAsync(Archive);
        // 与真实logger一致的共享写句柄模拟另一进程仍持有已轮转inode。
        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        // 先证明当前系统租约确实冲突；若语义不满足即停止，绝不尝试可能成功删除的请求。
        Assert.Throws<IOException>(() => new FileStream(path, FileMode.Open, FileAccess.Read,
            OperatingSystem.IsWindows() ? FileShare.Delete : FileShare.None));
        using var response = await host.DeleteAsync(Archive);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.True(File.Exists(path));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("LOG_FILE_BUSY", json.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task ArchiveOperationLeasePreventsDeletionDuringRotation()
    {
        await using var host = await LogTestHost.StartAsync();
        var path = await host.CreateAsync(Archive);
        var lockPath = Path.Combine(host.Directory, ".ipban-archive.lock");
        using var lease = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        Assert.Throws<IOException>(() => new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
        using var response = await host.DeleteAsync(Archive);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task EmptyArchiveAndDirectoryTargetsAreProtected()
    {
        await using var host = await LogTestHost.StartAsync();
        var empty = Path.Combine(host.Directory, Archive);
        await File.WriteAllTextAsync(empty, string.Empty);
        using var emptyResponse = await host.DeleteAsync(Archive);
        Assert.Equal(HttpStatusCode.Conflict, emptyResponse.StatusCode);
        var directoryName = Archive + ".gz";
        System.IO.Directory.CreateDirectory(Path.Combine(host.Directory, directoryName));
        using var directoryResponse = await host.DeleteAsync(directoryName);
        Assert.Equal(HttpStatusCode.Conflict, directoryResponse.StatusCode);
        Assert.True(File.Exists(empty));
        Assert.True(System.IO.Directory.Exists(Path.Combine(host.Directory, directoryName)));
    }

    [Fact]
    public async Task ListingExposesDeletionEligibilityWithoutDeletingAnything()
    {
        await using var host = await LogTestHost.StartAsync();
        await host.CreateAsync("ipban-20261109.ndjson");
        await host.CreateAsync("ipban-20261108.ndjson");
        await host.CreateAsync(Archive);
        await host.CreateAsync(Archive + ".gz");
        await File.WriteAllTextAsync(Path.Combine(host.Directory, "ipban-20261109.ndjson.120000002"), string.Empty);
        using var response = await host.Client.GetAsync("/api/admin/v1/logs/files");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var records = json.RootElement.GetProperty("data").EnumerateArray().ToArray();
        Assert.Equal(5, records.Length);
        Assert.Equal(2, records.Count(record => record.GetProperty("canDelete").GetBoolean()));
        Assert.All(records.Where(record => record.GetProperty("name").GetString()!.EndsWith(".ndjson", StringComparison.Ordinal)),
            record => Assert.False(record.GetProperty("canDelete").GetBoolean()));
        Assert.Equal(5, System.IO.Directory.GetFiles(host.Directory, "ipban-*.ndjson*").Length);
    }

    [Fact]
    public async Task SymbolicLinkTargetIsRejectedWithoutFollowingIt()
    {
        if (OperatingSystem.IsWindows()) return; // Windows 测试环境创建符号链接需要额外系统权限。
        await using var host = await LogTestHost.StartAsync();
        var original = await host.CreateAsync("original.txt");
        var link = Path.Combine(host.Directory, Archive);
        File.CreateSymbolicLink(link, original);
        using var response = await host.DeleteAsync(Archive);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("LOG_FILE_UNSAFE", json.RootElement.GetProperty("code").GetString());
        Assert.NotNull(new FileInfo(link).LinkTarget);
        Assert.True(File.Exists(original));
    }

    [Fact]
    public async Task TrustedConfiguredDirectoryLinkResolvesToPhysicalLogRoot()
    {
        if (OperatingSystem.IsWindows()) return;
        await using var host = await LogTestHost.StartAsync();
        var path = await host.CreateAsync(Archive);
        var link = Path.Combine(Path.GetDirectoryName(host.Directory)!, "configured-log-link");
        System.IO.Directory.CreateSymbolicLink(link, host.Directory);
        var store = new FileLogStore(new FileLoggingOptions { Directory = link }, Path.GetDirectoryName(host.Directory)!);
        var file = Assert.Single(store.ListFiles());
        Assert.Equal(Archive, file.Name);
        Assert.True(file.CanDelete);
        Assert.True(File.Exists(path));
        Assert.NotNull(new DirectoryInfo(link).LinkTarget);
        // 仅读取列表验证配置根兼容，绝不执行删除，链接和目标均保留。
    }

    private sealed class LogTestHost(WebApplication app, HttpClient client, string directory) : IAsyncDisposable
    {
        public string Directory { get; } = directory;
        public HttpClient Client { get; } = client;
        public SqliteAdminStore Store => app.Services.GetRequiredService<SqliteAdminStore>();

        public static async Task<LogTestHost> StartAsync(bool authenticated = true, bool auditAvailable = true)
        {
            var root = Path.Combine(Path.GetTempPath(), "ipban-log-delete-tests", Guid.NewGuid().ToString("N"));
            var logs = Path.Combine(root, "logs");
            System.IO.Directory.CreateDirectory(logs);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing", ContentRootPath = root });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            if (auditAvailable)
                await new SqliteDatabaseInitializer(Microsoft.Extensions.Options.Options.Create(new AgentOptions
                { DataDirectory = root, DatabaseFileName = "test.sqlite3" }), builder.Environment).InitializeAsync();
            builder.Services.Configure<ManagementDataOptions>(options =>
            { options.DataDirectory = root; options.DatabaseFileName = "test.sqlite3"; });
            builder.Services.ConfigureHttpJsonOptions(options =>
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpBanJsonContext.Default));
            builder.Services.AddSingleton<SqliteAdminStore>();
            builder.Services.AddSingleton(new FileLogStore(new FileLoggingOptions { Directory = logs }, root));
            builder.Services.AddIpBanAgentIpc();
            var application = builder.Build();
            if (authenticated)
                application.Use((context, next) => { context.Items["ipban.user"] = "regression-admin"; return next(context); });
            application.MapManagementEndpoints();
            await application.StartAsync();
            return new LogTestHost(application, new HttpClient { BaseAddress = new Uri(application.Urls.Single()) }, logs);
        }

        public async Task<string> CreateAsync(string name)
        {
            var path = Path.Combine(Directory, name);
            await File.WriteAllTextAsync(path, "{\"message\":\"synthetic retained fixture\"}\n");
            return path;
        }

        public Task<HttpResponseMessage> DeleteAsync(string name) =>
            Client.DeleteAsync("/api/admin/v1/logs/files/" + Uri.EscapeDataString(name));

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
            // 按用户约束保留所有文件，包括测试夹具和数据库。
        }
    }
}
