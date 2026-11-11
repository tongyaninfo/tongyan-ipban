using System.Globalization;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Models;
using IpBan.Api.Options;
using IpBan.Api.Service.impl;
using IpBan.Shared.Service;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace IpBan.Api.Tests;

public sealed class McpStoreTests
{
    [Fact]
    public async Task KeyRevocationAndDeletionPreserveAuditAndBlockReuse()
    {
        var (store, path) = await CreateStoreAsync();
        var created = await store.CreateKeyAsync("fixture", false, null, ["read_test", "write_test"], "fixture-admin", null);
        Assert.Equal(created.Key.Id, (await store.AuthenticateAsync(created.Secret))?.Id);
        Assert.False(await store.CanInvokeAsync(created.Key.Id, "read_test", false));
        await store.UpdateSettingsAsync(true, null, false, "fixture-admin", null);
        Assert.True(await store.CanInvokeAsync(created.Key.Id, "read_test", false));
        Assert.False(await store.CanInvokeAsync(created.Key.Id, "write_test", true));
        Assert.False(await store.CanInvokeAsync(created.Key.Id, "ungranted", false));
        var copied = await store.ReadKeySecretAsync(created.Key.Id, "fixture-admin", null);
        Assert.NotNull(copied);
        Assert.Equal(UserPasswordHasher.HashToken(created.Secret), UserPasswordHasher.HashToken(copied));

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT secret_hash, protected_secret FROM mcp_api_keys;";
        await using (var reader = await command.ExecuteReaderAsync())
        {
            Assert.True(await reader.ReadAsync());
            Assert.False(string.Equals(created.Secret, reader.GetString(0), StringComparison.Ordinal));
            Assert.False(reader.GetFieldValue<byte[]>(1).AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes(created.Secret)) >= 0);
        }

        var callId = await store.BeginCallAsync(new McpCallStart(created.Key, "fixture-trace", "192.0.2.2", "tools/call", "read_test", "{}", "{}"));
        await store.CompleteCallAsync(callId, "success", 200, 10, "{}", "{\"ok\":true}");
        Assert.False(await store.DeleteKeyAsync(created.Key.Id, "fixture-admin", null));
        Assert.True(await store.RevokeKeyAsync(created.Key.Id, "fixture-admin", null));
        Assert.True(await store.RevokeKeyAsync(created.Key.Id, "fixture-admin", null));
        Assert.Null(await store.AuthenticateAsync(created.Secret));
        Assert.Null(await store.ReadKeySecretAsync(created.Key.Id, "fixture-admin", null));
        Assert.False(await store.CanInvokeAsync(created.Key.Id, "read_test", false));
        Assert.True(await store.DeleteKeyAsync(created.Key.Id, "fixture-admin", null));
        Assert.Empty(await store.ListKeysAsync());
        var filtered = await store.ListCallsAsync(new McpCallFilter(null, null, created.Key.Id, "read_test", "success"));
        Assert.Equal(callId, Assert.Single(filtered.Items).Id);
        var detail = Assert.IsType<McpCallDetail>(await store.GetCallAsync(callId));
        Assert.Equal("fixture", detail.Call.KeyName);
        Assert.Equal("{\"ok\":true}", detail.ResponseBody);

        command.CommandText = "SELECT COUNT(*) FROM audit_records WHERE category = 'mcp' AND actor_username = 'fixture-admin';";
        Assert.Equal(5L, await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task RetentionUsesConfirmedCurrentSettingsAndDoesNotRemovePendingCalls()
    {
        var (store, path) = await CreateStoreAsync();
        var initial = await store.GetSettingsAsync();
        Assert.False(initial.Enabled);
        Assert.Equal(30, initial.AuditRetentionDays);
        var rejected = await Assert.ThrowsAsync<McpStoreException>(() => store.UpdateSettingsAsync(null, 10, false, "fixture-admin", null));
        Assert.Equal("RETENTION_CONFIRMATION_REQUIRED", rejected.Code);
        await store.UpdateSettingsAsync(null, 10, true, "fixture-admin", null);

        var expired = await store.BeginCallAsync(new McpCallStart(null, "expired", null, "tools/list", null, null, null));
        await store.CompleteCallAsync(expired, "denied", 401, 1, null, null);
        var pending = await store.BeginCallAsync(new McpCallStart(null, "pending", null, "tools/call", null, null, null));
        var recent = await store.BeginCallAsync(new McpCallStart(null, "recent", null, "tools/list", null, null, null));
        await store.CompleteCallAsync(recent, "denied", 401, 1, null, null);

        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE mcp_call_audits SET occurred_at_utc = $old WHERE id IN ($expired, $pending);";
        command.Parameters.AddWithValue("$old", DateTimeOffset.UtcNow.AddDays(-11).ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$expired", expired);
        command.Parameters.AddWithValue("$pending", pending);
        await command.ExecuteNonQueryAsync();

        Assert.Equal(1, await store.PruneAsync());
        Assert.Null(await store.GetCallAsync(expired));
        Assert.NotNull(await store.GetCallAsync(pending));
        Assert.NotNull(await store.GetCallAsync(recent));
        await store.CompleteCallAsync(pending, "uncertain", 502, 10, null, null);
        Assert.Equal(1, await store.PruneAsync());
    }

    private static async Task<(McpStore Store, string Path)> CreateStoreAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ipban-mcp-store-tests", Guid.NewGuid().ToString("N"));
        var environment = new TestEnvironment(directory);
        var initializer = new SqliteDatabaseInitializer(Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = directory }), environment);
        await initializer.InitializeAsync();
        var admin = new SqliteAdminStore(Microsoft.Extensions.Options.Options.Create(new ManagementDataOptions { DataDirectory = directory }), environment);
        return (new McpStore(admin, new McpKeyProtector(admin), new TestIdService()), initializer.DatabasePath);
    }

    private sealed class TestIdService : IIdService
    {
        private long next;
        public long NewId => Interlocked.Increment(ref next);
    }

    private sealed class TestEnvironment(string directory) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "IpBan.Api.Tests";
        public string ContentRootPath { get; set; } = directory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
