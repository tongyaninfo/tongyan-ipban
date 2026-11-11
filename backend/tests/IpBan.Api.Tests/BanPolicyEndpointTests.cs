using System.Globalization;
using System.Net;
using System.Text;
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
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IpBan.Api.Tests;

public sealed class BanPolicyEndpointTests
{
    [Theory]
    [InlineData("banDurationSeconds", "999999999999", "INVALID_BAN_POLICY_DURATION")]
    [InlineData("banDurationSeconds", "-2", "INVALID_BAN_POLICY_DURATION")]
    [InlineData("banDurationSeconds", "1.5", "INVALID_BAN_POLICY_DURATION")]
    [InlineData("banDurationSeconds", "null", "INVALID_BAN_POLICY_DURATION")]
    [InlineData("banDurationSeconds", "\"\"", "INVALID_BAN_POLICY_DURATION")]
    [InlineData("threshold", "999999999999", "INVALID_BAN_POLICY_THRESHOLD")]
    [InlineData("threshold", "0", "INVALID_BAN_POLICY_THRESHOLD")]
    [InlineData("windowSeconds", "0", "INVALID_BAN_POLICY_WINDOW")]
    [InlineData("windowSeconds", "1.5", "INVALID_BAN_POLICY_WINDOW")]
    [InlineData("observeSeconds", "-1", "INVALID_BAN_POLICY_OBSERVE")]
    [InlineData("observeSeconds", "999999999999", "INVALID_BAN_POLICY_OBSERVE")]
    [InlineData("cooldownSeconds", "-1", "INVALID_BAN_POLICY_COOLDOWN")]
    [InlineData("cooldownSeconds", "null", "INVALID_BAN_POLICY_COOLDOWN")]
    public async Task InvalidNumericFieldReturnsFriendly400AndPreservesSavedPolicy(
        string field, string value, string expectedCode)
    {
        await using var host = await PolicyTestHost.StartAsync();
        var id = await host.CreatePolicyAsync();
        var before = await host.Client.GetStringAsync("/api/admin/v1/policies");
        using var response = await host.PutAsync(id, $$"""{"name":"Existing policy","enabled":false,"{{field}}":{{value}}}""");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(expectedCode, json.RootElement.GetProperty("code").GetString());
        Assert.Contains("整数", json.RootElement.GetProperty("message").GetString());
        Assert.True(json.RootElement.TryGetProperty("data", out _));
        Assert.Equal(before, await host.Client.GetStringAsync("/api/admin/v1/policies"));
    }

    [Theory]
    [InlineData("{")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{\"name\":null}")]
    [InlineData("{\"name\":\"Existing policy\",\"action\":null}")]
    public async Task MalformedPolicyReturnsUnified400WithoutChangingPolicy(string body)
    {
        await using var host = await PolicyTestHost.StartAsync();
        var id = await host.CreatePolicyAsync();
        var before = await host.Client.GetStringAsync("/api/admin/v1/policies");
        using var response = await host.PutAsync(id, body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("INVALID_BAN_POLICY", json.RootElement.GetProperty("code").GetString());
        Assert.Equal(before, await host.Client.GetStringAsync("/api/admin/v1/policies"));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1800)]
    [InlineData(int.MaxValue)]
    public async Task DurationAndEffectiveActionSaveAndReadBack(int durationSeconds)
    {
        await using var host = await PolicyTestHost.StartAsync();
        var id = await host.CreatePolicyAsync();
        using var response = await host.PutAsync(id,
            $$"""{"name":"Existing policy","enabled":false,"banDurationSeconds":{{durationSeconds}}}""");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(json.RootElement.GetProperty("success").GetBoolean());
        var expectedAction = durationSeconds == 0 ? "Observe" : "Ban";
        Assert.Equal(durationSeconds, json.RootElement.GetProperty("data").GetProperty("banDurationSeconds").GetInt32());
        Assert.Equal(expectedAction, json.RootElement.GetProperty("data").GetProperty("action").GetString());
        using var query = JsonDocument.Parse(await host.Client.GetStringAsync("/api/admin/v1/policies"));
        var saved = query.RootElement.GetProperty("data").EnumerateArray()
            .Single(item => item.GetProperty("name").GetString() == "Existing policy");
        Assert.Equal(durationSeconds, saved.GetProperty("banDurationSeconds").GetInt32());
        Assert.Equal(expectedAction, saved.GetProperty("action").GetString());
        Assert.Equal(durationSeconds, await host.ReadStoredDurationAsync(id));
        Assert.Equal(2, saved.GetProperty("version").GetInt32());
    }

    [Fact]
    public async Task LegacyZeroReadsAsUnlimitedWithoutRewritingDatabase()
    {
        await using var host = await PolicyTestHost.StartAsync();
        var id = await host.CreatePolicyAsync();
        await host.SetLegacyZeroDurationAsync(id);

        using var query = JsonDocument.Parse(await host.Client.GetStringAsync("/api/admin/v1/policies"));
        var saved = query.RootElement.GetProperty("data").EnumerateArray()
            .Single(item => item.GetProperty("id").ToString() == id);
        Assert.Equal(-1, saved.GetProperty("banDurationSeconds").GetInt32());
        Assert.Equal(1, saved.GetProperty("version").GetInt32());
        Assert.Equal(0, await host.ReadStoredDurationAsync(id));

        // 编辑保存才写入新合同值；兼容读取本身不执行迁移或暗中改写旧策略。
        using var response = await host.PutAsync(id,
            """{"name":"Existing policy","enabled":false,"banDurationSeconds":-1}""");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(-1, await host.ReadStoredDurationAsync(id));
    }

    /// <summary>
    /// 真实Kestrel和策略端点验证HTTP合同；不启动Agent，不触及宿主防火墙。
    /// 账号认证不属于本测试目标，仅在随机回环端口开放测试路由，库独立且保留便于复查。
    /// </summary>
    private sealed class PolicyTestHost(WebApplication application, HttpClient client) : IAsyncDisposable
    {
        public HttpClient Client { get; } = client;

        public static async Task<PolicyTestHost> StartAsync()
        {
            var directory = Path.Combine(Path.GetTempPath(), "ipban-api-policy-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = "Testing",
                ContentRootPath = directory
            });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            await new SqliteDatabaseInitializer(Microsoft.Extensions.Options.Options.Create(new AgentOptions
            {
                DataDirectory = directory,
                DatabaseFileName = "test.sqlite3"
            }), builder.Environment).InitializeAsync();
            builder.Services.Configure<ManagementDataOptions>(options =>
            {
                options.DataDirectory = directory;
                options.DatabaseFileName = "test.sqlite3";
            });
            builder.Services.ConfigureHttpJsonOptions(options =>
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpBanJsonContext.Default));
            builder.Services.AddSingleton<SqliteAdminStore>();
            builder.Services.AddSingleton(new FileLogStore(new FileLoggingOptions(), directory));
            builder.Services.AddIpBanAgentIpc();
            var app = builder.Build();
            app.MapManagementEndpoints();
            await app.StartAsync();
            return new PolicyTestHost(app, new HttpClient { BaseAddress = new Uri(app.Urls.Single()) });
        }

        public async Task<string> CreatePolicyAsync()
        {
            using var response = await PutAsync(null,
                """{"name":"Existing policy","enabled":false,"banDurationSeconds":1800}""");
            response.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("data").GetProperty("id").ToString();
        }

        public Task<HttpResponseMessage> PutAsync(string? id, string body) => Client.PutAsync(
            $"/api/admin/v1/policies{(id is null ? string.Empty : $"/{id}")}",
            new StringContent(body, Encoding.UTF8, "application/json"));

        public async Task SetLegacyZeroDurationAsync(string id)
        {
            await using var connection = await OpenTestDatabaseAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE ban_policies SET ban_duration_seconds=0 WHERE id=$id;";
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        public async Task<int> ReadStoredDurationAsync(string id)
        {
            await using var connection = await OpenTestDatabaseAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT ban_duration_seconds FROM ban_policies WHERE id=$id;";
            command.Parameters.AddWithValue("$id", id);
            return Convert.ToInt32(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture);
        }

        private async Task<SqliteConnection> OpenTestDatabaseAsync()
        {
            var store = application.Services.GetRequiredService<SqliteAdminStore>();
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = store.DatabasePath,
                Mode = SqliteOpenMode.ReadWrite
            }.ToString());
            await connection.OpenAsync();
            return connection;
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await application.StopAsync();
            await application.DisposeAsync();
        }
    }
}
