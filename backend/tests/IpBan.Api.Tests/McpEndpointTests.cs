using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using IpBan.Agent.Options;
using IpBan.Agent.Service.impl;
using IpBan.Api.Options;
using IpBan.Api.Service;
using IpBan.Api.Service.impl;
using IpBan.Api.Service.Mcp;
using IpBan.Shared.Logging;
using IpBan.Shared.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IpBan.Api.Tests;

public sealed class McpEndpointTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HttpAndHttpsClientsDiscoverOnlyGrantedToolsAndAuditWithoutCredentials(bool useHttps)
    {
        var directory = Path.Combine(Path.GetTempPath(), "ipban-mcp-endpoint-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var rsa = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ContentRootPath = directory, EnvironmentName = "Testing" });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listener =>
        {
            if (useHttps) listener.UseHttps(certificate);
        }));
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
        builder.Services.AddSingleton<SqliteAdminStore>();
        builder.Services.AddSingleton(new FileLogStore(new FileLoggingOptions(), directory));
        var agent = new McpBusinessToolsTests.FakeAgent();
        builder.Services.AddSingleton<IAgentIpcClient>(agent);
        builder.Services.AddIpBanMcp();
        await using var app = builder.Build();
        // 注入已认证的管理员身份，其余请求经过真实的 Kestrel、来源校验、MCP 和 SQLite。
        app.Use(async (context, next) =>
        {
            context.Items["ipban.user"] = "integration-admin";
            await next(context);
        });
        app.UseIpBanMcpBoundary();
        app.MapIpBanMcp();
        app.MapIpBanAgentIpcEndpoints();
        await app.StartAsync();
        var fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        using var http = new HttpClient(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, remote, _, _) =>
                remote?.GetCertHashString(HashAlgorithmName.SHA256) == fingerprint
        }) { BaseAddress = new Uri(app.Urls.Single()) };
        Assert.Equal(useHttps ? Uri.UriSchemeHttps : Uri.UriSchemeHttp, http.BaseAddress.Scheme);
        const string bans = "/api/admin/v1/bans";
        using (var missingReason = await AdminAsync(HttpMethod.Post, bans, """{"sourceAddress":"192.0.2.30","durationSeconds":-1,"disconnectExisting":false}"""))
        {
            Assert.Equal(HttpStatusCode.BadRequest, missingReason.StatusCode);
            Assert.Null(agent.LastBan);
        }
        using (var permanent = await AdminAsync(HttpMethod.Post, bans, """{"sourceAddress":"192.0.2.30","durationSeconds":-1,"disconnectExisting":false,"reason":"fixture"}"""))
        {
            using var result = await ReadAsync(permanent);
            Assert.Equal("FIREWALL_DISABLED", result.RootElement.GetProperty("code").GetString());
            Assert.Equal(("192.0.2.30", ManualBanDuration.Permanent, false), agent.LastBan);
        }
        var banAudit = await app.Services.GetRequiredService<SqliteAdminStore>().ListAuditAsync();
        Assert.Contains(banAudit, item => item.Action == "ban.create.request" && item.Success);
        Assert.Contains(banAudit, item => item.Action == "ban.create" && !item.Success);
        const string path = "/api/admin/v1/mcp";
        using (var csrf = await http.PutAsync(path + "/settings", Json("""{"enabled":true}""")))
            Assert.Equal(HttpStatusCode.Forbidden, csrf.StatusCode);
        using (var crossOrigin = new HttpRequestMessage(HttpMethod.Put, path + "/settings") { Content = Json("""{"enabled":true}""") })
        {
            crossOrigin.Headers.Add("X-IPBan-Management", "1");
            crossOrigin.Headers.Add("Origin", "https://other.example");
            using var rejected = await http.SendAsync(crossOrigin);
            Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        }
        using (var enabled = await AdminAsync(HttpMethod.Put, path + "/settings", """{"enabled":true}"""))
            enabled.EnsureSuccessStatusCode();
        using (var settings = await AdminAsync(HttpMethod.Put, path + "/settings", """{"auditRetentionDays":12}"""))
            Assert.Equal(HttpStatusCode.Conflict, settings.StatusCode);
        using (var settings = await AdminAsync(HttpMethod.Put, path + "/settings", """{"auditRetentionDays":12,"confirmShorter":true}"""))
        {
            using var result = await ReadAsync(settings);
            Assert.Equal(12, result.RootElement.GetProperty("data").GetProperty("auditRetentionDays").GetInt32());
        }

        using var created = await AdminAsync(HttpMethod.Post, path + "/keys", """{"name":"fixture","mode":"read","scopes":["list_log_files"]}""");
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using var createData = await ReadAsync(created);
        var key = createData.RootElement.GetProperty("data");
        var keyId = key.GetProperty("key").GetProperty("id").GetString();
        var secret = key.GetProperty("secret").GetString()!;
        using (var updateKey = await AdminAsync(HttpMethod.Put, $"{path}/keys/{keyId}", """{"name":"rename"}"""))
            Assert.Equal(HttpStatusCode.MethodNotAllowed, updateKey.StatusCode);
        using (var deleteActiveKey = await AdminAsync(HttpMethod.Delete, $"{path}/keys/{keyId}"))
            Assert.Equal(HttpStatusCode.Conflict, deleteActiveKey.StatusCode);
        using (var copied = await AdminAsync(HttpMethod.Post, $"{path}/keys/{keyId}/copy"))
        {
            using var value = await ReadAsync(copied);
            Assert.True(value.RootElement.GetProperty("data").GetProperty("secret").GetString() == secret, "复制的凭据应匹配创建结果。");
        }
        using (var keyList = await http.GetAsync(path + "/keys"))
            Assert.False((await keyList.Content.ReadAsStringAsync()).Contains(secret, StringComparison.Ordinal), "Key 列表不能包含明文。");

        using (var initialize = await RpcAsync("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}""", secret))
        {
            using var result = await ReadAsync(initialize);
            Assert.Equal("ipban", result.RootElement.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString());
        }
        using (var notification = await RpcAsync("""{"jsonrpc":"2.0","method":"notifications/initialized"}""", secret))
            Assert.Equal(HttpStatusCode.Accepted, notification.StatusCode);
        using (var tools = await RpcAsync("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", secret))
        {
            using var result = await ReadAsync(tools);
            var tool = Assert.Single(result.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray());
            Assert.Equal("list_log_files", tool.GetProperty("name").GetString());
        }
        using (var allowed = await RpcAsync("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_log_files","arguments":{"limit":1}}}""", secret))
        {
            using var result = await ReadAsync(allowed);
            Assert.True(result.RootElement.GetProperty("result").GetProperty("structuredContent").GetProperty("success").GetBoolean());
        }
        using (var denied = await RpcAsync("""{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"create_ban","arguments":{"sourceAddress":"192.0.2.30","durationSeconds":180}}}""", secret))
        {
            using var result = await ReadAsync(denied);
            Assert.True(result.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
        }
        using (var writer = await AdminAsync(HttpMethod.Post, path + "/keys", """{"name":"limited-writer","mode":"write","scopes":["create_ban"]}"""))
        {
            using var keyResult = await ReadAsync(writer);
            var limitedSecret = keyResult.RootElement.GetProperty("data").GetProperty("secret").GetString()!;
            using var denied = await RpcAsync("""{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"create_permanent_ban","arguments":{"sourceAddress":"192.0.2.31","reason":"fixture"}}}""", limitedSecret);
            using var result = await ReadAsync(denied);
            Assert.Equal("TOOL_NOT_ALLOWED", result.RootElement.GetProperty("result").GetProperty("structuredContent").GetProperty("code").GetString());
            Assert.Equal("192.0.2.30", agent.LastBan?.Source);
        }
        using (var writer = await AdminAsync(HttpMethod.Post, path + "/keys", """{"name":"permanent-writer","mode":"write","scopes":["create_permanent_ban"]}"""))
        {
            using var keyResult = await ReadAsync(writer);
            var permanentSecret = keyResult.RootElement.GetProperty("data").GetProperty("secret").GetString()!;
            using var call = await RpcAsync("""{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_permanent_ban","arguments":{"sourceAddress":"192.0.2.32","reason":"fixture"}}}""", permanentSecret);
            using var result = await ReadAsync(call);
            Assert.Equal("FIREWALL_DISABLED", result.RootElement.GetProperty("result").GetProperty("structuredContent").GetProperty("code").GetString());
            Assert.Equal(("192.0.2.32", ManualBanDuration.Permanent, false), agent.LastBan);
        }
        using (var invalid = await RpcAsync("""{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_log_files","arguments":{"limit":1,"limit":2}}}""", secret))
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using (var audits = await http.GetAsync(path + "/audits?tool=list_log_files&status=success"))
        {
            using var result = await ReadAsync(audits);
            var row = Assert.Single(result.RootElement.GetProperty("data").GetProperty("items").EnumerateArray());
            using var detail = await http.GetAsync($"{path}/audits/{row.GetProperty("id").GetString()}");
            using var record = await ReadAsync(detail);
            var data = record.RootElement.GetProperty("data");
            Assert.Contains("list_log_files", data.GetProperty("requestBody").GetString(), StringComparison.Ordinal);
            Assert.Contains("structuredContent", data.GetProperty("responseBody").GetString(), StringComparison.Ordinal);
            Assert.Contains("fixture-header", data.GetProperty("requestHeaders").GetString(), StringComparison.Ordinal);
            Assert.False(data.GetRawText().Contains(secret, StringComparison.Ordinal), "调用审计不能保存 Key 明文。");
        }
        using (var revoked = await AdminAsync(HttpMethod.Post, $"{path}/keys/{keyId}/revoke"))
            revoked.EnsureSuccessStatusCode();
        using (var denied = await RpcAsync("""{"jsonrpc":"2.0","id":5,"method":"tools/list"}""", secret))
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        using (var deleted = await AdminAsync(HttpMethod.Delete, $"{path}/keys/{keyId}"))
            deleted.EnsureSuccessStatusCode();
        using (var history = await http.GetAsync($"{path}/audits?keyId={keyId}"))
        {
            using var result = await ReadAsync(history);
            Assert.True(result.RootElement.GetProperty("data").GetProperty("total").GetInt64() >= 4);
        }

        async Task<HttpResponseMessage> AdminAsync(HttpMethod method, string requestPath, string? payload = null)
        {
            using var request = new HttpRequestMessage(method, requestPath) { Content = payload is null ? null : Json(payload) };
            request.Headers.Add("X-IPBan-Management", "1");
            request.Headers.Add("Origin", http.BaseAddress.GetLeftPart(UriPartial.Authority));
            return await http.SendAsync(request);
        }

        async Task<HttpResponseMessage> RpcAsync(string payload, string apiKey)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = Json(payload) };
            request.Headers.Add("Accept", "application/json, text/event-stream");
            request.Headers.Add("MCP-Protocol-Version", "2025-11-25");
            request.Headers.Add("Origin", http.BaseAddress.GetLeftPart(UriPartial.Authority));
            request.Headers.Authorization = new("Bearer", apiKey);
            request.Headers.Add("X-Test-Header", "fixture-header");
            return await http.SendAsync(request);
        }
    }

    private static StringContent Json(string text) => new(text, Encoding.UTF8, "application/json");

    private static async Task<JsonDocument> ReadAsync(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadAsStringAsync();
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
            payload = payload.Split('\n').First(line => line.StartsWith("data:", StringComparison.Ordinal))[5..].Trim();
        return JsonDocument.Parse(payload);
    }
}
