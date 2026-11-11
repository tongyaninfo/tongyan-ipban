using IpBan.Shared.Models;
using IpBan.Shared.Logging;
using IpBan.Shared.Logging.Syslog;
using IpBan.Shared.Serialization;
using IpBan.Shared.Service;
using IpBan.Api.Service;
using IpBan.Api.Options;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using IpBan.Api.Service.Mcp;
using System.Text.Json;
using System.Net;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddIpBanFileLogging(builder.Configuration, builder.Environment.ContentRootPath);

// 默认监听 IPv4 的 0.0.0.0；部署时可用 ASPNETCORE_URLS 覆盖，HTTPS 证书接入后再增加 TLS endpoint。
var managementConfiguration = builder.Configuration.GetSection("Management");
var listenAddress = managementConfiguration["ListenAddress"] ?? "0.0.0.0";
var configuredHttpPort = int.TryParse(managementConfiguration["HttpPort"], out var httpPort)
    ? httpPort
    : 5180;
var httpsEnabled = !string.Equals(managementConfiguration["HttpsEnabled"], "false", StringComparison.OrdinalIgnoreCase);
var configuredHttpsPort = int.TryParse(managementConfiguration["HttpsPort"], out var httpsPort)
    ? httpsPort
    : 8443;
if (string.IsNullOrWhiteSpace(builder.Configuration["ASPNETCORE_URLS"]))
{
    builder.WebHost.ConfigureKestrel(serverOptions =>
    {
        var address = IPAddress.TryParse(listenAddress, out var parsedAddress)
            ? parsedAddress
            : IPAddress.Any;
        serverOptions.Listen(address, configuredHttpPort);
        if (httpsEnabled)
        {
            var certificatePath = CertificateRuntime.EnsureSelfSignedCertificate(
                builder.Configuration,
                builder.Environment.ContentRootPath);
            serverOptions.Listen(address, configuredHttpsPort, listenOptions =>
                listenOptions.UseHttps(certificatePath, string.Empty));
        }
    });
}

// 管理台默认绑定由部署配置控制；首次启动不创建默认账号，由初始化向导创建首个管理员。
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, IpBanJsonContext.Default);
});
builder.Services.AddIpBanAgentIpc();
builder.Services.AddSignalR();
builder.Services.AddHostedService<ManagementRealtimeWorker>();
builder.Services.Configure<ManagementDataOptions>(builder.Configuration.GetSection(ManagementDataOptions.SectionName));
builder.Services.AddSingleton<SqliteAdminStore>();
builder.Services.AddIpLocation();
builder.Services.AddIpBanMcp();
builder.Services.AddIpBanNotifications();
builder.Services.AddSingleton<ISyslogSettingsReader, SyslogSettingsReader>();
builder.Services.AddSingleton<SyslogManagementService>();
builder.Services.AddIpBanSyslog(builder.Logging, "api", Path.GetFullPath(
    builder.Configuration["Agent:DataDirectory"] ?? "data", builder.Environment.ContentRootPath),
    builder.Configuration["Syslog:ComputerName"]);
builder.Services.AddSingleton(services => new FileLogStore(
    FileLoggingOptions.Load(builder.Configuration),
    builder.Environment.ContentRootPath,
    services.GetRequiredService<FileLoggerProvider>()));

var app = builder.Build();
var syslog = app.Services.GetRequiredService<SyslogRuntime>();
app.Lifetime.ApplicationStarted.Register(() => syslog.Publish("ipban-runtime", "api.started", SyslogSeverity.Notice, "IPBan 管理 API 已启动。"));
app.Lifetime.ApplicationStopping.Register(() => syslog.Publish("ipban-runtime", "api.stopping", SyslogSeverity.Notice, "IPBan 管理 API 正在停止。"));
app.Use(next => context => ApiRequestLogging.InvokeAsync(context, next, syslog));

// 不提供健康探测接口，也不让前端回退页伪装成健康响应。
app.Use(async (context, next) =>
{
    if (context.Request.Path.Equals("/health", StringComparison.OrdinalIgnoreCase)
        || context.Request.Path.Equals("/api/health", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return;
    }

    await next().ConfigureAwait(false);
});

app.UseIpBanMcpBoundary();
app.UseDefaultFiles();
app.UseStaticFiles();

const string SessionCookieName = "ipban.session";

// 管理 API 统一要求本机用户会话；健康检查、登录和首次初始化保持匿名可访问。
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/admin")
        || context.Request.Path.StartsWithSegments(ManagementHub.Path))
    {
        var store = context.RequestServices.GetRequiredService<SqliteAdminStore>();
        var token = context.Request.Path.StartsWithSegments(ManagementHub.Path)
            ? ManagementHub.ReadSessionToken(context)
            : context.Request.Cookies[SessionCookieName];
        var user = string.IsNullOrWhiteSpace(token)
            ? null
            : await store.GetUserBySessionAsync(UserPasswordHasher.HashToken(token), context.RequestAborted).ConfigureAwait(false);
        if (user is null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(ApiResult<string>.Fail("AUTH_REQUIRED", "请先登录管理台。"),
                IpBanJsonContext.Default.ApiResultString, cancellationToken: context.RequestAborted).ConfigureAwait(false);
            return;
        }
        context.Items["ipban.user"] = user.Username;
    }

    await next().ConfigureAwait(false);
});

app.MapGet("/api/setup/status", async (SqliteAdminStore store, CancellationToken cancellationToken) =>
    Results.Ok(ApiResult<SetupStatusContract>.Ok(
        new SetupStatusContract(await store.HasUsersAsync(cancellationToken).ConfigureAwait(false)),
        "初始化状态查询成功。")));

app.MapPost("/api/setup/initialize", async (HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
{
    if (await store.HasUsersAsync(cancellationToken).ConfigureAwait(false))
    {
        return Results.Conflict(ApiResult<UserSummaryContract>.Fail("ALREADY_INITIALIZED", "系统已经完成初始化。"));
    }

    var body = await JsonSerializer.DeserializeAsync(request.Body, ManagementJsonContext.Default.UpsertUserRequest, cancellationToken).ConfigureAwait(false);
    if (body is null || string.IsNullOrWhiteSpace(body.Username) || string.IsNullOrWhiteSpace(body.Password))
    {
        return Results.BadRequest(ApiResult<UserSummaryContract>.Fail("INVALID_USER", "用户名和密码不能为空。"));
    }

    try
    {
        var audit = ManagementAuditContext.From(request.HttpContext) with { Actor = body.Username.Trim() };
        var user = await store.UpsertUserAsync(null, body with { Enabled = true }, audit, "setup.initialize", cancellationToken).ConfigureAwait(false);
        await SignInAsync(user, request, store, "login.success", cancellationToken).ConfigureAwait(false);
        return Results.Ok(ApiResult<UserSummaryContract>.Ok(user, "管理员初始化成功。"));
    }
    catch (Microsoft.Data.Sqlite.SqliteException exception) when (exception.SqliteErrorCode == 19)
    {
        return Results.Conflict(ApiResult<UserSummaryContract>.Fail("ALREADY_INITIALIZED", "系统已经完成初始化。"));
    }
});

app.MapGet("/api/currentUser", async (HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
{
    var token = request.Cookies[SessionCookieName];
    var user = string.IsNullOrWhiteSpace(token)
        ? null
        : await store.GetUserBySessionAsync(UserPasswordHasher.HashToken(token), cancellationToken).ConfigureAwait(false);
    return user is null
        ? Results.Unauthorized()
        : Results.Ok(ApiResult<CurrentUserContract>.Ok(new CurrentUserContract(user.DisplayName, user.Username, "admin")));
});

app.MapPost("/api/login/account", async (HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
{
    var context = request.HttpContext;
    var remoteIp = context.Connection.RemoteIpAddress?.ToString();
    try
    {
        LoginAccountRequest? body;
        try
        {
            body = await JsonSerializer.DeserializeAsync(request.Body, ManagementJsonContext.Default.LoginAccountRequest, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (JsonException) { body = null; }
        var user = body is not null && !string.IsNullOrWhiteSpace(body.Username) && !string.IsNullOrWhiteSpace(body.Password)
            ? await store.AuthenticateUserAsync(body.Username, body.Password, cancellationToken).ConfigureAwait(false)
            : null;
        if (user is not null)
        {
            await SignInAsync(user, request, store, "login.success", cancellationToken).ConfigureAwait(false);
            return Results.Ok(new LoginResponseContract("ok", "account", "admin"));
        }

        // 失败输入未经验证，外发仅保留远端地址及结果，不复制账号表单或认证材料。
        await store.AppendAuditAsync("login.failure", "login", null, null, remoteIp, false, null, context.TraceIdentifier,
            result: "rejected", cancellationToken: cancellationToken).ConfigureAwait(false);
        return Results.Ok(new LoginResponseContract("error", "account", string.Empty));
    }
    catch (Exception error) when (error is Microsoft.Data.Sqlite.SqliteException or IOException or UnauthorizedAccessException
        or System.Security.Cryptography.CryptographicException)
    {
        store.PublishAudit("login.error", null, null, remoteIp, false, context.TraceIdentifier, "LOGIN_UNAVAILABLE");
        return Results.Json(ApiResult<string>.Fail("LOGIN_UNAVAILABLE", "管理台登录暂不可用。"),
            IpBanJsonContext.Default.ApiResultString, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.MapPost("/api/login/outLogin", async (HttpRequest request, SqliteAdminStore store, CancellationToken cancellationToken) =>
{
    if (request.Cookies[SessionCookieName] is { } token)
    {
        var tokenHash = UserPasswordHasher.HashToken(token);
        var user = await store.GetUserBySessionAsync(tokenHash, cancellationToken).ConfigureAwait(false);
        await store.RevokeUserSessionAsync(tokenHash, user?.Username,
            request.HttpContext.Connection.RemoteIpAddress?.ToString(), request.HttpContext.TraceIdentifier, cancellationToken).ConfigureAwait(false);
        request.HttpContext.Response.Cookies.Delete(SessionCookieName);
    }

    return Results.Ok(new LoginResponseContract("ok", "account", string.Empty));
});

app.MapGet("/api/admin/v1/system/status", () =>
{
    var status = new SystemStatusContract(
        Version: "0.1.0",
        Platform: OperatingSystem.IsWindows() ? "windows" : "linux",
        Runtime: Environment.Version.ToString(),
        Ready: false,
        FirewallStatus.Unsupported);

    return TypedResults.Ok(ApiResult<SystemStatusContract>.Ok(status, "管理 API 骨架已启动"));
});

app.MapIpBanAgentIpcEndpoints();
app.MapManagementEndpoints();
app.MapIpLocationEndpoints();
app.MapNotificationEndpoints();
app.MapSyslogEndpoints();
app.MapIpBanMcp();
app.MapHub<ManagementHub>(ManagementHub.Path);

app.MapGet(
    "/api/admin/v1/sessions",
    async (IAgentIpcClient client, CancellationToken cancellationToken) =>
    {
        var connections = await client.ListConnectionsAsync(cancellationToken).ConfigureAwait(false);
        if (!connections.Success || connections.Data is null)
        {
            return Results.Ok(ApiResult<LoginSessionContract[]>.Fail(
                connections.Code,
                connections.Message));
        }

        var events = await client.ListLoginEventsAsync(1000, cancellationToken).ConfigureAwait(false);
        var sessions = CurrentSessionProjector.Project(
            connections.Data,
            events.Success && events.Data is not null
                ? events.Data
                : Array.Empty<LoginEventContract>());

        return Results.Ok(ApiResult<LoginSessionContract[]>.Ok(
            sessions.ToArray(),
            events.Success
                ? "当前登录会话查询成功。"
                : "当前登录会话已查询，用户名关联暂不可用。"));
    });

app.MapPost(
    "/api/admin/v1/sessions/{sessionId}/disconnect",
    async (string sessionId, HttpContext context, IAgentIpcClient client, SqliteAdminStore store, CancellationToken cancellationToken) =>
    {
        var connections = await client.ListConnectionsAsync(cancellationToken).ConfigureAwait(false);
        if (!connections.Success || connections.Data is null)
        {
            return Results.Ok(ApiResult<ConnectionTerminationContract>.Fail(
                connections.Code,
                connections.Message));
        }

        var events = await client.ListLoginEventsAsync(1000, cancellationToken).ConfigureAwait(false);
        var sessions = CurrentSessionProjector.Project(
            connections.Data,
            events.Success && events.Data is not null
                ? events.Data
                : Array.Empty<LoginEventContract>());
        if (!sessions.Any(session => session.SessionId.Equals(sessionId, StringComparison.Ordinal)))
        {
            return Results.NotFound(ApiResult<ConnectionTerminationContract>.Fail(
                "SESSION_NOT_FOUND",
                "会话不存在或已结束。"));
        }

        var connection = connections.Data.FirstOrDefault(
            candidate => CurrentSessionProjector.BuildSessionId(candidate)
                .Equals(sessionId, StringComparison.Ordinal));
        if (connection is null)
        {
            return Results.NotFound(ApiResult<ConnectionTerminationContract>.Fail(
                "SESSION_CONNECTION_NOT_FOUND",
                "会话对应的当前连接不存在。"));
        }

        var result = await ManagementDisconnect.RunAsync(context, store, client, connection, cancellationToken)
            .ConfigureAwait(false);
        return Results.Ok(result);
    });

app.MapFallbackToFile("index.html");

app.Run();

static async Task SignInAsync(
    UserSummaryContract user,
    HttpRequest request,
    SqliteAdminStore store,
    string auditAction,
    CancellationToken cancellationToken)
{
    var token = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
    await store.CreateUserSessionAsync(
        user.Id,
        UserPasswordHasher.HashToken(token),
        request.HttpContext.Connection.RemoteIpAddress?.ToString(),
        DateTimeOffset.UtcNow.AddDays(7),
        auditAction, user.Username, request.HttpContext.TraceIdentifier, cancellationToken).ConfigureAwait(false);
    request.HttpContext.Response.Cookies.Append("ipban.session", token, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = request.IsHttps,
        IsEssential = true,
        MaxAge = TimeSpan.FromDays(7)
    });
}
