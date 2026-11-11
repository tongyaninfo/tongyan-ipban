using System.Text.Json;
using IpBan.Api.Models;
using IpBan.Api.Service.impl;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace IpBan.Api.Service.Mcp;

public static class McpEndpointExtensions
{
    internal const string Path = "/mcp";

    public static IServiceCollection AddIpBanMcp(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddSingleton<McpAdmission>();
        services.AddSingleton<McpRequestBoundary>();
        services.AddSingleton<McpStore>();
        services.AddSingleton<McpKeyProtector>();
        services.AddSingleton<IpBan.Shared.Service.IIdService, McpIdService>();
        services.AddHostedService<McpAuditPruneWorker>();
        services.AddScoped<McpBusinessTools>();
        services.AddMcpServer(options =>
        {
            options.ServerInfo = new Implementation { Name = "ipban", Version = "0.1.0", Title = "通研 IPBan" };
            options.Capabilities = new ServerCapabilities { Tools = new ToolsCapability { ListChanged = false } };
        }).WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
            .WithListToolsHandler(ListToolsAsync)
            .WithCallToolHandler(CallToolAsync);
        return services;
    }

    public static IApplicationBuilder UseIpBanMcpBoundary(this IApplicationBuilder app) =>
        app.UseMiddleware<McpRequestBoundary>();

    public static IEndpointRouteBuilder MapIpBanMcp(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapMcp(Path);
        endpoints.MapMcpManagement();
        return endpoints;
    }

    private static ValueTask<ListToolsResult> ListToolsAsync(RequestContext<ListToolsRequestParams> request, CancellationToken cancellationToken)
    {
        var call = CallContext(request.Services);
        var tools = McpBusinessTools.Definitions.Where(tool => IsAllowed(call.Key, tool)).Select(tool => new Tool
        {
            Name = tool.Name,
            Title = tool.Title,
            Description = tool.Description,
            InputSchema = tool.InputSchema,
            Annotations = new ToolAnnotations { ReadOnlyHint = !tool.IsWrite, DestructiveHint = tool.IsDangerous, OpenWorldHint = tool.IsWrite }
        }).ToArray();
        return ValueTask.FromResult(new ListToolsResult { Tools = tools });
    }

    private static async ValueTask<CallToolResult> CallToolAsync(RequestContext<CallToolRequestParams> request, CancellationToken cancellationToken)
    {
        var call = CallContext(request.Services);
        var services = request.Services!;
        var name = request.Params?.Name;
        var tool = McpBusinessTools.Definitions.FirstOrDefault(tool => tool.Name == name);
        if (tool is null || !IsAllowed(call.Key, tool))
        {
            call.Status = "denied";
            return ToolFailure("TOOL_NOT_ALLOWED", "此 API Key 未授权该工具。");
        }

        using var arguments = new MemoryStream();
        using (var writer = new Utf8JsonWriter(arguments))
        {
            writer.WriteStartObject();
            if (request.Params?.Arguments is { } values)
            {
                foreach (var argument in values)
                {
                    writer.WritePropertyName(argument.Key);
                    argument.Value.WriteTo(writer);
                }
            }
            writer.WriteEndObject();
        }
        arguments.Position = 0;
        using var parsedArguments = await JsonDocument.ParseAsync(arguments, cancellationToken: cancellationToken).ConfigureAwait(false);

        // 单次查询重新检查开关、凭据状态和工具授权，之后才交给业务执行器。
        var store = services.GetRequiredService<McpStore>();
        if (!await store.CanInvokeAsync(call.Key.Id, tool.Name, tool.IsWrite, cancellationToken).ConfigureAwait(false))
        {
            call.Status = "denied";
            return ToolFailure("MCP_ACCESS_CHANGED", "MCP 服务或 API Key 状态已变化。");
        }

        using var deadline = tool.IsWrite ? new CancellationTokenSource(TimeSpan.FromSeconds(45))
            : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (!tool.IsWrite) deadline.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            var result = await services.GetRequiredService<McpBusinessTools>()
                .InvokeAsync(tool.Name, parsedArguments.RootElement, $"mcp:{call.Key.Id}",
                    tool.IsWrite ? AuthorizeWriteAsync : null, deadline.Token).ConfigureAwait(false);
            if (call.WriteStarted && result.Code.StartsWith("AGENT_IPC_", StringComparison.Ordinal))
            {
                call.Status = "uncertain";
                return ToolFailure("MCP_RESULT_UNCERTAIN", "执行结果待核验，请按关联 ID 查询记录。");
            }
            call.Status = result.Success ? "success" : result.Code == "MCP_ACCESS_CHANGED" ? "denied" : "error";
            return new CallToolResult
            {
                IsError = !result.Success,
                StructuredContent = JsonSerializer.SerializeToElement(result, McpJsonContext.Default.McpBusinessResult),
                Content = [new TextContentBlock { Text = $"{result.Code} {result.Message}" }]
            };
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            call.Status = call.WriteStarted ? "uncertain" : "error";
            return ToolFailure(call.WriteStarted ? "MCP_RESULT_UNCERTAIN" : "MCP_TOOL_ERROR",
                call.WriteStarted ? "执行结果待核验，请按关联 ID 查询记录。" : "工具暂时无法完成请求。");
        }

        async Task<bool> AuthorizeWriteAsync(CancellationToken token)
        {
            call.WriteStarted = await store.CanInvokeAsync(call.Key.Id, tool.Name, write: true, token).ConfigureAwait(false);
            return call.WriteStarted;
        }
    }

    private static bool IsAllowed(McpApiKey key, McpToolDefinition tool) =>
        (!tool.IsWrite || key.Mode == "write") && key.Scopes.Contains(tool.Name, StringComparer.Ordinal);

    private static McpRequestContext CallContext(IServiceProvider? services) =>
        services!.GetRequiredService<IHttpContextAccessor>().HttpContext!.Features.Get<McpRequestContext>()!;

    private static CallToolResult ToolFailure(string code, string message) => new()
    {
        IsError = true,
        StructuredContent = JsonSerializer.SerializeToElement(new McpBusinessResult(false, code, message, null), McpJsonContext.Default.McpBusinessResult),
        Content = [new TextContentBlock { Text = message }]
    };
}

internal sealed class McpRequestContext(McpApiKey key)
{
    public McpApiKey Key { get; } = key;
    public string? Status { get; set; }
    public bool WriteStarted { get; set; }
}
