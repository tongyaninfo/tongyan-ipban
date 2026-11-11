using System.Text.Json;
using System.Net;
using IpBan.Api.Models;

namespace IpBan.Api.Service.impl;

/// <summary>通研 IP 查询适配器。超时包含响应体读取，不自动重试或跟随重定向。</summary>
public sealed class TongYanIPLocation(HttpClient client) : IIPLocation, IDisposable
{
    private const int MaximumResponseBytes = 128 * 1024;

    public void Dispose() => client.Dispose();

    public async Task<IpLocationResult> ResolveAsync(string ip, IpLocationSettings settings, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));
        try
        {
            var uri = new UriBuilder(settings.Protocol, settings.Host, settings.Port, "/")
            {
                Query = $"ip={Uri.EscapeDataString(ip)}&db={Uri.EscapeDataString(settings.Database)}&format=json"
            }.Uri;
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > MaximumResponseBytes)
                return new(ip, "failed", Database: settings.Database);

            await using var input = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                var count = await input.ReadAsync(buffer, deadline.Token).ConfigureAwait(false);
                if (count == 0) break;
                if (output.Length + count > MaximumResponseBytes)
                    return new(ip, "failed", Database: settings.Database);
                await output.WriteAsync(buffer.AsMemory(0, count), deadline.Token).ConfigureAwait(false);
            }

            using var document = JsonDocument.Parse(output.GetBuffer().AsMemory(0, (int)output.Length), new JsonDocumentOptions { MaxDepth = 32 });
            return Parse(ip, settings.Database, document.RootElement);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(ip, "timeout", Database: settings.Database);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException or InvalidOperationException)
        {
            // 只返回固定状态，不将内部地址、响应正文或异常堆栈传给管理台。
            return new(ip, "failed", Database: settings.Database);
        }
    }

    private static IpLocationResult Parse(string ip, string database, JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("success", out var success) || success.ValueKind != JsonValueKind.True
            || !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object
            || !data.TryGetProperty("sources", out var sources) || sources.ValueKind != JsonValueKind.Array)
            return new(ip, "failed", Database: database);
        if (!IPAddress.TryParse(Text(data, "ip"), out var returnedIp) || !IPAddress.TryParse(ip, out var requestedIp)
            || !returnedIp.Equals(requestedIp)) return new(ip, "failed", Database: database);

        foreach (var source in sources.EnumerateArray())
        {
            if (source.ValueKind != JsonValueKind.Object || !string.Equals(Text(source, "id"), database, StringComparison.OrdinalIgnoreCase))
                continue;
            var result = new IpLocationResult(ip, "notFound", Database: database,
                Version: Text(source, "version"), Attribution: Text(source, "attribution"), LicenseUrl: SafeUrl(Text(source, "licenseUrl")));
            if (!string.Equals(Text(source, "status"), "success", StringComparison.OrdinalIgnoreCase))
                return result with { Status = "failed" };
            if (!source.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Object)
                return result;
            var region = Text(fields, "region");
            result = result with
            {
                Country = Text(fields, "country"), Province = Text(fields, "province") ?? region,
                City = Text(fields, "city"), District = Text(fields, "district"), Region = region,
                Isp = Text(fields, "isp"), Asn = Text(fields, "asn"), AsName = Text(fields, "asName")
            };
            return result with { Status = new[] { result.Country, result.Province, result.City, result.District, result.Region, result.Isp, result.Asn, result.AsName }
                .Any(value => value is not null) ? "resolved" : "notFound" };
        }
        return new(ip, "notFound", Database: database);
    }

    private static string? Text(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String)
            return null;
        var text = value.GetString()?.Trim();
        return string.IsNullOrEmpty(text) ? null : text[..Math.Min(text.Length, 1024)];
    }

    private static string? SafeUrl(string? value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme is "https" or "http" && string.IsNullOrEmpty(uri.UserInfo) ? uri.AbsoluteUri : null;
}
