using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using IpBan.Shared.Models;

namespace IpBan.Api.Service.impl;

internal static class OverviewHostReader
{
    public static OverviewHostContract Read() => new(
        RuntimeInformation.OSDescription,
        Environment.MachineName,
        ReadIpAddresses(),
        ReadStartedAtUtc());

    private static string[] ReadIpAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up
                    && adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
                .Select(entry => entry.Address)
                .Where(address => !IPAddress.IsLoopback(address)
                    && !address.Equals(IPAddress.Any)
                    && !address.Equals(IPAddress.IPv6Any))
                .OrderBy(address => address.AddressFamily != AddressFamily.InterNetwork)
                .ThenBy(address => address.IsIPv6LinkLocal)
                .Select(address => address.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
        }
        catch (NetworkInformationException)
        {
            // 网卡信息不可用时，其他总览指标仍可显示。
            return [];
        }
    }

    private static DateTimeOffset? ReadStartedAtUtc()
    {
        if (OperatingSystem.IsWindows())
        {
            // .NET 10 的 Windows 计时包含睡眠和休眠时间，可以用来估算系统启动时刻。
            var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
            return DateTimeOffset.UtcNow.Subtract(uptime);
        }

        if (OperatingSystem.IsLinux())
        {
            try
            {
                // 内核提供的 btime 是 Unix 秒数，API 或 Agent 重启不影响该值。
                const string bootTimePrefix = "btime ";
                foreach (var line in File.ReadLines("/proc/stat"))
                {
                    if (line.StartsWith(bootTimePrefix, StringComparison.Ordinal)
                        && long.TryParse(line.AsSpan(bootTimePrefix.Length), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
                        && seconds > 0 && seconds <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
                    {
                        return DateTimeOffset.FromUnixTimeSeconds(seconds);
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // 无法读取内核启动时间时保留空值。
            }
        }

        return null;
    }
}
