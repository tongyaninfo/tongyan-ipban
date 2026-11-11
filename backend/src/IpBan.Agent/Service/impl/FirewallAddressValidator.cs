using System.Net;

namespace IpBan.Agent.Service.impl;

internal static class FirewallAddressValidator
{
    public static bool TryNormalize(string? sourceAddress, out string normalized)
    {
        normalized = string.Empty;
        var value = sourceAddress?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var separator = value.IndexOf('/');
        if (separator < 0)
        {
            if (!IPAddress.TryParse(value, out var address))
            {
                return false;
            }

            normalized = address.ToString();
            return true;
        }

        if (separator == 0 || separator == value.Length - 1 || value.IndexOf('/', separator + 1) >= 0)
        {
            return false;
        }

        var addressText = value[..separator];
        var prefixText = value[(separator + 1)..];
        if (!IPAddress.TryParse(addressText, out var networkAddress)
            || !int.TryParse(prefixText, System.Globalization.CultureInfo.InvariantCulture, out var prefixLength))
        {
            return false;
        }

        var maxPrefixLength = networkAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? 32
            : 128;
        if (prefixLength < 0 || prefixLength > maxPrefixLength)
        {
            return false;
        }

        normalized = $"{networkAddress}/{prefixLength}";
        return true;
    }

    public static bool IsIpv6(string normalized) => normalized.Contains(':', StringComparison.Ordinal);
}
