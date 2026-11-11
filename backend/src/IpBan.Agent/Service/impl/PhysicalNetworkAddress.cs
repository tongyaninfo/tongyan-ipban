using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace IpBan.Agent.Service.impl;

/// <summary>登录事件缺少本机地址时，从运行正常的物理网卡选择一个单播地址。</summary>
internal static class PhysicalNetworkAddress
{
    public static string? Find()
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux()) return null;

        NetworkInterface[] adapters;
        try
        {
            adapters = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (NetworkInformationException)
        {
            return null;
        }

        IPAddress? fallbackV6 = null;
        foreach (var adapter in adapters)
        {
            try
            {
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;

                var properties = adapter.GetIPProperties();
                if (OperatingSystem.IsWindows()
                    ? !IsWindowsPhysicalInterface(adapter, properties)
                    : !IsLinuxPhysicalInterface(adapter.Name))
                    continue;

                foreach (var unicast in properties.UnicastAddresses)
                {
                    if (OperatingSystem.IsWindows() &&
                        unicast.DuplicateAddressDetectionState != DuplicateAddressDetectionState.Preferred)
                        continue;
                    var address = unicast.Address;
                    if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                    if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.IPv6Any)
                        || address.IsIPv6LinkLocal || address.IsIPv6Multicast)
                        continue;
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var bytes = address.GetAddressBytes();
                        if (bytes[0] is not (0 or >= 224) && !(bytes[0] == 169 && bytes[1] == 254))
                            return address.ToString();
                    }
                    else if (address.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        fallbackV6 ??= address;
                    }
                }
            }
            catch (Exception error) when (error is NetworkInformationException or IOException or UnauthorizedAccessException)
            {
                // 网卡热插拔或系统属性不可用时，继续检查其余网卡。
            }
        }

        return fallbackV6?.ToString();
    }

    private static bool IsLinuxPhysicalInterface(string name)
    {
        var path = Path.Combine("/sys/class/net", name);
        // 物理设备拥有设备目录链接，网桥、隧道及普通 veth 没有该链接。
        if (!Directory.Exists(Path.Combine(path, "device"))) return false;
        try
        {
            return File.ReadAllText(Path.Combine(path, "carrier")).AsSpan().Trim().SequenceEqual("1");
        }
        catch (FileNotFoundException)
        {
            // 未暴露载波属性的驱动仍需满足调用方的 OperationalStatus.Up 检查。
            return Directory.Exists(Path.Combine(path, "device"));
        }
    }

    private static bool IsWindowsPhysicalInterface(NetworkInterface adapter, IPInterfaceProperties properties)
    {
        var index = adapter.Supports(NetworkInterfaceComponent.IPv4) ? properties.GetIPv4Properties()?.Index : null;
        index ??= adapter.Supports(NetworkInterfaceComponent.IPv6) ? properties.GetIPv6Properties()?.Index : null;
        if (index is not > 0) return false;

        var row = new MibIfRow2 { InterfaceIndex = (uint)index.Value };
        const byte hardwareInterface = 0x01;
        const byte unavailable = 0x02 | 0x08 | 0x10 | 0x20 | 0x40;
        return GetIfEntry2(ref row) == 0
            && (row.InterfaceFlags & hardwareInterface) != 0
            && (row.InterfaceFlags & unavailable) == 0
            && row.OperStatus == 1 && row.AdminStatus == 1 && row.MediaConnectState == 1;
    }

    // Windows IP Helper 的 MIB_IF_ROW2 ABI。定长内联缓冲不使用反射编组，兼容 Native AOT。
    [StructLayout(LayoutKind.Sequential)]
    private struct MibIfRow2
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public Guid InterfaceGuid;
        public InterfaceText Alias;
        public InterfaceText Description;
        public uint PhysicalAddressLength;
        public PhysicalAddress PhysicalAddress;
        public PhysicalAddress PermanentPhysicalAddress;
        public uint Mtu;
        public uint Type;
        public uint TunnelType;
        public uint MediaType;
        public uint PhysicalMediumType;
        public uint AccessType;
        public uint DirectionType;
        public byte InterfaceFlags;
        public uint OperStatus;
        public uint AdminStatus;
        public uint MediaConnectState;
        public Guid NetworkGuid;
        public uint ConnectionType;
        public LinkStatistics LinkStatistics;
    }

    [InlineArray(257)]
    private struct InterfaceText { private ushort element; }

    [InlineArray(32)]
    private struct PhysicalAddress { private byte element; }

    [InlineArray(20)]
    private struct LinkStatistics { private ulong element; }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetIfEntry2(ref MibIfRow2 row);
}
