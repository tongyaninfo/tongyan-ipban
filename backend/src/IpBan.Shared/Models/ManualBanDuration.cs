namespace IpBan.Shared.Models;

public static class ManualBanDuration
{
    public const int Permanent = -1;
    public const int DefaultSeconds = 180;
    public const int MaximumSeconds = 604800;

    public static bool IsValid(int seconds) => seconds == Permanent || seconds is >= 1 and <= MaximumSeconds;
}
