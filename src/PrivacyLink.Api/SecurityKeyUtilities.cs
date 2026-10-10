using System.Net;
using System.Security.Cryptography;

namespace PrivacyLink.Api;

internal static class SecurityKeyUtilities
{
    internal static string? Normalize(IPAddress? address)
    {
        if (address is null) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.ToString().ToLowerInvariant();
    }

    internal static bool TryKey(string text, out byte[] key)
    {
        try { key = Convert.FromBase64String(text); return key.Length >= 32; }
        catch (FormatException) { key = []; return false; }
    }

    internal static bool KeyEquals(string first, string? second) =>
        !string.IsNullOrWhiteSpace(second) && TryKey(first, out var firstKey) && TryKey(second, out var secondKey) &&
        firstKey.Length == secondKey.Length && CryptographicOperations.FixedTimeEquals(firstKey, secondKey);
}
