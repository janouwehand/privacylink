using System.Net;
using System.Security.Cryptography;

namespace PrivacyLink.Api;

internal static class SecurityKeyUtilities
{
    internal static byte[] RequireExactKey(string? text, string name, int length)
    {
        if (string.IsNullOrWhiteSpace(text)) throw new InvalidOperationException($"{name} must be configured as a Base64 secret.");
        try
        {
            var bytes = Convert.FromBase64String(text);
            if (bytes.Length == length) return bytes;
        }
        catch (FormatException) { }
        throw new InvalidOperationException($"{name} must be a Base64 secret of exactly {length} bytes.");
    }

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
