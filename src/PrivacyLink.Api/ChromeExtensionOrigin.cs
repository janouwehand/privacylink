namespace PrivacyLink.Api;

internal static class ChromeExtensionOrigin
{
    private const string OriginPrefix = "chrome-extension://";

    public static string? Read(IConfiguration configuration)
    {
        var origin = configuration["Security:ChromeExtensionOrigin"];
        if (string.IsNullOrEmpty(origin)) return null;
        if (!IsValidConfiguredOrigin(origin))
            throw new InvalidOperationException("Security:ChromeExtensionOrigin must be an exact chrome-extension:// origin with a 32-character lowercase a-p extension ID.");
        return origin;
    }

    public static bool IsExtensionOrigin(string origin) =>
        origin.StartsWith(OriginPrefix, StringComparison.OrdinalIgnoreCase);

    private static bool IsValidConfiguredOrigin(string origin)
    {
        if (!origin.StartsWith(OriginPrefix, StringComparison.Ordinal) || origin.Length != OriginPrefix.Length + 32)
            return false;
        for (var index = OriginPrefix.Length; index < origin.Length; index++)
            if (origin[index] is < 'a' or > 'p') return false;
        return true;
    }
}
