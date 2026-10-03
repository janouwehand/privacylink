namespace PrivacyLink.Api;

internal static class ProductionConfiguration
{
    public static void Validate(IConfiguration configuration, bool isProduction)
    {
        var requirePepper = !bool.TryParse(configuration["Security:RequirePasswordPepper"], out var configuredRequirePepper) || configuredRequirePepper;
        if (!isProduction) return;

        if (requirePepper) SecretStoreConfiguration.ReadPasswordPepper(configuration, isProduction: true);
        else if (!string.IsNullOrWhiteSpace(configuration["Security:SecretStore:Provider"]))
            SecretStoreConfiguration.ReadPasswordPepper(configuration, isProduction: true);
        if (string.IsNullOrWhiteSpace(configuration.GetConnectionString("PrivacyLink")))
            throw new InvalidOperationException("ConnectionStrings:PrivacyLink must be supplied in production.");
        var auditKey = configuration["Security:AuditHashKey"];
        if (string.IsNullOrWhiteSpace(auditKey) || !StatisticsRecorder.TryKey(auditKey, out _))
            throw new InvalidOperationException("Security:AuditHashKey must be a base64-encoded random key of at least 32 bytes in production.");
        var analyticsKey = configuration["Analytics:Key"];
        if (string.IsNullOrWhiteSpace(analyticsKey) || !StatisticsRecorder.TryKey(analyticsKey, out _))
            throw new InvalidOperationException("Analytics:Key must be a base64-encoded random key of at least 32 bytes in production.");
        if (StatisticsRecorder.KeyEquals(auditKey, analyticsKey))
            throw new InvalidOperationException("Security:AuditHashKey and Analytics:Key must be different keys.");
        var passwordPepper = configuration["Security:PasswordPepper"];
        if (!string.IsNullOrWhiteSpace(passwordPepper) && StatisticsRecorder.KeyEquals(analyticsKey, passwordPepper))
            throw new InvalidOperationException("Analytics:Key must be independent from Security:PasswordPepper.");
        if (!string.IsNullOrWhiteSpace(passwordPepper) && StatisticsRecorder.KeyEquals(auditKey, passwordPepper))
            throw new InvalidOperationException("Security:AuditHashKey must be independent from Security:PasswordPepper.");
        if (!bool.TryParse(configuration["Security:RequireHttps"], out _))
            throw new InvalidOperationException("Security:RequireHttps must be true or false in production.");

        var blobPath = configuration["Storage:BlobPath"];
        if (string.IsNullOrWhiteSpace(blobPath) || !Path.IsPathFullyQualified(blobPath))
            throw new InvalidOperationException("Storage:BlobPath must be an absolute production path.");
        if (string.IsNullOrWhiteSpace(configuration["AllowedHosts"]) || configuration["AllowedHosts"]!.Contains('*', StringComparison.Ordinal))
            throw new InvalidOperationException("AllowedHosts must list explicit production hostnames.");
        foreach (var proxy in configuration.GetSection("Security:TrustedProxies").GetChildren())
        {
            if (string.IsNullOrWhiteSpace(proxy.Value)) continue;
            if (!System.Net.IPAddress.TryParse(proxy.Value, out _))
                throw new InvalidOperationException("Security:TrustedProxies contains an invalid IP address.");
        }
    }
}
