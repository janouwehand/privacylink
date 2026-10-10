using Microsoft.Extensions.Configuration;
using Npgsql;

namespace PrivacyLink.Api;

internal static class SecretStoreConfiguration
{
    private const string SupportedProvider = "Environment";

    public static void ApplyFileSecrets(IConfigurationManager configuration)
    {
        var settings = new Dictionary<string, string?>();
        var pepperPath = configuration["Security:PasswordPepper_FILE"];
        if (!string.IsNullOrWhiteSpace(pepperPath))
            settings["Security:PasswordPepper"] = ReadSecretFile(pepperPath);

        var auditHashKeyPath = configuration["Security:AuditHashKey_FILE"];
        if (!string.IsNullOrWhiteSpace(auditHashKeyPath))
            settings["Security:AuditHashKey"] = ReadSecretFile(auditHashKeyPath);

        var databasePasswordPath = configuration["ConnectionStrings:PrivacyLinkPassword_FILE"];
        if (!string.IsNullOrWhiteSpace(databasePasswordPath))
        {
            var connectionString = configuration.GetConnectionString("PrivacyLink")
                ?? throw new InvalidOperationException("ConnectionStrings:PrivacyLink is required when a database password file is configured.");
            var connectionStringBuilder = new NpgsqlConnectionStringBuilder(connectionString)
            {
                Password = ReadSecretFile(databasePasswordPath)
            };
            settings["ConnectionStrings:PrivacyLink"] = connectionStringBuilder.ConnectionString;
        }

        if (settings.Count > 0)
            configuration.AddInMemoryCollection(settings);
    }

    private static string ReadSecretFile(string path) => File.ReadAllText(path).TrimEnd('\r', '\n');

    public static string? ReadPasswordPepper(IConfiguration configuration, bool isProduction)
    {
        var provider = configuration["Security:SecretStore:Provider"];
        if (isProduction && string.IsNullOrWhiteSpace(provider))
            throw new InvalidOperationException("Security:SecretStore:Provider must be set to Environment in production.");
        if (!string.IsNullOrWhiteSpace(provider) && !string.Equals(provider, SupportedProvider, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Security:SecretStore:Provider must be Environment.");

        var pepper = configuration["Security:PasswordPepper"];
        if (isProduction && string.IsNullOrWhiteSpace(pepper))
            throw new InvalidOperationException("Security:PasswordPepper must be supplied through Environment configuration in production.");
        return string.IsNullOrWhiteSpace(pepper) ? null : pepper;
    }
}
