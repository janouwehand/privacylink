using System.Text;
using System.Security.Cryptography;

namespace PrivacyLink.Api;

internal static class PrivacyAudit
{
    public static bool IsAudited(HttpRequest request) =>
        request.Path.StartsWithSegments("/api/v1/secrets") &&
        (HttpMethods.IsPost(request.Method) || HttpMethods.IsGet(request.Method));

    public static string Operation(HttpRequest request)
    {
        if (HttpMethods.IsGet(request.Method)) return "metadata";
        var path = request.Path.Value ?? string.Empty;
        if (path.EndsWith("/revoke", StringComparison.Ordinal)) return "revoke";
        if (path.EndsWith("/unlock", StringComparison.Ordinal)) return "unlock";
        if (path.EndsWith("/open", StringComparison.Ordinal)) return "open";
        return "create";
    }

    public static string ClientAddress(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    public static void Log(HttpContext context, string operation, TimeSpan? duration = null)
    {
        var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("PrivacyAudit");
        var keyText = context.RequestServices.GetService<IConfiguration>()?["Security:AuditHashKey"];
        var configuration = context.RequestServices.GetService<IConfiguration>();
        var clientHash = "unavailable";
        if (!string.IsNullOrWhiteSpace(keyText) && SecurityKeyUtilities.TryKey(keyText, out var key) &&
            !SecurityKeyUtilities.KeyEquals(keyText, configuration?["Security:PasswordPepper"]) &&
            SecurityKeyUtilities.Normalize(context.Connection.RemoteIpAddress) is { } address)
            clientHash = Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(address)))[..16];
        logger.LogInformation("Privacy audit {Operation} status={StatusCode} client={ClientHash} trace={TraceId} durationMs={DurationMs}",
            operation, context.Response.StatusCode, clientHash, context.TraceIdentifier, duration?.TotalMilliseconds);
    }
}
