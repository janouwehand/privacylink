using System.Text;
using System.Security.Cryptography;
using System.Net;
using Microsoft.AspNetCore.Http;
using PrivacyLink.Services;

namespace PrivacyLink.Api;

internal static class PrivacyAudit
{
    internal const string RequestIdItem = "PrivacyLink.SecretRequestId";
    internal const string CreateSecretIdItem = "PrivacyLink.CreateSecretId";
    internal const string ErrorCodeItem = "PrivacyLink.SecretRequestErrorCode";

    public static bool IsAudited(HttpRequest request) =>
        !(HttpMethods.IsGet(request.Method) && request.Path.Equals("/api/v1/secrets/create-challenge", StringComparison.OrdinalIgnoreCase)) &&
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

    public static string ClientAddress(HttpContext context) => SecurityKeyUtilities.Normalize(context.Connection.RemoteIpAddress) ?? "unknown";

    public static string NewSecretId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool IsCanonicalSecretId(string value)
    {
        if (value.Length != 22 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_')) return false;
        try
        {
            var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + "==");
            return bytes.Length == 16 && NewEncoding(bytes) == value;
        }
        catch (FormatException) { return false; }
    }

    public static (int StatusCode, string ErrorCode) Failure(Exception exception) => exception switch
    {
        SecretAuditUnavailableException => (StatusCodes.Status503ServiceUnavailable, "audit_unavailable"),
        BadHttpRequestException badRequest => (badRequest.StatusCode, badRequest.StatusCode switch
        {
            StatusCodes.Status400BadRequest => "invalid_request",
            StatusCodes.Status413PayloadTooLarge => "payload_too_large",
            StatusCodes.Status414RequestUriTooLong => "request_uri_too_long",
            StatusCodes.Status415UnsupportedMediaType => "unsupported_media_type",
            StatusCodes.Status431RequestHeaderFieldsTooLarge => "request_headers_too_large",
            _ => "server_error"
        }),
        _ => (StatusCodes.Status500InternalServerError, "server_error")
    };

    public static string? AuditErrorCode(int statusCode, string? mappedCode) =>
        statusCode < 400 ? null : mappedCode ?? $"http_{statusCode}";

    private static string NewEncoding(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static IPAddress? NormalizedClientIp(HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        return address?.IsIPv4MappedToIPv6 == true ? address.MapToIPv4() : address;
    }

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
