using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using PrivacyLink.Services;

namespace PrivacyLink.Api;

internal sealed class AdminPasswordVerifier
{
    private readonly string? _passwordHash;
    private readonly PasswordHasher<string> _hasher = new();

    public AdminPasswordVerifier(IConfiguration configuration)
    {
        var password = configuration["Security:AdminPassword"];
        if (!string.IsNullOrEmpty(password))
            _passwordHash = _hasher.HashPassword("admin", password);
    }

    public bool IsEnabled => _passwordHash is not null;

    public bool Verify(string? suppliedPassword) => _passwordHash is not null && suppliedPassword is { Length: <= 1024 } &&
        _hasher.VerifyHashedPassword("admin", _passwordHash, suppliedPassword ?? string.Empty) != PasswordVerificationResult.Failed;
}

internal sealed record AdminLoginRequest(string Password);
internal sealed record AdminSessionResponse(bool Authenticated);
internal sealed record AdminAuditRecordResponse(long Id, string TraceId, string SecretId, string SecretIdSource, string? RequestedSecretId,
    string Action, string HttpMethod, string RouteTemplate, DateTimeOffset StartedAt, DateTimeOffset? CompletedAt, long? DurationMs,
    string State, string? Outcome, int? HttpStatus, string? ErrorCode, string? ClientIp, string? FileId);
internal sealed record AdminAuditPageResponse(IReadOnlyList<AdminAuditRecordResponse> Items, int Page, int PageSize, long TotalCount);

internal static class AdminEndpoints
{
    public static async Task<IResult> Login(HttpContext context, AdminPasswordVerifier verifier)
    {
        if (context.Request.ContentLength is > 4096) return Results.BadRequest();
        AdminLoginRequest? request;
        try
        {
            request = await context.Request.ReadFromJsonAsync(PrivacyLinkJsonContext.Default.AdminLoginRequest, context.RequestAborted);
        }
        catch (System.Text.Json.JsonException)
        {
            return Results.BadRequest();
        }

        if (!verifier.Verify(request?.Password)) return Results.Unauthorized();

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin")], CookieAuthenticationDefaults.AuthenticationScheme);
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), new AuthenticationProperties
        {
            IsPersistent = false,
            AllowRefresh = false
        });
        return Results.NoContent();
    }

    public static IResult Session() => Results.Json(new AdminSessionResponse(true), PrivacyLinkJsonContext.Default.AdminSessionResponse);

    public static async Task<IResult> Logout(HttpContext context)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.NoContent();
    }

    public static async Task<IResult> Audit(int? page, int? pageSize, string? sortBy, string? sortDirection, string? secretId, string? clientIp,
        ISecretRequestAuditReader reader, CancellationToken cancellationToken)
    {
        var requestedPage = page ?? 1;
        var requestedPageSize = pageSize ?? 50;
        var requestedSort = sortBy ?? "time";
        var descending = sortDirection?.Equals("asc", StringComparison.OrdinalIgnoreCase) != true;
        if (requestedPage is < 1 or > 10_000_000 || requestedPageSize is < 1 or > 100 || requestedSort is not ("time" or "action" or "secretId" or "clientIp" or "outcome" or "httpStatus" or "request") ||
            (sortDirection is not null && !sortDirection.Equals("asc", StringComparison.OrdinalIgnoreCase) && !sortDirection.Equals("desc", StringComparison.OrdinalIgnoreCase)))
            return Results.BadRequest();
        string? normalizedClientIp = null;
        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            if (!System.Net.IPAddress.TryParse(clientIp.Trim(), out var parsedIp)) return Results.BadRequest();
            normalizedClientIp = (parsedIp.IsIPv4MappedToIPv6 ? parsedIp.MapToIPv4() : parsedIp).ToString();
        }
        var records = await reader.ListAsync(new SecretRequestAuditQuery(requestedPage, requestedPageSize, requestedSort, descending,
            string.IsNullOrWhiteSpace(secretId) ? null : secretId.Trim(), normalizedClientIp), cancellationToken);
        var items = records.Items.Select(record => new AdminAuditRecordResponse(record.Id, record.TraceId, record.SecretId, record.SecretIdSource,
            record.RequestedSecretId, record.Action, record.HttpMethod, record.RouteTemplate, record.StartedAt, record.CompletedAt,
            record.DurationMs, record.State, record.Outcome, record.HttpStatus, record.ErrorCode, record.ClientIp?.ToString(), record.FileId)).ToArray();
        return Results.Json(new AdminAuditPageResponse(items, requestedPage, requestedPageSize, records.TotalCount), PrivacyLinkJsonContext.Default.AdminAuditPageResponse);
    }
}
