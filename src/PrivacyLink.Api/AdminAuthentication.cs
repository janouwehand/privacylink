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
internal sealed record AdminAuditPageResponse(IReadOnlyList<AdminAuditRecordResponse> Items, long? NextBeforeId);

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

    public static async Task<IResult> Audit(long? beforeId, ISecretRequestAuditReader reader, CancellationToken cancellationToken)
    {
        const int pageSize = 50;
        var records = await reader.ListAsync(beforeId, pageSize + 1, cancellationToken);
        var hasMore = records.Count > pageSize;
        var visible = records.Take(pageSize).ToArray();
        var items = visible.Select(record => new AdminAuditRecordResponse(record.Id, record.TraceId, record.SecretId, record.SecretIdSource,
            record.RequestedSecretId, record.Action, record.HttpMethod, record.RouteTemplate, record.StartedAt, record.CompletedAt,
            record.DurationMs, record.State, record.Outcome, record.HttpStatus, record.ErrorCode, record.ClientIp?.ToString(), record.FileId)).ToArray();
        long? nextBeforeId = hasMore && visible.Length > 0 ? visible[^1].Id : null;
        return Results.Json(new AdminAuditPageResponse(items, nextBeforeId), PrivacyLinkJsonContext.Default.AdminAuditPageResponse);
    }
}
