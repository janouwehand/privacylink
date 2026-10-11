using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using PrivacyLink.Contracts;
using PrivacyLink.Services;

namespace PrivacyLink.Api;

internal sealed class SecretRequestAuditMiddleware(IConfiguration configuration, ISecretRequestAuditWriter writer) : IMiddleware
{
    private readonly int _maxRequestBytes = int.TryParse(configuration["Limits:MaxRequestBytes"], out var configuredRequestBytes) && configuredRequestBytes > 0
        ? configuredRequestBytes
        : 110 * 1024 * 1024;

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        if (HttpMethods.IsGet(context.Request.Method) && path.Equals("/api/v1/secrets/create-challenge", StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secretApi = path.Equals("/api/v1/secrets", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/api/v1/secrets/", StringComparison.OrdinalIgnoreCase);
        var secretPage = segments.Length == 2 && segments[0].Equals("s", StringComparison.OrdinalIgnoreCase);
        if (!secretApi && !secretPage)
        {
            await next(context);
            return;
        }

        var create = secretApi && segments.Length == 3 && IsSegment(segments[0], "api") && IsSegment(segments[1], "v1") && IsSegment(segments[2], "secrets") && HttpMethods.IsPost(context.Request.Method);
        var idIndex = secretPage ? 1 : segments.Length > 3 ? 3 : -1;
        var requestedId = idIndex >= 0 && idIndex < segments.Length ? segments[idIndex] : null;
        var usableId = requestedId is not null && PrivacyAudit.IsCanonicalSecretId(requestedId);
        var secretId = create ? PrivacyAudit.NewSecretId() : usableId ? requestedId! : PrivacyAudit.NewSecretId();
        var source = create || !usableId ? "reserved" : "route";
        var (action, template) = ClassifySecretRequest(context.Request.Method, segments, secretApi, secretPage);
        string? fileId = action == "file_open" && segments.Length > 5 && PrivacyAudit.IsCanonicalSecretId(segments[5]) ? segments[5] : null;
        var requestId = Guid.NewGuid();
        context.Items[PrivacyAudit.RequestIdItem] = requestId;
        if (create) context.Items[PrivacyAudit.CreateSecretIdItem] = secretId;
        var audit = new SecretRequestAuditStart(requestId, context.TraceIdentifier, secretId, source,
            usableId ? null : requestedId is { Length: > 256 } ? requestedId[..256] : requestedId,
            action, context.Request.Method, template, DateTimeOffset.UtcNow, PrivacyAudit.NormalizedClientIp(context), fileId);
        try
        {
            await writer.StartAsync(audit, CancellationToken.None);
        }
        catch
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(new ErrorResponse("audit_unavailable"), PrivacyLinkJsonContext.Default.ErrorResponse, cancellationToken: CancellationToken.None);
            return;
        }

        var originalBody = context.Response.Body;
        var responseBuffer = CreateResponseBuffer();
        context.Response.Body = responseBuffer;
        var startTimestamp = Stopwatch.GetTimestamp();
        try
        {
            try
            {
                await next(context);
            }
            catch (Exception exception)
            {
                var failure = PrivacyAudit.Failure(exception);
                context.Response.Clear();
                var failedResponseBuffer = responseBuffer;
                responseBuffer = CreateResponseBuffer();
                context.Response.Body = responseBuffer;
                await failedResponseBuffer.DisposeAsync();
                context.Response.StatusCode = failure.StatusCode;
                await context.Response.WriteAsJsonAsync(new ErrorResponse(failure.ErrorCode), PrivacyLinkJsonContext.Default.ErrorResponse, cancellationToken: CancellationToken.None);
            }
            var status = context.Response.StatusCode;
            var finish = new SecretRequestAuditFinish(DateTimeOffset.UtcNow, (long)Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds,
                context.RequestAborted.IsCancellationRequested ? "aborted" : "completed",
                context.RequestAborted.IsCancellationRequested ? "aborted" : status >= 500 ? "error" : status >= 400 ? "rejected" : "success",
                status, PrivacyAudit.AuditErrorCode(status,
                    context.Items.TryGetValue(PrivacyAudit.ErrorCodeItem, out var errorCode) ? errorCode as string : null));
            try
            {
                await writer.FinishAsync(requestId, finish, CancellationToken.None);
            }
            catch
            {
                context.Response.Body = originalBody;
                context.Response.Clear();
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsJsonAsync(new ErrorResponse("audit_unavailable"), PrivacyLinkJsonContext.Default.ErrorResponse, cancellationToken: CancellationToken.None);
                return;
            }

            context.Response.Body = originalBody;
            await responseBuffer.DrainBufferAsync(originalBody, CancellationToken.None);
        }
        finally
        {
            context.Response.Body = originalBody;
            await responseBuffer.DisposeAsync();
        }
    }

    private FileBufferingWriteStream CreateResponseBuffer() => new(1024 * 1024, _maxRequestBytes, () => Path.GetTempPath());

    private static (string Action, string Template) ClassifySecretRequest(string method, string[] segments, bool secretApi, bool secretPage)
    {
        if (secretPage) return ("secret_page", "/s/{id}");
        if (segments.Length == 3 && IsSegment(segments[2], "secrets") && HttpMethods.IsPost(method)) return ("create", "/api/v1/secrets");
        if (segments.Length == 4 && IsSegment(segments[2], "secrets"))
        {
            if (HttpMethods.IsGet(method)) return ("metadata", "/api/v1/secrets/{id}");
            return ("secret_request", "/api/v1/secrets/{id}");
        }
        if (segments.Length == 5 && IsSegment(segments[2], "secrets"))
        {
            if (HttpMethods.IsPost(method) && (IsSegment(segments[4], "open") || IsSegment(segments[4], "unlock") || IsSegment(segments[4], "revoke")))
            {
                var action = segments[4].ToLowerInvariant();
                return (action, $"/api/v1/secrets/{{id}}/{action}");
            }
            return ("secret_request", "/api/v1/secrets/{id}/*");
        }
        if (segments.Length == 7 && IsSegment(segments[2], "secrets") && IsSegment(segments[4], "files") && IsSegment(segments[6], "open") && HttpMethods.IsPost(method))
            return ("file_open", "/api/v1/secrets/{id}/files/{fileId}/open");
        return ("secret_request", secretApi ? "/api/v1/secrets/*" : "/s/*");
    }

    private static bool IsSegment(string actual, string expected) => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
}
