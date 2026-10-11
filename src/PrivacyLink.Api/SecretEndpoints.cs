using System.Security.Cryptography;
using System.Text.Json;
using PrivacyLink.Contracts;
using PrivacyLink.Services;

namespace PrivacyLink.Api;

internal static class SecretEndpoints
{
    private static readonly HashSet<string> Expiries = ["1d", "7d", "14d"];
    private static readonly string[] DefaultExtensions = [".pdf", ".txt", ".md", ".rtf", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".7z", ".zip", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".cer", ".crt", ".der", ".pem", ".p7b", ".p7c", ".p12", ".pfx", ".key"];

    public static IResult Capabilities(IConfiguration configuration)
    {
        var maxFiles = Limit(configuration, "Limits:MaxFiles", 15);
        var maxFileBytes = LimitLong(configuration, "Limits:MaxTotalPlaintextFileBytes", 75 * 1024 * 1024);
        return Results.Json(new FileUploadPolicyResponse(maxFiles, maxFileBytes, AllowedExtensions(configuration).OrderBy(extension => extension, StringComparer.Ordinal).ToArray()), PrivacyLinkJsonContext.Default.FileUploadPolicyResponse);
    }

    public static async Task<IResult> Create(HttpRequest request, HttpContext context, SecretApplicationService service, IConfiguration configuration)
    {
        var cancellationToken = request.HttpContext.RequestAborted;
        var maxMessage = Limit(configuration, "Limits:MaxMessagePlaintextBytes", 80000);
        var maxFiles = Limit(configuration, "Limits:MaxFiles", 15);
        var maxFileBytes = LimitLong(configuration, "Limits:MaxTotalPlaintextFileBytes", 75 * 1024 * 1024);
        var maxRequestBytes = Limit(configuration, "Limits:MaxRequestBytes", 110 * 1024 * 1024);
        var allowedExtensions = AllowedExtensions(configuration);
        if (!request.HasJsonContentType()) return Error(415, "unsupported_media_type");
        if (request.ContentLength > maxRequestBytes) return Error(413, "payload_too_large");
        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body, new JsonDocumentOptions { MaxDepth = 6 }, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !KnownOnly(root, "protocolVersion", "expiry", "message", "files", "password") ||
                !root.TryGetProperty("protocolVersion", out var version) || version.GetInt32() != 1 ||
                !root.TryGetProperty("expiry", out var expiry) || expiry.ValueKind != JsonValueKind.String || !Expiries.Contains(expiry.GetString()!) ||
                !root.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array || files.GetArrayLength() > maxFiles)
                return Error(400, "invalid_request");

            string? password = null;
            if (root.TryGetProperty("password", out var passwordValue) && passwordValue.ValueKind != JsonValueKind.Null)
            {
                var minPassword = Limit(configuration, "Security:MinPasswordLength", 4);
                var maxPassword = Limit(configuration, "Security:MaxPasswordLength", 256);
                if (passwordValue.ValueKind != JsonValueKind.String || passwordValue.GetString() is not { } supplied || string.IsNullOrWhiteSpace(supplied) || supplied.Length < minPassword || supplied.Length > maxPassword || System.Text.Encoding.UTF8.GetByteCount(supplied) > maxPassword * 4)
                    return Error(400, "invalid_request");
                password = supplied;
            }

            SecretCreateMessage? message = null;
            if (root.TryGetProperty("message", out var messageValue) && messageValue.ValueKind != JsonValueKind.Null)
            {
                if (messageValue.ValueKind != JsonValueKind.Object || !Only(messageValue, "nonce", "ciphertext") || !ReadCipher(messageValue, out var parsedMessage)) return Error(400, "invalid_request");
                if (parsedMessage!.Ciphertext.Length - 16 > maxMessage) return Error(413, "payload_too_large");
                message = new SecretCreateMessage(parsedMessage.Nonce, parsedMessage.Ciphertext);
            }

            var parsedFiles = new List<SecretCreateFile>();
            var fileIds = new HashSet<string>(StringComparer.Ordinal);
            long totalPlaintext = 0;
            foreach (var file in files.EnumerateArray())
            {
                if (file.ValueKind != JsonValueKind.Object || !Only(file, "id", "extension", "nameNonce", "nameCiphertext", "mimeType", "size", "nonce", "ciphertext") ||
                    !file.TryGetProperty("id", out var idValue) || !file.TryGetProperty("extension", out var extensionValue) || !file.TryGetProperty("nameNonce", out var nameNonceValue) || !file.TryGetProperty("nameCiphertext", out var nameCiphertextValue) || !file.TryGetProperty("mimeType", out var mimeValue) ||
                    !file.TryGetProperty("size", out var sizeValue) || !file.TryGetProperty("nonce", out _) || !file.TryGetProperty("ciphertext", out _) ||
                    idValue.ValueKind != JsonValueKind.String || extensionValue.ValueKind != JsonValueKind.String || nameNonceValue.ValueKind != JsonValueKind.String || nameCiphertextValue.ValueKind != JsonValueKind.String || mimeValue.ValueKind != JsonValueKind.String || !ValidMimeType(mimeValue.GetString()!) ||
                    sizeValue.ValueKind != JsonValueKind.Number || !sizeValue.TryGetInt64(out var size) || !ValidId(idValue.GetString()!) ||
                    !ValidExtension(extensionValue.GetString()!) || !fileIds.Add(idValue.GetString()!) ||
                    !TryDecodeCanonical(nameNonceValue.GetString()!, 12, 12, out _) || !ValidEncryptedFileName(extensionValue.GetString()!, nameCiphertextValue.GetString()!) ||
                    !ReadCipher(file, out var cipher) || size < 1 || cipher!.Ciphertext.Length - 16 != size)
                    return Error(400, "invalid_request");
                if (!allowedExtensions.Contains(extensionValue.GetString()!)) return Error(400, "unsupported_file_type");
                if (size > maxFileBytes || totalPlaintext > maxFileBytes - size) return Error(413, "payload_too_large");
                totalPlaintext += size;
                parsedFiles.Add(new SecretCreateFile(idValue.GetString()!, extensionValue.GetString()!, nameNonceValue.GetString()!, nameCiphertextValue.GetString()!, mimeValue.GetString()!, size, cipher.Nonce, cipher.Ciphertext));
            }
            if (message is null && parsedFiles.Count == 0) return Error(400, "invalid_request");

            cancellationToken.ThrowIfCancellationRequested();
            var preGeneratedId = context.Items.TryGetValue(PrivacyAudit.CreateSecretIdItem, out var value) ? value as string : null;
            var auditRequestId = context.Items.TryGetValue(PrivacyAudit.RequestIdItem, out var requestId) && requestId is Guid id ? id : (Guid?)null;
            var created = await service.CreateAsync(new CreateSecretCommand(expiry.GetString()!, message, parsedFiles, password, preGeneratedId, auditRequestId), cancellationToken);
            if (created is null) return Error(429, "rate_limited");
            return Results.Json(new CreateSecretResponse(created.Id, created.ExpiresAt, created.PasswordProtected, created.RevokeToken), PrivacyLinkJsonContext.Default.CreateSecretResponse, statusCode: 201);
        }
        catch (JsonException) { return Error(400, "invalid_request"); }
        catch (InvalidOperationException) { return Error(400, "invalid_request"); }
        catch (FormatException) { return Error(400, "invalid_request"); }
        catch (PasswordEnvelopeCapacityException)
        {
            if (cancellationToken.IsCancellationRequested) return Results.Empty;
            return Error(503, "temporarily_unavailable");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return Results.Empty; }
        catch (SecretAuditUnavailableException) { throw; }
        catch { return Error(500, "server_error"); }
    }

    public static async Task<IResult> Metadata(string id, SecretApplicationService service, TimeProvider clock)
    {
        if (!ValidId(id) || await service.GetAsync(id, clock.GetUtcNow()) is not { } secret) return Error(404, "not_found");
        var metadata = secret.PasswordProtected
            ? Array.Empty<FileMetadataResponse>()
            : secret.Files.Select(Metadata).ToArray();
        return Results.Json(new SecretMetadataResponse(true, 1, secret.ExpiresAt, secret.PasswordProtected, secret.MessageNonce is not null, secret.Files.Count, metadata), PrivacyLinkJsonContext.Default.SecretMetadataResponse);
    }

    public static async Task<IResult> Revoke(string id, HttpRequest request, SecretApplicationService service, ILoggerFactory loggerFactory)
    {
        if (!request.HasJsonContentType() || request.ContentLength is > 4096 || request.ContentLength is 0)
            return Error(400, "invalid_request");
        if (!ValidId(id)) return Error(404, "not_found");
        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body, new JsonDocumentOptions { MaxDepth = 2 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Only(root, "revokeToken") ||
                !root.TryGetProperty("revokeToken", out var tokenValue) || tokenValue.ValueKind != JsonValueKind.String ||
                !TryDecodeCanonical(tokenValue.GetString()!, 32, 32, out var revokeToken))
                return Error(400, "invalid_request");

            var revokeTokenHash = Encode(SHA256.HashData(revokeToken));
            var auditRequestId = request.HttpContext.Items.TryGetValue(PrivacyAudit.RequestIdItem, out var requestId) && requestId is Guid idValue ? idValue : (Guid?)null;
            var logger = loggerFactory.CreateLogger("SecretRevocation");
            return await service.RevokeAsync(id, revokeTokenHash, auditRequestId, request.HttpContext.RequestAborted,
                exception => logger.LogError(exception, "Blob cleanup failed after secret revocation for {SecretId}", id))
                ? Results.NoContent()
                : Error(404, "not_found");
        }
        catch (JsonException) { return Error(400, "invalid_request"); }
    }

    public static async Task<IResult> Open(string id, HttpRequest request, SecretApplicationService service, TimeProvider clock)
    {
        if (request.ContentLength is > 0 || request.Headers.ContainsKey("Transfer-Encoding")) return Error(400, "invalid_request");
        if (!ValidId(id)) return Error(404, "not_found");
        try
        {
            var opened = await service.OpenAsync(id, clock.GetUtcNow());
            if (opened is null) return Error(404, "not_found");
            MessageCiphertext? message = opened.MessageNonce is not null && opened.MessageCiphertext is not null
                ? new MessageCiphertext(opened.MessageNonce, Encode(opened.MessageCiphertext))
                : null;
            return Results.Json(new OpenSecretResponse(1, message, []), PrivacyLinkJsonContext.Default.OpenSecretResponse);
        }
        catch (SecretProtectedException) { return Error(403, "forbidden"); }
        catch (FileNotFoundException) { return Error(404, "not_found"); }
    }

    public static async Task<IResult> Unlock(string id, HttpRequest request, SecretApplicationService service, TimeProvider clock, IConfiguration configuration)
    {
        var cancellationToken = request.HttpContext.RequestAborted;
        var maxAttempts = BoundedLimit(configuration, "Security:UnlockAttempts:MaxPerWindow", 5, 1, 100);
        var attemptWindow = TimeSpan.FromMinutes(BoundedLimit(configuration, "Security:UnlockAttempts:WindowMinutes", 15, 1, 1440));
        var cooldown = TimeSpan.FromMinutes(BoundedLimit(configuration, "Security:UnlockAttempts:CooldownMinutes", 15, 1, 1440));
        if (!request.HasJsonContentType() || request.ContentLength is > 16 * 1024 || request.ContentLength is 0) return Error(400, "invalid_request");
        if (!ValidId(id)) return Error(404, "not_found");
        StoredSecret? secret;
        try { secret = await service.GetUnlockTargetAsync(id, clock.GetUtcNow()); }
        catch (SecretProtectedException) { return Error(403, "forbidden"); }
        if (secret is null) return Error(404, "not_found");
        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body, new JsonDocumentOptions { MaxDepth = 3 }, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Only(root, "password") || !root.TryGetProperty("password", out var password) || password.ValueKind != JsonValueKind.String || password.GetString() is not { } value)
                return Error(400, "invalid_request");

            var auditRequestId = request.HttpContext.Items.TryGetValue(PrivacyAudit.RequestIdItem, out var requestId) && requestId is Guid idValue ? idValue : (Guid?)null;
            var result = await service.UnlockAsync(secret, value, maxAttempts, attemptWindow, cooldown, auditRequestId, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            MessageCiphertext? message = result.MessageNonce is not null && result.MessageCiphertext is not null
                ? new MessageCiphertext(result.MessageNonce, Encode(result.MessageCiphertext))
                : null;
            var files = result.Files.Select(file => OpenedFile(file.File, Encode(file.Ciphertext))).ToArray();
            return Results.Json(new OpenSecretResponse(1, message, files), PrivacyLinkJsonContext.Default.OpenSecretResponse);
        }
        catch (PasswordEnvelopeCapacityException)
        {
            if (cancellationToken.IsCancellationRequested) return Results.Empty;
            request.HttpContext.Response.Headers.RetryAfter = "2";
            return Error(503, "temporarily_unavailable");
        }
        catch (UnlockAttemptLimitException ex)
        {
            if (cancellationToken.IsCancellationRequested) return Results.Empty;
            request.HttpContext.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling((ex.RetryAt - clock.GetUtcNow()).TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Error(429, "rate_limited");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return Results.Empty; }
        catch (SecretProtectedException) { return Error(403, "forbidden"); }
        catch (CryptographicException) { return Error(403, "forbidden"); }
        catch (FileNotFoundException) { return Error(404, "not_found"); }
        catch (JsonException) { return Error(400, "invalid_request"); }
        catch (FormatException) { return Error(500, "server_error"); }
    }

    public static async Task<IResult> OpenFile(string id, string fileId, HttpRequest request, SecretApplicationService service, TimeProvider clock)
    {
        if (request.ContentLength is > 0 || request.Headers.ContainsKey("Transfer-Encoding")) return Error(400, "invalid_request");
        if (!ValidId(id) || !ValidId(fileId)) return Error(404, "not_found");
        try
        {
            var opened = await service.OpenFileAsync(id, fileId, clock.GetUtcNow());
            if (opened is null) return Error(404, "not_found");
            return Results.Json(new OpenFileResponse(1, OpenedFile(opened.File, Encode(opened.Ciphertext))), PrivacyLinkJsonContext.Default.OpenFileResponse);
        }
        catch (SecretProtectedException) { return Error(403, "forbidden"); }
        catch (FileNotFoundException) { return Error(404, "not_found"); }
    }

    private sealed record MessageInput(string Nonce, byte[] Ciphertext);
    private static FileMetadataResponse Metadata(StoredFile file) => new(file.Id, file.Extension, file.NameNonce, file.NameCiphertext, file.MimeType, file.Size);
    private static OpenedFileResponse OpenedFile(StoredFile file, string ciphertext) => new(file.Id, file.Extension, file.NameNonce, file.NameCiphertext, file.MimeType, file.Size, file.Nonce, ciphertext);
    private static bool ReadCipher(JsonElement value, out MessageInput? result)
    {
        result = null;
        if (!value.TryGetProperty("nonce", out var nonce) || !value.TryGetProperty("ciphertext", out var ciphertext) || nonce.ValueKind != JsonValueKind.String || ciphertext.ValueKind != JsonValueKind.String) return false;
        if (!TryDecodeCanonical(nonce.GetString()!, 12, 12, out _) || !TryDecodeCanonical(ciphertext.GetString()!, 17, 76 * 1024 * 1024, out var bytes)) return false;
        result = new MessageInput(nonce.GetString()!, bytes);
        return true;
    }
    private static int Limit(IConfiguration configuration, string key, int fallback) => int.TryParse(configuration[key], out var value) && value > 0 ? value : fallback;
    private static int BoundedLimit(IConfiguration configuration, string key, int fallback, int minimum, int maximum) => int.TryParse(configuration[key], out var value) && value >= minimum && value <= maximum ? value : fallback;
    private static long LimitLong(IConfiguration configuration, string key, long fallback) => long.TryParse(configuration[key], out var value) && value > 0 ? value : fallback;
    private static HashSet<string> AllowedExtensions(IConfiguration configuration)
    {
        var configured = configuration.GetSection("Limits:AllowedFileExtensions").GetChildren().Select(section => section.Value).OfType<string>()
            .Select(extension => extension.Trim().ToLowerInvariant()).Where(extension => extension.Length is > 1 and <= 16 && extension[0] == '.' && extension.Skip(1).All(char.IsAsciiLetterOrDigit)).ToArray();
        return new HashSet<string>(configured.Length == 0 ? DefaultExtensions : configured, StringComparer.Ordinal);
    }
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static IResult Error(int status, string code) => Results.Json(new ErrorResponse(code), PrivacyLinkJsonContext.Default.ErrorResponse, statusCode: status);
    private static bool Only(JsonElement value, params string[] names) => value.EnumerateObject().Count() == names.Length && KnownOnly(value, names) && value.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() == names.Length;
    private static bool KnownOnly(JsonElement value, params string[] names) => value.EnumerateObject().All(p => names.Contains(p.Name, StringComparer.Ordinal)) && value.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() == value.EnumerateObject().Count();
    private static bool ValidId(string id) => TryDecodeCanonical(id, 16, 16, out _);
    private static bool ValidExtension(string extension) =>
        extension.Length is > 1 and <= 16 && extension[0] == '.' && extension == extension.ToLowerInvariant() && extension.Skip(1).All(char.IsAsciiLetterOrDigit);
    private static bool ValidEncryptedFileName(string extension, string ciphertext) =>
        TryDecodeCanonical(ciphertext, 16, 271, out var bytes) && bytes.Length - 16 + extension.Length <= 255;
    private static bool ValidMimeType(string value) =>
        value.Length is > 0 and <= 255 &&
        value.All(c => c is >= '!' and <= '~' && c is not '"' and not ';' and not '\\');
    private static bool TryDecodeCanonical(string value, int minBytes, int maxBytes, out byte[] bytes)
    {
        bytes = [];
        if (value.Length > ((maxBytes + 2) / 3) * 4 || value.Contains('=') || value.Length == 0 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_')) return false;
        try { var padded = value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4); bytes = Convert.FromBase64String(padded); return bytes.Length >= minBytes && bytes.Length <= maxBytes && Encode(bytes) == value; }
        catch (FormatException) { return false; }
    }
}
