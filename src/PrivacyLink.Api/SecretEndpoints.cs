using System.Security.Cryptography;
using System.Text.Json;
using PrivacyLink.Contracts;

namespace PrivacyLink.Api;

internal static class SecretEndpoints
{
    private static readonly HashSet<string> Expiries = ["1d", "7d", "14d"];
    private static readonly string[] DefaultExtensions = [".pdf", ".txt", ".md", ".rtf", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff"];

    public static IResult Capabilities(IConfiguration configuration)
    {
        var maxFiles = Limit(configuration, "Limits:MaxFiles", 10);
        var maxFileBytes = LimitLong(configuration, "Limits:MaxTotalPlaintextFileBytes", 25 * 1024 * 1024);
        return Results.Json(new FileUploadPolicyResponse(maxFiles, maxFileBytes, AllowedExtensions(configuration).OrderBy(extension => extension, StringComparer.Ordinal).ToArray()), PrivacyLinkJsonContext.Default.FileUploadPolicyResponse);
    }

    public static async Task<IResult> Create(HttpRequest request, ISecretRepository repository, IBlobStorage blobs, PasswordEnvelopeService envelopes, TimeProvider clock, IConfiguration configuration, StatisticsRecorder statistics)
    {
        var cancellationToken = request.HttpContext.RequestAborted;
        var maxMessage = Limit(configuration, "Limits:MaxMessagePlaintextBytes", 80000);
        var maxFiles = Limit(configuration, "Limits:MaxFiles", 10);
        var maxFileBytes = LimitLong(configuration, "Limits:MaxTotalPlaintextFileBytes", 25 * 1024 * 1024);
        var maxRequestBytes = Limit(configuration, "Limits:MaxRequestBytes", 36 * 1024 * 1024);
        var allowedExtensions = AllowedExtensions(configuration);
        if (!request.HasJsonContentType()) return Error(415, "unsupported_media_type");
        if (request.ContentLength > maxRequestBytes) return Error(413, "payload_too_large");
        var blobIds = new List<string>();
        string? secretId = null;
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

            MessageInput? message = null;
            if (root.TryGetProperty("message", out var messageValue) && messageValue.ValueKind != JsonValueKind.Null)
            {
                if (messageValue.ValueKind != JsonValueKind.Object || !Only(messageValue, "nonce", "ciphertext") || !ReadCipher(messageValue, out message)) return Error(400, "invalid_request");
                if (message!.Ciphertext.Length - 16 > maxMessage) return Error(413, "payload_too_large");
            }

            var parsedFiles = new List<FileInput>();
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
                parsedFiles.Add(new FileInput(idValue.GetString()!, extensionValue.GetString()!, nameNonceValue.GetString()!, nameCiphertextValue.GetString()!, mimeValue.GetString()!, size, cipher.Nonce, cipher.Ciphertext));
            }
            if (message is null && parsedFiles.Count == 0) return Error(400, "invalid_request");

            secretId = NewId();
            var revokeTokenBytes = RandomNumberGenerator.GetBytes(32);
            var revokeToken = Encode(revokeTokenBytes);
            var revokeTokenHash = Encode(SHA256.HashData(revokeTokenBytes));
            using var passwordSession = password is null ? null : await envelopes.CreateSessionAsync(password, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            var storedFiles = new List<StoredFile>();
            string? messageBlobId = null;
            string? messageOuterNonce = null;
            if (message is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                messageBlobId = NewId();
                var content = message.Ciphertext;
                if (passwordSession is not null)
                {
                    var wrapped = passwordSession.Encrypt(content);
                    content = wrapped.Ciphertext;
                    messageOuterNonce = Encode(wrapped.Nonce);
                }
                await blobs.PutAsync(secretId, messageBlobId, content);
                blobIds.Add(messageBlobId);
                cancellationToken.ThrowIfCancellationRequested();
            }
            foreach (var file in parsedFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var blobId = NewId();
                var content = file.Ciphertext;
                string? outerNonce = null;
                if (passwordSession is not null)
                {
                    var wrapped = passwordSession.Encrypt(content);
                    content = wrapped.Ciphertext;
                    outerNonce = Encode(wrapped.Nonce);
                }
                await blobs.PutAsync(secretId, blobId, content);
                blobIds.Add(blobId);
                cancellationToken.ThrowIfCancellationRequested();
                storedFiles.Add(new StoredFile(file.Id, file.Extension, file.NameNonce, file.NameCiphertext, file.MimeType, file.Size, file.Nonce, blobId, outerNonce));
            }
            var secret = new StoredSecret(secretId, clock.GetUtcNow().Add(ParseLifetime(expiry.GetString()!)), message?.Nonce, messageBlobId, (message?.Ciphertext.LongLength ?? 0) + storedFiles.Sum(f => f.Size + 16), storedFiles, passwordSession is null ? null : Encode(passwordSession.Salt), messageOuterNonce, revokeTokenHash);
            cancellationToken.ThrowIfCancellationRequested();
            var contentType = message is not null && storedFiles.Count > 0 ? "both" : message is not null ? "text" : "files";
            var visitorEvent = statistics.Event(request.HttpContext, "creations");
            var creationStats = new[]
            {
                visitorEvent,
                visitorEvent with { Metric = "creation_content_type", Dimension = "content_type", Value = contentType },
                visitorEvent with { Metric = "creation_password_protected", Dimension = "password_protected", Value = secret.PasswordProtected ? "true" : "false" },
                visitorEvent with { Metric = "creation_expiry", Dimension = "expiry", Value = expiry.GetString()! },
                visitorEvent with { Metric = "files", Count = storedFiles.Count, Bytes = storedFiles.Sum(file => file.Size) }
            };
            if (await repository.CreateAsync(secret, creationStats) is null)
            {
                foreach (var blobId in blobIds) await blobs.DeleteAsync(secret.Id, blobId);
                request.HttpContext.Items["PrivacyLink.StatisticsErrorCategory"] = "capacity";
                return Error(429, "rate_limited");
            }
            return Results.Json(new CreateSecretResponse(secret.Id, secret.ExpiresAt, secret.PasswordProtected, revokeToken), PrivacyLinkJsonContext.Default.CreateSecretResponse, statusCode: 201);
        }
        catch (JsonException) { return Error(400, "invalid_request"); }
        catch (InvalidOperationException) { return Error(400, "invalid_request"); }
        catch (FormatException) { return Error(400, "invalid_request"); }
        catch (PasswordEnvelopeCapacityException)
        {
            if (cancellationToken.IsCancellationRequested) return Results.Empty;
            return Error(503, "temporarily_unavailable");
        }
        catch (StatisticsDayFinalizedException)
        {
            if (secretId is not null) foreach (var blobId in blobIds) { try { await blobs.DeleteAsync(secretId, blobId); } catch { } }
            if (cancellationToken.IsCancellationRequested) return Results.Empty;
            request.HttpContext.Response.Headers.RetryAfter = "2";
            return Error(503, "temporarily_unavailable");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (secretId is not null) foreach (var blobId in blobIds) { try { await blobs.DeleteAsync(secretId, blobId); } catch { } }
            return Results.Empty;
        }
        catch
        {
            if (secretId is not null) foreach (var blobId in blobIds) { try { await blobs.DeleteAsync(secretId, blobId); } catch { } }
            return Error(500, "server_error");
        }
    }

    public static async Task<IResult> Metadata(string id, ISecretRepository repository, TimeProvider clock)
    {
        if (!ValidId(id) || await repository.GetAsync(id, clock.GetUtcNow()) is not { } secret) return Error(404, "not_found");
        var metadata = secret.PasswordProtected
            ? Array.Empty<FileMetadataResponse>()
            : secret.Files.Select(Metadata).ToArray();
        return Results.Json(new SecretMetadataResponse(true, 1, secret.ExpiresAt, secret.PasswordProtected, secret.MessageNonce is not null, secret.Files.Count, metadata), PrivacyLinkJsonContext.Default.SecretMetadataResponse);
    }

    public static async Task<IResult> Revoke(string id, HttpRequest request, ISecretRepository repository, IBlobStorage blobs)
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
            var secret = await repository.GetForRevocationAsync(id, revokeTokenHash);
            if (secret is null) return Error(404, "not_found");

            var blobIds = secret.Files.Select(file => file.BlobId)
                .Append(secret.MessageBlobId)
                .OfType<string>()
                .Distinct(StringComparer.Ordinal);
            foreach (var blobId in blobIds) await blobs.DeleteAsync(secret.Id, blobId);
            await repository.DeleteAsync(secret.Id);
            return Results.NoContent();
        }
        catch (JsonException) { return Error(400, "invalid_request"); }
    }

    public static async Task<IResult> Open(string id, HttpRequest request, ISecretRepository repository, IBlobStorage blobs, TimeProvider clock, StatisticsRecorder statistics)
    {
        if (request.ContentLength is > 0 || request.Headers.ContainsKey("Transfer-Encoding")) return Error(400, "invalid_request");
        if (!ValidId(id) || await repository.GetAsync(id, clock.GetUtcNow()) is not { } secret) return Error(404, "not_found");
        if (secret.PasswordProtected) return Error(403, "forbidden");
        try
        {
            MessageCiphertext? message = null;
            if (secret.MessageBlobId is not null && secret.MessageNonce is not null) message = new MessageCiphertext(secret.MessageNonce, Encode(await blobs.ReadAsync(secret.Id, secret.MessageBlobId)));
            await statistics.RecordAsync(statistics.Event(request.HttpContext, "secret_open"), request.HttpContext.RequestAborted);
            return Results.Json(new OpenSecretResponse(1, message, []), PrivacyLinkJsonContext.Default.OpenSecretResponse);
        }
        catch (FileNotFoundException) { return Error(404, "not_found"); }
    }

    public static async Task<IResult> Unlock(string id, HttpRequest request, ISecretRepository repository, IBlobStorage blobs, PasswordEnvelopeService envelopes, TimeProvider clock, IConfiguration configuration, StatisticsRecorder statistics)
    {
        var cancellationToken = request.HttpContext.RequestAborted;
        var maxAttempts = BoundedLimit(configuration, "Security:UnlockAttempts:MaxPerWindow", 5, 1, 100);
        var attemptWindow = TimeSpan.FromMinutes(BoundedLimit(configuration, "Security:UnlockAttempts:WindowMinutes", 15, 1, 1440));
        var cooldown = TimeSpan.FromMinutes(BoundedLimit(configuration, "Security:UnlockAttempts:CooldownMinutes", 15, 1, 1440));
        if (!request.HasJsonContentType() || request.ContentLength is > 16 * 1024 || request.ContentLength is 0) return Error(400, "invalid_request");
        if (!ValidId(id) || await repository.GetAsync(id, clock.GetUtcNow()) is not { } secret) return Error(404, "not_found");
        if (!secret.PasswordProtected || secret.PasswordSalt is null) return Error(403, "forbidden");
        try
        {
            using var document = await JsonDocument.ParseAsync(request.Body, new JsonDocumentOptions { MaxDepth = 3 }, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Only(root, "password") || !root.TryGetProperty("password", out var password) || password.ValueKind != JsonValueKind.String || password.GetString() is not { } value)
                return Error(400, "invalid_request");
            if (!TryDecodeCanonical(secret.PasswordSalt, 16, 16, out var salt)) return Error(500, "server_error");
            async Task ReserveAttempt(CancellationToken token)
            {
                var admission = await repository.ReserveUnlockAttemptAsync(secret.Id, clock.GetUtcNow(), maxAttempts, attemptWindow, cooldown, token);
                if (!admission.SecretExists) throw new FileNotFoundException();
                if (!admission.Allowed) throw new UnlockAttemptLimitException(admission.RetryAt ?? clock.GetUtcNow().Add(cooldown));
            }
            using var session = await envelopes.OpenSessionAsync(value, salt, cancellationToken, beforeKdf: ReserveAttempt);
            cancellationToken.ThrowIfCancellationRequested();
            MessageCiphertext? message = null;
            if (secret.MessageBlobId is not null && secret.MessageNonce is not null && secret.MessageOuterNonce is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var wrapped = await blobs.ReadAsync(secret.Id, secret.MessageBlobId);
                cancellationToken.ThrowIfCancellationRequested();
                var inner = session.Decrypt(new PasswordEnvelope(salt, Decode(secret.MessageOuterNonce), wrapped));
                cancellationToken.ThrowIfCancellationRequested();
                message = new MessageCiphertext(secret.MessageNonce, Encode(inner));
            }
            var files = new List<OpenedFileResponse>();
            foreach (var file in secret.Files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (file.OuterNonce is null) return Error(500, "server_error");
                var wrapped = await blobs.ReadAsync(secret.Id, file.BlobId);
                cancellationToken.ThrowIfCancellationRequested();
                var inner = session.Decrypt(new PasswordEnvelope(salt, Decode(file.OuterNonce), wrapped));
                cancellationToken.ThrowIfCancellationRequested();
                files.Add(OpenedFile(file, Encode(inner)));
            }
            await repository.ResetUnlockAttemptsAsync(secret.Id, cancellationToken);
            await statistics.RecordAsync(statistics.Event(request.HttpContext, "unlock"), cancellationToken);
            return Results.Json(new OpenSecretResponse(1, message, files.ToArray()), PrivacyLinkJsonContext.Default.OpenSecretResponse);
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
        catch (CryptographicException) { return Error(403, "forbidden"); }
        catch (FileNotFoundException) { return Error(404, "not_found"); }
        catch (JsonException) { return Error(400, "invalid_request"); }
        catch (FormatException) { return Error(500, "server_error"); }
    }

    public static async Task<IResult> OpenFile(string id, string fileId, HttpRequest request, ISecretRepository repository, IBlobStorage blobs, TimeProvider clock, StatisticsRecorder statistics)
    {
        if (request.ContentLength is > 0 || request.Headers.ContainsKey("Transfer-Encoding")) return Error(400, "invalid_request");
        if (!ValidId(id) || !ValidId(fileId) || await repository.GetAsync(id, clock.GetUtcNow()) is not { } secret) return Error(404, "not_found");
        if (secret.PasswordProtected) return Error(403, "forbidden");
        var file = secret.Files.FirstOrDefault(f => f.Id == fileId);
        if (file is null) return Error(404, "not_found");
        try
        {
            var ciphertext = Encode(await blobs.ReadAsync(secret.Id, file.BlobId));
            await statistics.RecordAsync(statistics.Event(request.HttpContext, "file_retrieval", bytes: file.Size), request.HttpContext.RequestAborted);
            return Results.Json(new OpenFileResponse(1, OpenedFile(file, ciphertext)), PrivacyLinkJsonContext.Default.OpenFileResponse);
        }
        catch (FileNotFoundException) { return Error(404, "not_found"); }
    }

    private sealed record MessageInput(string Nonce, byte[] Ciphertext);
    private sealed record FileInput(string Id, string Extension, string NameNonce, string NameCiphertext, string MimeType, long Size, string Nonce, byte[] Ciphertext);
    private static FileMetadataResponse Metadata(StoredFile file) => new(file.Id, file.Extension, file.NameNonce, file.NameCiphertext, file.MimeType, file.Size);
    private static OpenedFileResponse OpenedFile(StoredFile file, string ciphertext) => new(file.Id, file.Extension, file.NameNonce, file.NameCiphertext, file.MimeType, file.Size, file.Nonce, ciphertext);
    private static bool ReadCipher(JsonElement value, out MessageInput? result)
    {
        result = null;
        if (!value.TryGetProperty("nonce", out var nonce) || !value.TryGetProperty("ciphertext", out var ciphertext) || nonce.ValueKind != JsonValueKind.String || ciphertext.ValueKind != JsonValueKind.String) return false;
        if (!TryDecodeCanonical(nonce.GetString()!, 12, 12, out _) || !TryDecodeCanonical(ciphertext.GetString()!, 17, 36 * 1024 * 1024, out var bytes)) return false;
        result = new MessageInput(nonce.GetString()!, bytes);
        return true;
    }
    private static TimeSpan ParseLifetime(string value) => value switch { "1d" => TimeSpan.FromDays(1), "7d" => TimeSpan.FromDays(7), "14d" => TimeSpan.FromDays(14), _ => TimeSpan.FromDays(14) };
    private static int Limit(IConfiguration configuration, string key, int fallback) => int.TryParse(configuration[key], out var value) && value > 0 ? value : fallback;
    private static int BoundedLimit(IConfiguration configuration, string key, int fallback, int minimum, int maximum) => int.TryParse(configuration[key], out var value) && value >= minimum && value <= maximum ? value : fallback;
    private static long LimitLong(IConfiguration configuration, string key, long fallback) => long.TryParse(configuration[key], out var value) && value > 0 ? value : fallback;
    private static HashSet<string> AllowedExtensions(IConfiguration configuration)
    {
        var configured = configuration.GetSection("Limits:AllowedFileExtensions").GetChildren().Select(section => section.Value).OfType<string>()
            .Select(extension => extension.Trim().ToLowerInvariant()).Where(extension => extension.Length is > 1 and <= 16 && extension[0] == '.' && extension.Skip(1).All(char.IsAsciiLetterOrDigit)).ToArray();
        return new HashSet<string>(configured.Length == 0 ? DefaultExtensions : configured, StringComparer.Ordinal);
    }
    private static string NewId() => Encode(RandomNumberGenerator.GetBytes(16));
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
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
