using System.Security.Cryptography;
using System.Text;

namespace PrivacyLink.Services;

public sealed record SecretCreateMessage(string Nonce, byte[] Ciphertext);
public sealed record SecretCreateFile(string Id, string Extension, string NameNonce, string NameCiphertext, string MimeType, long Size, string Nonce, byte[] Ciphertext);
public sealed record CreateSecretCommand(string Expiry, SecretCreateMessage? Message, IReadOnlyList<SecretCreateFile> Files, string? Password, string? SecretId = null, Guid? AuditRequestId = null);
public sealed record CreatedSecret(string Id, DateTimeOffset ExpiresAt, bool PasswordProtected, string RevokeToken);
public sealed record SecretOpenData(string? MessageNonce, byte[]? MessageCiphertext);
public sealed record OpenedFileData(StoredFile File, byte[] Ciphertext);
public sealed record SecretUnlockData(string? MessageNonce, byte[]? MessageCiphertext, IReadOnlyList<OpenedFileData> Files);

public sealed class SecretProtectedException : Exception { }

public sealed class SecretApplicationService(
    ISecretRepository repository,
    IBlobStorage blobs,
    PasswordEnvelopeService envelopes,
    TimeProvider clock)
{
    public Task<StoredSecret?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        repository.GetAsync(id, now, cancellationToken);

    public async Task<CreatedSecret?> CreateAsync(CreateSecretCommand command, CancellationToken cancellationToken = default)
    {
        var secretId = command.SecretId ?? NewId();
        var blobIds = new List<string>();
        var persisted = false;
        try
        {
            var revokeTokenBytes = RandomNumberGenerator.GetBytes(32);
            var revokeToken = Encode(revokeTokenBytes);
            var revokeTokenHash = Encode(SHA256.HashData(revokeTokenBytes));
            using var passwordSession = command.Password is null ? null : await envelopes.CreateSessionAsync(command.Password, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            var storedFiles = new List<StoredFile>();
            string? messageBlobId = null;
            string? messageOuterNonce = null;
            if (command.Message is not null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                messageBlobId = NewId();
                var content = command.Message.Ciphertext;
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

            foreach (var file in command.Files)
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

            var secret = new StoredSecret(
                secretId,
                clock.GetUtcNow().Add(ParseLifetime(command.Expiry)),
                command.Message?.Nonce,
                messageBlobId,
                (command.Message?.Ciphertext.LongLength ?? 0) + storedFiles.Sum(file => file.Size + 16),
                storedFiles,
                passwordSession is null ? null : Encode(passwordSession.Salt),
                messageOuterNonce,
                revokeTokenHash);
            cancellationToken.ThrowIfCancellationRequested();
            if (await repository.CreateAsync(secret, command.AuditRequestId, cancellationToken) is null)
            {
                foreach (var blobId in blobIds) await blobs.DeleteAsync(secret.Id, blobId);
                return null;
            }

            persisted = true;
            return new CreatedSecret(secret.Id, secret.ExpiresAt, secret.PasswordProtected, revokeToken);
        }
        catch
        {
            if (!persisted)
                foreach (var blobId in blobIds)
                {
                    try { await blobs.DeleteAsync(secretId, blobId); }
                    catch { }
                }
            throw;
        }
    }

    public async Task<bool> RevokeAsync(string id, string revokeTokenHash, Guid? auditRequestId = null, CancellationToken cancellationToken = default, Action<Exception>? blobDeleteFailure = null)
    {
        var candidate = await repository.GetForRevocationAsync(id, revokeTokenHash, cancellationToken);
        if (candidate is null) return false;
        var secret = await repository.RevokeAsync(id, revokeTokenHash, auditRequestId, cancellationToken);
        if (secret is null) return false;

        var blobIds = secret.Files.Select(file => file.BlobId)
            .Append(secret.MessageBlobId)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal);
        foreach (var blobId in blobIds)
        {
            try { await blobs.DeleteAsync(secret.Id, blobId, CancellationToken.None); }
            catch (Exception ex)
            {
                try { blobDeleteFailure?.Invoke(ex); }
                catch { }
            }
        }
        return true;
    }

    public async Task<SecretOpenData?> OpenAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var secret = await repository.GetAsync(id, now, cancellationToken);
        if (secret is null) return null;
        if (secret.PasswordProtected) throw new SecretProtectedException();

        byte[]? messageCiphertext = null;
        if (secret.MessageBlobId is not null && secret.MessageNonce is not null)
            messageCiphertext = await blobs.ReadAsync(secret.Id, secret.MessageBlobId);
        return new SecretOpenData(secret.MessageNonce, messageCiphertext);
    }

    public async Task<StoredSecret?> GetUnlockTargetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var secret = await repository.GetAsync(id, now, cancellationToken);
        if (secret is not null && (!secret.PasswordProtected || secret.PasswordSalt is null))
            throw new SecretProtectedException();
        return secret;
    }

    public async Task<SecretUnlockData> UnlockAsync(
        StoredSecret secret,
        string password,
        int maxAttempts,
        TimeSpan attemptWindow,
        TimeSpan cooldown,
        Guid? auditRequestId = null,
        CancellationToken cancellationToken = default)
    {
        if (secret.PasswordSalt is null) throw new SecretProtectedException();
        if (!TryDecodeCanonical(secret.PasswordSalt, 16, 16, out var salt)) throw new FormatException("Stored password salt is invalid.");

        async Task ReserveAttempt(CancellationToken token)
        {
            var admission = await repository.ReserveUnlockAttemptAsync(secret.Id, clock.GetUtcNow(), maxAttempts, attemptWindow, cooldown, token);
            if (!admission.SecretExists) throw new FileNotFoundException();
            if (!admission.Allowed) throw new UnlockAttemptLimitException(admission.RetryAt ?? clock.GetUtcNow().Add(cooldown));
        }

        using var session = await envelopes.OpenSessionAsync(password, salt, cancellationToken, beforeKdf: ReserveAttempt);
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? messageCiphertext = null;
        if (secret.MessageBlobId is not null && secret.MessageNonce is not null && secret.MessageOuterNonce is not null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var wrapped = await blobs.ReadAsync(secret.Id, secret.MessageBlobId);
            cancellationToken.ThrowIfCancellationRequested();
            var inner = session.Decrypt(new PasswordEnvelope(salt, Decode(secret.MessageOuterNonce), wrapped));
            cancellationToken.ThrowIfCancellationRequested();
            messageCiphertext = inner;
        }

        var files = new List<OpenedFileData>();
        foreach (var file in secret.Files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (file.OuterNonce is null) throw new InvalidDataException("Stored encrypted file is incomplete.");
            var wrapped = await blobs.ReadAsync(secret.Id, file.BlobId);
            cancellationToken.ThrowIfCancellationRequested();
            var inner = session.Decrypt(new PasswordEnvelope(salt, Decode(file.OuterNonce), wrapped));
            cancellationToken.ThrowIfCancellationRequested();
            files.Add(new OpenedFileData(file, inner));
        }

        await repository.ResetUnlockAttemptsAsync(secret.Id, auditRequestId, cancellationToken);
        return new SecretUnlockData(secret.MessageNonce, messageCiphertext, files);
    }

    public async Task<OpenedFileData?> OpenFileAsync(string id, string fileId, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var secret = await repository.GetAsync(id, now, cancellationToken);
        if (secret is null) return null;
        if (secret.PasswordProtected) throw new SecretProtectedException();
        var file = secret.Files.FirstOrDefault(candidate => candidate.Id == fileId);
        if (file is null) return null;
        return new OpenedFileData(file, await blobs.ReadAsync(secret.Id, file.BlobId));
    }

    private static TimeSpan ParseLifetime(string value) => value switch
    {
        "1d" => TimeSpan.FromDays(1),
        "7d" => TimeSpan.FromDays(7),
        "14d" => TimeSpan.FromDays(14),
        _ => throw new InvalidOperationException("Unsupported secret expiry.")
    };

    private static string NewId() => Encode(RandomNumberGenerator.GetBytes(16));

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));

    private static bool TryDecodeCanonical(string value, int minBytes, int maxBytes, out byte[] bytes)
    {
        bytes = [];
        if (value.Length > ((maxBytes + 2) / 3) * 4 || value.Contains('=') || value.Length == 0 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_')) return false;
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4);
            bytes = Convert.FromBase64String(padded);
            return bytes.Length >= minBytes && bytes.Length <= maxBytes && Encode(bytes) == value;
        }
        catch (FormatException) { return false; }
    }
}
