namespace PrivacyLink.Services;

public sealed record StoredFile(
    string Id,
    string Extension,
    string NameNonce,
    string NameCiphertext,
    string MimeType,
    long Size,
    string Nonce,
    string BlobId,
    string? OuterNonce = null);

public sealed record StoredSecret(
    string Id,
    DateTimeOffset ExpiresAt,
    string? MessageNonce,
    string? MessageBlobId,
    long Size,
    IReadOnlyList<StoredFile> Files,
    string? PasswordSalt = null,
    string? MessageOuterNonce = null,
    string? RevokeTokenHash = null)
{
    public bool PasswordProtected => PasswordSalt is not null;
}

public sealed record UnlockAttemptAdmission(bool SecretExists, bool Allowed, DateTimeOffset? RetryAt = null);

public sealed class UnlockAttemptLimitException(DateTimeOffset retryAt) : Exception
{
    public DateTimeOffset RetryAt { get; } = retryAt;
}

public interface IBlobStorage
{
    Task PutAsync(string secretId, string blobId, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken = default);
    Task<byte[]> ReadAsync(string secretId, string blobId, CancellationToken cancellationToken = default);
    Task DeleteAsync(string secretId, string blobId, CancellationToken cancellationToken = default);
}

public interface ISecretRepository
{
    Task<StoredSecret?> CreateAsync(StoredSecret secret, CancellationToken cancellationToken = default);
    Task<StoredSecret?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<StoredSecret?> GetForRevocationAsync(string id, string revokeTokenHash, CancellationToken cancellationToken = default);
    Task<UnlockAttemptAdmission> ReserveUnlockAttemptAsync(string id, DateTimeOffset now, int maxAttempts, TimeSpan window, TimeSpan cooldown, CancellationToken cancellationToken = default);
    Task ResetUnlockAttemptsAsync(string id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<StoredSecret>> GetExpiredAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default);
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
}
