namespace PrivacyLink.Services;

public interface ICreateProofReplayStore
{
    Task<CreateProofConsumeResult> TryConsumeAsync(string challengeId, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken cancellationToken);
}

public enum CreateProofConsumeResult { Consumed, Replay, Full }

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
    string? RevokeTokenHash = null,
    string? EmailAddress = null)
{
    public bool PasswordProtected => PasswordSalt is not null;
}

public enum EmailCodeVerificationStatus { Invalid, RateLimited, Verified }
public enum EmailSecretAccessStatus { NotFound, NotRequired, VerificationRequired, Authorized }
public sealed record EncryptedEmailCode(byte[] Nonce, byte[] Ciphertext, byte[] Tag);
public sealed record ClaimedEmailDelivery(long OutboxId, Guid LeaseToken, string SecretId, byte[] CodeMac, byte[] Nonce, byte[] Ciphertext, byte[] Tag, string Recipient);

public interface IEmailVerificationStore
{
    bool IsAvailable { get; }
    Task RecordRequestAsync(System.Net.IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<EmailCodeVerificationStatus> RecordFailedCodeInputAsync(System.Net.IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task RequestCodeAsync(string secretId, System.Net.IPAddress clientIp, byte[] codeMac, EncryptedEmailCode encryptedCode, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<ClaimedEmailDelivery?> ClaimDeliveryAsync(DateTimeOffset now, TimeSpan leaseDuration, CancellationToken cancellationToken = default);
    Task<bool> IsDeliveryCurrentAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task CompleteDeliveryAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task FailDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default);
    Task DiscardDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default);
    Task<EmailCodeVerificationStatus> VerifyCodeAsync(string secretId, System.Net.IPAddress clientIp, byte[] codeMac, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<EmailSecretAccessStatus> CheckAccessAsync(string secretId, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task CleanupAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}

public sealed record UnlockAttemptAdmission(bool SecretExists, bool Allowed, DateTimeOffset? RetryAt = null);

public sealed record SecretRequestAuditStart(Guid RequestId, string TraceId, string SecretId, string SecretIdSource, string? RequestedSecretId, string Action, string HttpMethod, string RouteTemplate, DateTimeOffset StartedAt, System.Net.IPAddress? ClientIp, string? FileId);
public sealed record SecretRequestAuditFinish(DateTimeOffset CompletedAt, long DurationMs, string State, string? Outcome, int? HttpStatus, string? ErrorCode);
public sealed record SecretRequestAuditRecord(long Id, Guid RequestId, string TraceId, string SecretId, string SecretIdSource, string? RequestedSecretId, string Action, string HttpMethod, string RouteTemplate, DateTimeOffset StartedAt, DateTimeOffset? CompletedAt, long? DurationMs, string State, string? Outcome, int? HttpStatus, string? ErrorCode, System.Net.IPAddress? ClientIp, string? FileId);
public sealed record SecretRequestAuditQuery(int Page, int PageSize, string SortBy, bool Descending, string? SecretId, string? ClientIp);
public sealed record SecretRequestAuditPage(IReadOnlyList<SecretRequestAuditRecord> Items, long TotalCount);

public sealed class SecretAuditUnavailableException : Exception
{
    public SecretAuditUnavailableException(Exception? inner = null) : base("Secret request audit storage is unavailable.", inner) { }
}

public interface ISecretRequestAuditWriter
{
    Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default);
    Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default);
}

public interface ISecretRequestAuditReader
{
    Task<SecretRequestAuditPage> ListAsync(SecretRequestAuditQuery query, CancellationToken cancellationToken = default);
}

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
    Task<StoredSecret?> CreateAsync(StoredSecret secret, Guid? auditRequestId = null, CancellationToken cancellationToken = default);
    Task<StoredSecret?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<StoredSecret?> GetForRevocationAsync(string id, string revokeTokenHash, CancellationToken cancellationToken = default);
    Task<UnlockAttemptAdmission> ReserveUnlockAttemptAsync(string id, DateTimeOffset now, int maxAttempts, TimeSpan window, TimeSpan cooldown, CancellationToken cancellationToken = default);
    Task ResetUnlockAttemptsAsync(string id, Guid? auditRequestId = null, CancellationToken cancellationToken = default);
    Task<StoredSecret?> RevokeAsync(string id, string revokeTokenHash, Guid? auditRequestId = null, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<StoredSecret>> GetExpiredAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default);
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
}
