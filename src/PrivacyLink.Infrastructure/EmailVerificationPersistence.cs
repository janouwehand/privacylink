using System.Data;
using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

internal sealed class UnavailableEmailVerificationStore : IEmailVerificationStore
{
    public bool IsAvailable => false;
    public Task RecordRequestAsync(IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<EmailCodeVerificationStatus> RecordFailedCodeInputAsync(IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        Task.FromResult(EmailCodeVerificationStatus.Invalid);
    public Task RequestCodeAsync(string secretId, IPAddress clientIp, byte[] codeMac, EncryptedEmailCode encryptedCode, DateTimeOffset now, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<ClaimedEmailDelivery?> ClaimDeliveryAsync(DateTimeOffset now, TimeSpan leaseDuration, CancellationToken cancellationToken = default) => Task.FromResult<ClaimedEmailDelivery?>(null);
    public Task<bool> IsDeliveryCurrentAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task CompleteDeliveryAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task FailDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task DiscardDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<EmailCodeVerificationStatus> VerifyCodeAsync(string secretId, IPAddress clientIp, byte[] codeMac, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        Task.FromResult(EmailCodeVerificationStatus.Invalid);
    public Task<EmailSecretAccessStatus> CheckAccessAsync(string secretId, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        Task.FromResult(EmailSecretAccessStatus.VerificationRequired);
    public Task CleanupAsync(DateTimeOffset now, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

internal sealed class PostgresEmailVerificationStore(IConfiguration configuration, EmailVerificationOptions options) : IEmailVerificationStore
{
    private readonly string? _connectionString = configuration.GetConnectionString("PrivacyLink");
    private readonly byte[]? _key = options.HmacKey;

    public bool IsAvailable => !string.IsNullOrWhiteSpace(_connectionString) && _key is { Length: >= 32 };

    public async Task RecordRequestAsync(IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await LockRateLimitsAsync(connection, transaction, clientIp, null, cancellationToken);
        var ipMac = Hash("ip", Normalize(clientIp));
        await InsertEventAsync(connection, transaction, "request", ipMac, null, null, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<EmailCodeVerificationStatus> RecordFailedCodeInputAsync(IPAddress clientIp, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return EmailCodeVerificationStatus.Invalid;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await LockRateLimitsAsync(connection, transaction, clientIp, null, cancellationToken);
        var ipMac = Hash("ip", Normalize(clientIp));
        var failedCounts = await ReadIpCountsAsync(connection, transaction, "failed", ipMac, now, cancellationToken);
        if (failedCounts.Hour >= 30 || failedCounts.Day >= 100)
        {
            await transaction.CommitAsync(cancellationToken);
            return EmailCodeVerificationStatus.RateLimited;
        }
        await InsertEventAsync(connection, transaction, "failed", ipMac, null, null, now, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return EmailCodeVerificationStatus.Invalid;
    }

    public async Task RequestCodeAsync(string secretId, IPAddress clientIp, byte[] codeMac, EncryptedEmailCode encryptedCode, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await LockRateLimitsAsync(connection, transaction, clientIp, secretId, cancellationToken);

        var ipMac = Hash("ip", Normalize(clientIp));
        await InsertEventAsync(connection, transaction, "request", ipMac, null, null, now, cancellationToken);

        var requestCounts = await ReadIpCountsAsync(connection, transaction, "request", ipMac, now, cancellationToken);
        var ipLimited = requestCounts.Hour > 10 || requestCounts.Day > 30;
        if (ipLimited)
        {
            await transaction.CommitAsync(cancellationToken);
            return;
        }

        string? recipient = null;
        await using (var secret = new NpgsqlCommand("SELECT email_address FROM secrets WHERE id=$1 AND expires_at>$2 FOR UPDATE", connection, transaction))
        {
            secret.Parameters.AddWithValue(secretId);
            secret.Parameters.AddWithValue(now.UtcDateTime);
            var result = await secret.ExecuteScalarAsync(cancellationToken);
            recipient = result is string address ? address : null;
        }

        if (recipient is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return;
        }

        var scopeMac = Hash("secret-email", secretId + "\0" + recipient);
        var secretLimited = false;
        await using (var count = new NpgsqlCommand("SELECT COUNT(*), MAX(occurred_at) FROM email_verification_events WHERE event_kind='send' AND scope_mac=$1 AND occurred_at > $2", connection, transaction))
        {
            count.Parameters.AddWithValue(scopeMac);
            count.Parameters.AddWithValue(now.AddHours(-1).UtcDateTime);
            await using var reader = await count.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
            await reader.ReadAsync(cancellationToken);
            var hourlySends = reader.GetInt64(0);
            var previousSend = reader.IsDBNull(1) ? (DateTime?)null : reader.GetDateTime(1);
            secretLimited = hourlySends >= 5 || previousSend is { } prior && now.UtcDateTime - prior < TimeSpan.FromSeconds(60);
        }
        if (secretLimited)
        {
            await transaction.CommitAsync(cancellationToken);
            return;
        }

        // Count a send once it is allowed to replace the active challenge. This reservation
        // remains counted if the provider subsequently rejects or cannot deliver the email.
        await InsertEventAsync(connection, transaction, "send", ipMac, scopeMac, secretId, now, cancellationToken);

        await using (var challenge = new NpgsqlCommand("INSERT INTO email_verification_challenges (secret_id, code_mac, expires_at, failed_attempts, active) VALUES ($1,$2,$3,0,false) ON CONFLICT (secret_id) DO UPDATE SET code_mac=EXCLUDED.code_mac, expires_at=EXCLUDED.expires_at, failed_attempts=0, active=false", connection, transaction))
        {
            challenge.Parameters.AddWithValue(secretId);
            challenge.Parameters.AddWithValue(codeMac);
            challenge.Parameters.AddWithValue(now.AddMinutes(5).UtcDateTime);
            await challenge.ExecuteNonQueryAsync(cancellationToken);
        }

        // Replacing a challenge also discards its old pending send. A delivery already
        // claimed by another worker will fail its lease/current-challenge check.
        await using (var removeOldOutbox = new NpgsqlCommand("DELETE FROM email_verification_outbox WHERE secret_id=$1", connection, transaction))
        {
            removeOldOutbox.Parameters.AddWithValue(secretId);
            await removeOldOutbox.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var outbox = new NpgsqlCommand("INSERT INTO email_verification_outbox (secret_id, code_mac, nonce, ciphertext, auth_tag, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)", connection, transaction))
        {
            outbox.Parameters.AddWithValue(secretId);
            outbox.Parameters.AddWithValue(codeMac);
            outbox.Parameters.AddWithValue(encryptedCode.Nonce);
            outbox.Parameters.AddWithValue(encryptedCode.Ciphertext);
            outbox.Parameters.AddWithValue(encryptedCode.Tag);
            outbox.Parameters.AddWithValue(now.AddMinutes(5).UtcDateTime);
            outbox.Parameters.AddWithValue(now.UtcDateTime);
            await outbox.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<ClaimedEmailDelivery?> ClaimDeliveryAsync(DateTimeOffset now, TimeSpan leaseDuration, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return null;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        var leaseToken = Guid.NewGuid();
        await using var command = new NpgsqlCommand("""
            WITH candidate AS (
                SELECT o.id
                FROM email_verification_outbox o
                JOIN email_verification_challenges c ON c.secret_id=o.secret_id AND c.code_mac=o.code_mac
                JOIN secrets s ON s.id=o.secret_id
                WHERE o.expires_at>$1
                  AND (o.lease_until IS NULL OR o.lease_until<=$1)
                  AND c.active=false AND c.expires_at>$1
                  AND s.expires_at>$1 AND s.email_address IS NOT NULL
                ORDER BY o.id
                LIMIT 1
                FOR UPDATE OF o SKIP LOCKED
            ), leased AS (
                UPDATE email_verification_outbox o
                SET lease_until=$2, lease_token=$3, attempts=o.attempts+1
                FROM candidate
                WHERE o.id=candidate.id
                RETURNING o.id, o.secret_id, o.code_mac, o.nonce, o.ciphertext, o.auth_tag, o.lease_token
            )
            SELECT l.id, l.secret_id, l.code_mac, l.nonce, l.ciphertext, l.auth_tag, l.lease_token, s.email_address
            FROM leased l JOIN secrets s ON s.id=l.secret_id
            """, connection, transaction);
        command.Parameters.AddWithValue(now.UtcDateTime);
        command.Parameters.AddWithValue(now.Add(leaseDuration).UtcDateTime);
        command.Parameters.AddWithValue(leaseToken);
        ClaimedEmailDelivery? delivery = null;
        await using (var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                delivery = new ClaimedEmailDelivery(
                    reader.GetInt64(0),
                    reader.GetGuid(6),
                    reader.GetString(1),
                    (byte[])reader[2],
                    (byte[])reader[3],
                    (byte[])reader[4],
                    (byte[])reader[5],
                    reader.GetString(7));
            }
        }
        await transaction.CommitAsync(cancellationToken);
        return delivery;
    }

    public async Task<bool> IsDeliveryCurrentAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM email_verification_outbox o JOIN email_verification_challenges c ON c.secret_id=o.secret_id AND c.code_mac=o.code_mac JOIN secrets s ON s.id=o.secret_id WHERE o.id=$1 AND o.lease_token=$2 AND o.secret_id=$3 AND o.code_mac=$4 AND o.lease_until>$5 AND o.expires_at>$5 AND c.active=false AND c.expires_at>$5 AND s.expires_at>$5 AND s.email_address IS NOT NULL)", connection);
        command.Parameters.AddWithValue(delivery.OutboxId);
        command.Parameters.AddWithValue(delivery.LeaseToken);
        command.Parameters.AddWithValue(delivery.SecretId);
        command.Parameters.AddWithValue(delivery.CodeMac);
        command.Parameters.AddWithValue(now.UtcDateTime);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }

    public async Task CompleteDeliveryAsync(ClaimedEmailDelivery delivery, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        bool challengeLocked;
        await using (var lockChallenge = new NpgsqlCommand("SELECT 1 FROM email_verification_challenges WHERE secret_id=$1 AND code_mac=$2 AND active=false FOR UPDATE", connection, transaction))
        {
            lockChallenge.Parameters.AddWithValue(delivery.SecretId);
            lockChallenge.Parameters.AddWithValue(delivery.CodeMac);
            challengeLocked = await lockChallenge.ExecuteScalarAsync(cancellationToken) is not null;
        }
        byte[]? codeMac = null;
        string? secretId = null;
        await using (var remove = new NpgsqlCommand("DELETE FROM email_verification_outbox WHERE id=$1 AND lease_token=$2 AND secret_id=$3 AND code_mac=$4 RETURNING secret_id, code_mac", connection, transaction))
        {
            remove.Parameters.AddWithValue(delivery.OutboxId);
            remove.Parameters.AddWithValue(delivery.LeaseToken);
            remove.Parameters.AddWithValue(delivery.SecretId);
            remove.Parameters.AddWithValue(delivery.CodeMac);
            await using var reader = await remove.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                secretId = reader.GetString(0);
                codeMac = (byte[])reader[1];
            }
        }
        if (challengeLocked && secretId is not null && codeMac is not null)
        {
            await using var activate = new NpgsqlCommand("UPDATE email_verification_challenges c SET active=true FROM secrets s WHERE c.secret_id=$1 AND c.code_mac=$2 AND c.active=false AND c.expires_at>$3 AND s.id=c.secret_id AND s.expires_at>$3 AND s.email_address IS NOT NULL", connection, transaction);
            activate.Parameters.AddWithValue(secretId);
            activate.Parameters.AddWithValue(codeMac);
            activate.Parameters.AddWithValue(now.UtcDateTime);
            await activate.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task FailDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using (var lockChallenge = new NpgsqlCommand("SELECT 1 FROM email_verification_challenges WHERE secret_id=$1 AND code_mac=$2 AND active=false FOR UPDATE", connection, transaction))
        {
            lockChallenge.Parameters.AddWithValue(delivery.SecretId);
            lockChallenge.Parameters.AddWithValue(delivery.CodeMac);
            await lockChallenge.ExecuteScalarAsync(cancellationToken);
        }
        byte[]? codeMac = null;
        string? secretId = null;
        await using (var remove = new NpgsqlCommand("DELETE FROM email_verification_outbox WHERE id=$1 AND lease_token=$2 AND secret_id=$3 AND code_mac=$4 RETURNING secret_id, code_mac", connection, transaction))
        {
            remove.Parameters.AddWithValue(delivery.OutboxId);
            remove.Parameters.AddWithValue(delivery.LeaseToken);
            remove.Parameters.AddWithValue(delivery.SecretId);
            remove.Parameters.AddWithValue(delivery.CodeMac);
            await using var reader = await remove.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                secretId = reader.GetString(0);
                codeMac = (byte[])reader[1];
            }
        }
        if (secretId is not null && codeMac is not null)
        {
            await using var invalidate = new NpgsqlCommand("DELETE FROM email_verification_challenges WHERE secret_id=$1 AND code_mac=$2 AND active=false", connection, transaction);
            invalidate.Parameters.AddWithValue(secretId);
            invalidate.Parameters.AddWithValue(codeMac);
            await invalidate.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task DiscardDeliveryAsync(ClaimedEmailDelivery delivery, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return;
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("DELETE FROM email_verification_outbox WHERE id=$1 AND lease_token=$2 AND secret_id=$3 AND code_mac=$4", connection);
        command.Parameters.AddWithValue(delivery.OutboxId);
        command.Parameters.AddWithValue(delivery.LeaseToken);
        command.Parameters.AddWithValue(delivery.SecretId);
        command.Parameters.AddWithValue(delivery.CodeMac);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<EmailCodeVerificationStatus> VerifyCodeAsync(string secretId, IPAddress clientIp, byte[] codeMac, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return EmailCodeVerificationStatus.Invalid;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        var ipMac = Hash("ip", Normalize(clientIp));
        await LockRateLimitsAsync(connection, transaction, clientIp, null, cancellationToken);

        var eligible = false;
        await using (var secret = new NpgsqlCommand("SELECT email_address FROM secrets WHERE id=$1 AND email_address IS NOT NULL AND expires_at>$2 FOR UPDATE", connection, transaction))
        {
            secret.Parameters.AddWithValue(secretId);
            secret.Parameters.AddWithValue(now.UtcDateTime);
            eligible = await secret.ExecuteScalarAsync(cancellationToken) is string;
        }

        byte[]? storedMac = null;
        var challengeExpiry = DateTime.MinValue;
        var failures = 0;
        if (eligible)
        {
            await using var challenge = new NpgsqlCommand("SELECT code_mac, expires_at, failed_attempts, active FROM email_verification_challenges WHERE secret_id=$1 FOR UPDATE", connection, transaction);
            challenge.Parameters.AddWithValue(secretId);
            await using var reader = await challenge.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                storedMac = (byte[])reader[0];
                challengeExpiry = reader.GetDateTime(1);
                failures = reader.GetInt32(2);
                if (!reader.GetBoolean(3)) storedMac = null;
            }
        }

        var codeMatches = storedMac is { Length: 32 } && challengeExpiry > now.UtcDateTime && CryptographicOperations.FixedTimeEquals(storedMac, codeMac);
        if (codeMatches)
        {
            await using var addSession = new NpgsqlCommand("INSERT INTO email_verification_sessions (session_mac, secret_id, expires_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING", connection, transaction);
            addSession.Parameters.AddWithValue(sessionMac);
            addSession.Parameters.AddWithValue(secretId);
            addSession.Parameters.AddWithValue(now.AddMinutes(30).UtcDateTime);
            if (await addSession.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                await transaction.RollbackAsync(cancellationToken);
                return EmailCodeVerificationStatus.Invalid;
            }
            await using var consume = new NpgsqlCommand("DELETE FROM email_verification_challenges WHERE secret_id=$1", connection, transaction);
            consume.Parameters.AddWithValue(secretId);
            if (await consume.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                await transaction.RollbackAsync(cancellationToken);
                return EmailCodeVerificationStatus.Invalid;
            }
            await using (var discardOutbox = new NpgsqlCommand("DELETE FROM email_verification_outbox WHERE secret_id=$1", connection, transaction))
            {
                discardOutbox.Parameters.AddWithValue(secretId);
                await discardOutbox.ExecuteNonQueryAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
            return EmailCodeVerificationStatus.Verified;
        }

        if (storedMac is not null && challengeExpiry <= now.UtcDateTime)
        {
            await using var removeExpired = new NpgsqlCommand("DELETE FROM email_verification_challenges WHERE secret_id=$1", connection, transaction);
            removeExpired.Parameters.AddWithValue(secretId);
            await removeExpired.ExecuteNonQueryAsync(cancellationToken);
        }

        var failedCounts = await ReadIpCountsAsync(connection, transaction, "failed", ipMac, now, cancellationToken);
        if (failedCounts.Hour >= 30 || failedCounts.Day >= 100)
        {
            await transaction.CommitAsync(cancellationToken);
            return EmailCodeVerificationStatus.RateLimited;
        }
        await InsertEventAsync(connection, transaction, "failed", ipMac, null, null, now, cancellationToken);

        if (storedMac is not null && challengeExpiry > now.UtcDateTime)
        {
            var nextFailures = failures + 1;
            if (nextFailures >= 3)
            {
                await using var remove = new NpgsqlCommand("DELETE FROM email_verification_challenges WHERE secret_id=$1", connection, transaction);
                remove.Parameters.AddWithValue(secretId);
                await remove.ExecuteNonQueryAsync(cancellationToken);
            }
            else
            {
                await using var update = new NpgsqlCommand("UPDATE email_verification_challenges SET failed_attempts=$2 WHERE secret_id=$1", connection, transaction);
                update.Parameters.AddWithValue(secretId);
                update.Parameters.AddWithValue(nextFailures);
                await update.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        await transaction.CommitAsync(cancellationToken);
        return EmailCodeVerificationStatus.Invalid;
    }

    public async Task<EmailSecretAccessStatus> CheckAccessAsync(string secretId, byte[] sessionMac, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable) return EmailSecretAccessStatus.VerificationRequired;
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT email_address, EXISTS (SELECT 1 FROM email_verification_sessions s WHERE s.secret_id=secrets.id AND s.session_mac=$3 AND s.expires_at>$2) FROM secrets WHERE id=$1 AND expires_at>$2", connection);
        command.Parameters.AddWithValue(secretId);
        command.Parameters.AddWithValue(now.UtcDateTime);
        command.Parameters.AddWithValue(sessionMac);
        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return EmailSecretAccessStatus.NotFound;
        if (reader.IsDBNull(0)) return EmailSecretAccessStatus.NotRequired;
        return reader.GetBoolean(1) ? EmailSecretAccessStatus.Authorized : EmailSecretAccessStatus.VerificationRequired;
    }

    public async Task CleanupAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        // Cleanup does not need the HMAC key. Keep retention working even when the
        // optional mailbox-verification feature is currently unconfigured.
        if (string.IsNullOrWhiteSpace(_connectionString)) return;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using (var expiredOutbox = new NpgsqlCommand("DELETE FROM email_verification_outbox WHERE expires_at <= $1", connection, transaction))
        {
            expiredOutbox.Parameters.AddWithValue(now.UtcDateTime);
            await expiredOutbox.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var staleOutbox = new NpgsqlCommand("DELETE FROM email_verification_outbox o WHERE NOT EXISTS (SELECT 1 FROM email_verification_challenges c JOIN secrets s ON s.id=c.secret_id WHERE c.secret_id=o.secret_id AND c.code_mac=o.code_mac AND c.active=false AND c.expires_at>$1 AND s.expires_at>$1 AND s.email_address IS NOT NULL)", connection, transaction))
        {
            staleOutbox.Parameters.AddWithValue(now.UtcDateTime);
            await staleOutbox.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var expiredEvents = new NpgsqlCommand("DELETE FROM email_verification_events e USING secrets s WHERE e.secret_id=s.id AND s.expires_at <= $1", connection, transaction))
        {
            expiredEvents.Parameters.AddWithValue(now.UtcDateTime);
            await expiredEvents.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var challenges = new NpgsqlCommand("DELETE FROM email_verification_challenges WHERE expires_at <= $1", connection, transaction))
        {
            challenges.Parameters.AddWithValue(now.UtcDateTime);
            await challenges.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var expiredChallenges = new NpgsqlCommand("DELETE FROM email_verification_challenges c USING secrets s WHERE c.secret_id=s.id AND s.expires_at <= $1", connection, transaction))
        {
            expiredChallenges.Parameters.AddWithValue(now.UtcDateTime);
            await expiredChallenges.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var sessions = new NpgsqlCommand("DELETE FROM email_verification_sessions WHERE expires_at <= $1", connection, transaction))
        {
            sessions.Parameters.AddWithValue(now.UtcDateTime);
            await sessions.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var expiredSessions = new NpgsqlCommand("DELETE FROM email_verification_sessions s USING secrets secret WHERE s.secret_id=secret.id AND secret.expires_at <= $1", connection, transaction))
        {
            expiredSessions.Parameters.AddWithValue(now.UtcDateTime);
            await expiredSessions.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var emailAddresses = new NpgsqlCommand("UPDATE secrets SET email_address=NULL WHERE expires_at <= $1 AND email_address IS NOT NULL", connection, transaction))
        {
            emailAddresses.Parameters.AddWithValue(now.UtcDateTime);
            await emailAddresses.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var events = new NpgsqlCommand("DELETE FROM email_verification_events WHERE occurred_at <= $1", connection, transaction))
        {
            events.Parameters.AddWithValue(now.AddDays(-1).UtcDateTime);
            await events.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private async Task<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new NpgsqlConnection(_connectionString!);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private async Task LockRateLimitsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, IPAddress clientIp, string? secretId, CancellationToken cancellationToken)
    {
        var keys = new List<long> { RateLimitLockKey("ip", Normalize(clientIp)) };
        if (secretId is not null) keys.Add(RateLimitLockKey("secret", secretId));
        foreach (var key in keys.Distinct().Order())
        {
            await using var command = new NpgsqlCommand("SELECT pg_advisory_xact_lock($1)", connection, transaction);
            command.Parameters.AddWithValue(key);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private long RateLimitLockKey(string purpose, string value)
    {
        var input = Encoding.UTF8.GetBytes($"PrivacyLink:EmailVerification:rate-lock:{purpose}\0{value}");
        return BinaryPrimitives.ReadInt64BigEndian(HMACSHA256.HashData(_key!, input));
    }

    private static async Task<long> InsertEventAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string kind, byte[] ipMac, byte[]? scopeMac, string? secretId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("INSERT INTO email_verification_events (event_kind, ip_mac, scope_mac, secret_id, occurred_at) VALUES ($1,$2,$3,$4,$5) RETURNING id", connection, transaction);
        command.Parameters.AddWithValue(kind);
        command.Parameters.AddWithValue(ipMac);
        command.Parameters.AddWithValue((object?)scopeMac ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)secretId ?? DBNull.Value);
        command.Parameters.AddWithValue(now.UtcDateTime);
        return (long)(await command.ExecuteScalarAsync(cancellationToken) ?? 0L);
    }

    private static async Task<(long Hour, long Day)> ReadIpCountsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string kind, byte[] ipMac, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT COUNT(*) FILTER (WHERE occurred_at > $3), COUNT(*) FILTER (WHERE occurred_at > $4) FROM email_verification_events WHERE event_kind=$1 AND ip_mac=$2", connection, transaction);
        command.Parameters.AddWithValue(kind);
        command.Parameters.AddWithValue(ipMac);
        command.Parameters.AddWithValue(now.AddHours(-1).UtcDateTime);
        command.Parameters.AddWithValue(now.AddDays(-1).UtcDateTime);
        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        await reader.ReadAsync(cancellationToken);
        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    private byte[] Hash(string purpose, string value) => HMACSHA256.HashData(_key!, Encoding.UTF8.GetBytes($"PrivacyLink:EmailVerification:{purpose}\0{value}"));
    private static string Normalize(IPAddress ip) => (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
}

internal sealed class ResendEmailSender(EmailVerificationOptions options, IHttpClientFactory clients) : IEmailSender
{
    private static readonly Uri Endpoint = new("https://api.resend.com/emails");

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (!options.HasSenderConfiguration || string.IsNullOrWhiteSpace(options.ResendApiKey) || string.IsNullOrWhiteSpace(options.FromAddress))
            throw new InvalidOperationException("Email delivery is not configured.");

        using var body = new MemoryStream();
        using (var writer = new Utf8JsonWriter(body))
        {
            writer.WriteStartObject();
            writer.WriteString("from", options.FromAddress);
            writer.WriteStartArray("to");
            writer.WriteStringValue(message.Recipient);
            writer.WriteEndArray();
            writer.WriteString("subject", message.Subject);
            writer.WriteString("text", message.TextBody);
            writer.WriteString("html", message.HtmlBody);
            writer.WriteEndObject();
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.ResendApiKey);
        request.Content = new ByteArrayContent(body.ToArray());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var response = await clients.CreateClient(nameof(ResendEmailSender)).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException("Email delivery failed.");
    }
}

internal sealed class EmailVerificationCleanupService(IEmailVerificationStore store, TimeProvider clock, ILogger<EmailVerificationCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await store.CleanupAsync(clock.GetUtcNow(), stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        catch { logger.LogWarning("Email verification cleanup failed"); }

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5), clock);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { await store.CleanupAsync(clock.GetUtcNow(), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch { logger.LogWarning("Email verification cleanup failed"); }
        }
    }
}
