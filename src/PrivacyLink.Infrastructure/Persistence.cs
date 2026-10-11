using System.Data;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

internal interface IInfrastructureHealthCheck
{
    Task CheckHealthAsync(CancellationToken cancellationToken = default);
}

internal interface IInfrastructureInitializer
{
    Task<bool> InitializeAsync(CancellationToken cancellationToken = default);
}

public interface IStorageReadiness
{
    Task<bool> CheckReadinessAsync(CancellationToken requestCancellation);
}

internal sealed class FileBlobStorage(IConfiguration configuration) : IBlobStorage, IInfrastructureHealthCheck, IInfrastructureInitializer
{
    private readonly string _root = Path.GetFullPath(configuration["Storage:BlobPath"] ?? Path.Combine(AppContext.BaseDirectory, "data", "blobs"));

    public async Task CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Directory.CreateDirectory(_root);
        var probePath = Path.Combine(_root, ".health.tmp-" + Guid.NewGuid().ToString("N"));
        try
        {
            await File.WriteAllBytesAsync(probePath, [0xA5], cancellationToken);
            File.Delete(probePath);
        }
        finally
        {
            if (File.Exists(probePath)) File.Delete(probePath);
        }
    }

    public async Task<bool> InitializeAsync(CancellationToken cancellationToken = default)
    {
        await CleanupTemporaryFilesAsync(cancellationToken);
        return true;
    }

    internal Task CleanupTemporaryFilesAsync(CancellationToken cancellationToken = default)
    {
        if (!Directory.Exists(_root)) return Task.CompletedTask;
        foreach (var file in Directory.EnumerateFiles(_root, "*.tmp-*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            File.Delete(file);
        }
        return Task.CompletedTask;
    }

    public async Task PutAsync(string secretId, string blobId, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken = default)
    {
        var directory = GetDirectory(secretId);
        Directory.CreateDirectory(directory);
        var target = GetPath(secretId, blobId);
        var temporary = target + ".tmp-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        try
        {
            await File.WriteAllBytesAsync(temporary, contents.ToArray(), cancellationToken);
            File.Move(temporary, target);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public Task<byte[]> ReadAsync(string secretId, string blobId, CancellationToken cancellationToken = default) =>
        File.ReadAllBytesAsync(GetPath(secretId, blobId), cancellationToken);

    public Task DeleteAsync(string secretId, string blobId, CancellationToken cancellationToken = default)
    {
        var path = GetPath(secretId, blobId);
        if (File.Exists(path)) File.Delete(path);
        var directory = GetDirectory(secretId);
        if (Directory.Exists(directory) && !Directory.EnumerateFileSystemEntries(directory).Any()) Directory.Delete(directory);
        return Task.CompletedTask;
    }

    private string GetDirectory(string secretId) => Path.Combine(_root, SafeSegment(secretId));
    private string GetPath(string secretId, string blobId) => Path.Combine(GetDirectory(secretId), SafeSegment(blobId));

    private static string SafeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value is "." or ".." || value.Any(char.IsControl) || value.Contains(Path.DirectorySeparatorChar) || value.Contains(Path.AltDirectorySeparatorChar) || value.Contains(':'))
            throw new ArgumentException("Invalid blob path segment.", nameof(value));
        return value;
    }
}

internal sealed class InMemoryBlobStorage : IBlobStorage, IInfrastructureHealthCheck
{
    private readonly Dictionary<(string SecretId, string BlobId), byte[]> _blobs = new();
    private readonly object _gate = new();

    public Task CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task PutAsync(string secretId, string blobId, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken = default)
    {
        lock (_gate) _blobs[(secretId, blobId)] = contents.ToArray();
        return Task.CompletedTask;
    }

    public Task<byte[]> ReadAsync(string secretId, string blobId, CancellationToken cancellationToken = default)
    {
        lock (_gate) return Task.FromResult(_blobs.TryGetValue((secretId, blobId), out var contents) ? contents : throw new FileNotFoundException());
    }

    public Task DeleteAsync(string secretId, string blobId, CancellationToken cancellationToken = default)
    {
        lock (_gate) _blobs.Remove((secretId, blobId));
        return Task.CompletedTask;
    }
}

internal sealed class InMemorySecretRepository : ISecretRepository, IInfrastructureHealthCheck, IInfrastructureInitializer
{
    private readonly Dictionary<string, StoredSecret> _secrets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, UnlockAttemptState> _unlockAttempts = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly int _maxActive;
    private readonly long _maxBytes;
    private long _bytes;

    private sealed record UnlockAttemptState(int Count, DateTimeOffset WindowStartedAt, DateTimeOffset? BlockedUntil);

    public InMemorySecretRepository(IConfiguration configuration)
    {
        _maxActive = int.TryParse(configuration["Storage:MaxActiveSecrets"], out var active) && active > 0 ? active : 10000;
        _maxBytes = long.TryParse(configuration["Storage:MaxCiphertextBytes"], out var bytes) && bytes > 0 ? bytes : 256L * 1024 * 1024;
    }

    public Task<bool> InitializeAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);

    public Task CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task<StoredSecret?> CreateAsync(StoredSecret secret, Guid? auditRequestId = null, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_secrets.Count >= _maxActive || _bytes + secret.Size > _maxBytes) return Task.FromResult<StoredSecret?>(null);
            _secrets.Add(secret.Id, secret);
            _bytes += secret.Size;
            return Task.FromResult<StoredSecret?>(secret);
        }
    }

    public Task<StoredSecret?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        lock (_gate) return Task.FromResult(_secrets.TryGetValue(id, out var secret) && secret.ExpiresAt > now ? secret : null);
    }

    public Task<StoredSecret?> GetForRevocationAsync(string id, string revokeTokenHash, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_secrets.TryGetValue(id, out var secret) || secret.RevokeTokenHash is null) return Task.FromResult<StoredSecret?>(null);
            var storedHash = System.Text.Encoding.ASCII.GetBytes(secret.RevokeTokenHash);
            var suppliedHash = System.Text.Encoding.ASCII.GetBytes(revokeTokenHash);
            return Task.FromResult<StoredSecret?>(storedHash.Length == suppliedHash.Length && CryptographicOperations.FixedTimeEquals(storedHash, suppliedHash) ? secret : null);
        }
    }

    public Task<UnlockAttemptAdmission> ReserveUnlockAttemptAsync(string id, DateTimeOffset now, int maxAttempts, TimeSpan window, TimeSpan cooldown, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (!_secrets.TryGetValue(id, out var secret) || secret.ExpiresAt <= now)
                return Task.FromResult(new UnlockAttemptAdmission(false, false));

            _unlockAttempts.TryGetValue(id, out var state);
            if (state?.BlockedUntil is { } blockedUntil)
            {
                if (blockedUntil > now) return Task.FromResult(new UnlockAttemptAdmission(true, false, blockedUntil));
                state = null;
            }
            if (state is null || now - state.WindowStartedAt >= window)
                state = new UnlockAttemptState(0, now, null);

            var count = state.Count + 1;
            var next = new UnlockAttemptState(count, state.WindowStartedAt, count >= maxAttempts ? now.Add(cooldown) : null);
            _unlockAttempts[id] = next;
            return Task.FromResult(new UnlockAttemptAdmission(true, true));
        }
    }

    public Task ResetUnlockAttemptsAsync(string id, Guid? auditRequestId = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) _unlockAttempts.Remove(id);
        return Task.CompletedTask;
    }

    public Task<StoredSecret?> RevokeAsync(string id, string revokeTokenHash, Guid? auditRequestId = null, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_secrets.TryGetValue(id, out var secret) || secret.RevokeTokenHash is null ||
                !CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(secret.RevokeTokenHash), System.Text.Encoding.ASCII.GetBytes(revokeTokenHash)))
                return Task.FromResult<StoredSecret?>(null);
            _secrets.Remove(id);
            _bytes -= secret.Size;
            _unlockAttempts.Remove(id);
            return Task.FromResult<StoredSecret?>(secret);
        }
    }

    public Task<IReadOnlyList<StoredSecret>> GetExpiredAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default)
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<StoredSecret>>(_secrets.Values.Where(s => s.ExpiresAt <= now).Take(batchSize).ToArray());
    }

    public Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _unlockAttempts.Remove(id);
            if (_secrets.Remove(id, out var secret)) _bytes -= secret.Size;
        }
        return Task.CompletedTask;
    }
}

internal sealed class PostgresSecretRepository(IConfiguration configuration) : ISecretRepository, IInfrastructureHealthCheck, IInfrastructureInitializer
{
    private readonly string _connectionString = configuration.GetConnectionString("PrivacyLink") ?? throw new InvalidOperationException("ConnectionStrings:PrivacyLink is required.");
    private readonly int _maxActive = int.TryParse(configuration["Storage:MaxActiveSecrets"], out var active) && active > 0 ? active : 10000;
    private readonly long _maxBytes = long.TryParse(configuration["Storage:MaxCiphertextBytes"], out var bytes) && bytes > 0 ? bytes : 256L * 1024 * 1024;

    public async Task CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT 1", connection) { CommandTimeout = 2 };
        await command.ExecuteScalarAsync(cancellationToken);
    }

    public async Task<bool> InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await using (var lockCommand = new NpgsqlCommand("SELECT pg_advisory_xact_lock(738292)", connection, transaction))
            await lockCommand.ExecuteNonQueryAsync(cancellationToken);
        await using (var migrationsCommand = new NpgsqlCommand("CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL)", connection, transaction))
            await migrationsCommand.ExecuteNonQueryAsync(cancellationToken);

        var applied = new HashSet<int>();
        await using (var appliedCommand = new NpgsqlCommand("SELECT version FROM schema_migrations", connection, transaction))
        await using (var reader = await appliedCommand.ExecuteReaderAsync(cancellationToken))
            while (await reader.ReadAsync(cancellationToken)) applied.Add(reader.GetInt32(0));

        var migrations = new Dictionary<int, string>
        {
            [1] = """
                CREATE TABLE IF NOT EXISTS secrets (
                    id text PRIMARY KEY,
                    expires_at timestamptz NOT NULL,
                    protocol_version integer NOT NULL,
                    nonce text,
                    blob_id text,
                    ciphertext_size bigint NOT NULL,
                    files_json text NOT NULL DEFAULT '[]'
                )
                """,
            [2] = """
                ALTER TABLE secrets ALTER COLUMN nonce DROP NOT NULL;
                ALTER TABLE secrets ALTER COLUMN blob_id DROP NOT NULL;
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS password_salt text;
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS message_outer_nonce text;
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS files_json text NOT NULL DEFAULT '[]';
                CREATE INDEX IF NOT EXISTS ix_secrets_expires_at ON secrets (expires_at);
                """,
            [3] = """
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS revoke_token_hash text;
                """,
            [4] = """
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS unlock_attempt_count integer NOT NULL DEFAULT 0;
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS unlock_attempt_window_started_at timestamptz;
                ALTER TABLE secrets ADD COLUMN IF NOT EXISTS unlock_blocked_until timestamptz;
                """,
            [5] = """
                CREATE TABLE IF NOT EXISTS stats_daily (
                    day date NOT NULL,
                    metric text NOT NULL,
                    dimension text NOT NULL DEFAULT '',
                    dimension_value text NOT NULL DEFAULT '',
                    count bigint NOT NULL DEFAULT 0,
                    bytes bigint NOT NULL DEFAULT 0,
                    PRIMARY KEY (day, metric, dimension, dimension_value),
                    CHECK (metric IN ('creations','creation_content_type','creation_password_protected','creation_expiry','secret_open','unlock','file_retrieval','files','errors','unique_ips')),
                    CHECK (metric <> 'creation_content_type' OR (dimension='content_type' AND dimension_value IN ('text','files','both'))),
                    CHECK (metric <> 'creation_password_protected' OR (dimension='password_protected' AND dimension_value IN ('true','false'))),
                    CHECK (metric <> 'creation_expiry' OR (dimension='expiry' AND dimension_value IN ('1d','7d','14d'))),
                    CHECK (metric <> 'errors' OR (dimension='category' AND dimension_value IN ('validation','rate_limit','capacity','server_error'))),
                    CHECK (count >= 0 AND bytes >= 0)
                );
                CREATE TABLE IF NOT EXISTS stats_visitors_daily (
                    day date NOT NULL,
                    visitor_hmac bytea NOT NULL,
                    PRIMARY KEY (day, visitor_hmac)
                );
                """,
            [6] = """
                DROP TABLE IF EXISTS stats_visitors_daily;
                DROP TABLE IF EXISTS stats_daily;
                """,
            [7] = """
                CREATE TABLE secret_request_audit (
                    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    request_id uuid NOT NULL UNIQUE,
                    trace_id text NOT NULL,
                    secret_id text NOT NULL CHECK (secret_id ~ '^[A-Za-z0-9_-]{22}$'),
                    secret_id_source text NOT NULL CHECK (secret_id_source IN ('route','reserved')),
                    requested_secret_id text CHECK (requested_secret_id IS NULL OR length(requested_secret_id) <= 256),
                    action text NOT NULL CHECK (action IN ('create','metadata','open','unlock','file_open','revoke','secret_page','secret_request')),
                    http_method text NOT NULL CHECK (length(http_method) > 0),
                    route_template text NOT NULL CHECK (length(route_template) BETWEEN 1 AND 128),
                    started_at timestamptz NOT NULL,
                    completed_at timestamptz,
                    duration_ms bigint CHECK (duration_ms IS NULL OR duration_ms >= 0),
                    state text NOT NULL CHECK (state IN ('started','completed','aborted')),
                    outcome text,
                    http_status smallint CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
                    error_code text CHECK (error_code IS NULL OR length(error_code) <= 64),
                    client_ip inet,
                    file_id text,
                    CHECK (
                        (state='started' AND completed_at IS NULL AND duration_ms IS NULL AND outcome IS NULL AND http_status IS NULL AND error_code IS NULL)
                        OR (state='completed' AND completed_at IS NOT NULL AND duration_ms IS NOT NULL AND outcome IS NOT NULL AND outcome IN ('success','rejected','error'))
                        OR (state='aborted' AND completed_at IS NOT NULL AND duration_ms IS NOT NULL AND outcome IS NOT NULL AND outcome='aborted')
                    )
                );
                CREATE INDEX ix_secret_request_audit_secret_started ON secret_request_audit (secret_id, started_at, id);
                CREATE INDEX ix_secret_request_audit_started ON secret_request_audit (started_at, id);
                """
        };
        foreach (var (version, sql) in migrations.OrderBy(pair => pair.Key))
        {
            if (applied.Contains(version)) continue;
            await using var migration = new NpgsqlCommand(sql, connection, transaction);
            await migration.ExecuteNonQueryAsync(cancellationToken);
            await using var record = new NpgsqlCommand("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, NOW())", connection, transaction);
            record.Parameters.AddWithValue(version);
            await record.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async Task<StoredSecret?> CreateAsync(StoredSecret secret, Guid? auditRequestId = null, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using (var lockCommand = new NpgsqlCommand("SELECT pg_advisory_xact_lock(738291)", connection, transaction))
            await lockCommand.ExecuteNonQueryAsync(cancellationToken);
        await using var capacityCommand = new NpgsqlCommand("SELECT COUNT(*), COALESCE(SUM(ciphertext_size), 0) FROM secrets WHERE expires_at > NOW()", connection, transaction);
        await using var capacity = await capacityCommand.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        await capacity.ReadAsync(cancellationToken);
        var activeCount = capacity.GetInt64(0);
        var activeBytes = capacity.GetInt64(1);
        await capacity.DisposeAsync();
        if (activeCount >= _maxActive || activeBytes + secret.Size > _maxBytes)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        await using var command = new NpgsqlCommand("INSERT INTO secrets (id, expires_at, protocol_version, nonce, blob_id, password_salt, message_outer_nonce, ciphertext_size, files_json, revoke_token_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING", connection, transaction);
        command.Parameters.AddWithValue(secret.Id);
        command.Parameters.AddWithValue(secret.ExpiresAt.UtcDateTime);
        command.Parameters.AddWithValue(1);
        command.Parameters.AddWithValue((object?)secret.MessageNonce ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)secret.MessageBlobId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)secret.PasswordSalt ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)secret.MessageOuterNonce ?? DBNull.Value);
        command.Parameters.AddWithValue(secret.Size);
        command.Parameters.AddWithValue(System.Text.Json.JsonSerializer.Serialize(secret.Files, InfrastructureJsonContext.Default.IReadOnlyListStoredFile));
        command.Parameters.AddWithValue((object?)secret.RevokeTokenHash ?? DBNull.Value);
        var created = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (created && auditRequestId is { } requestId)
            await FinishAuditInTransactionAsync(connection, transaction, requestId, 201, "success", null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return created ? secret : null;
    }

    public async Task<StoredSecret?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT id, expires_at, protocol_version, nonce, blob_id, password_salt, message_outer_nonce, ciphertext_size, files_json FROM secrets WHERE id = $1 AND expires_at > $2", connection);
        command.Parameters.AddWithValue(id);
        command.Parameters.AddWithValue(now.UtcDateTime);
        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public async Task<StoredSecret?> GetForRevocationAsync(string id, string revokeTokenHash, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT id, expires_at, protocol_version, nonce, blob_id, password_salt, message_outer_nonce, ciphertext_size, files_json, revoke_token_hash FROM secrets WHERE id = $1 AND revoke_token_hash = $2", connection);
        command.Parameters.AddWithValue(id);
        command.Parameters.AddWithValue(revokeTokenHash);
        await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public async Task<UnlockAttemptAdmission> ReserveUnlockAttemptAsync(string id, DateTimeOffset now, int maxAttempts, TimeSpan window, TimeSpan cooldown, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        int count;
        DateTimeOffset? windowStartedAt;
        DateTimeOffset? blockedUntil;
        await using (var command = new NpgsqlCommand("SELECT unlock_attempt_count, unlock_attempt_window_started_at, unlock_blocked_until FROM secrets WHERE id = $1 AND expires_at > $2 FOR UPDATE", connection, transaction))
        {
            command.Parameters.AddWithValue(id);
            command.Parameters.AddWithValue(now.UtcDateTime);
            await using var reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                await transaction.RollbackAsync(cancellationToken);
                return new UnlockAttemptAdmission(false, false);
            }
            count = reader.GetInt32(0);
            windowStartedAt = reader.IsDBNull(1) ? null : new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero);
            blockedUntil = reader.IsDBNull(2) ? null : new DateTimeOffset(reader.GetDateTime(2), TimeSpan.Zero);
        }

        if (blockedUntil > now)
        {
            await transaction.CommitAsync(cancellationToken);
            return new UnlockAttemptAdmission(true, false, blockedUntil);
        }
        if (blockedUntil is not null || windowStartedAt is null || now - windowStartedAt.Value >= window)
        {
            count = 0;
            windowStartedAt = now;
        }

        count++;
        blockedUntil = count >= maxAttempts ? now.Add(cooldown) : null;
        await using (var update = new NpgsqlCommand("UPDATE secrets SET unlock_attempt_count = $2, unlock_attempt_window_started_at = $3, unlock_blocked_until = $4 WHERE id = $1", connection, transaction))
        {
            update.Parameters.AddWithValue(id);
            update.Parameters.AddWithValue(count);
            update.Parameters.AddWithValue(windowStartedAt.Value.UtcDateTime);
            update.Parameters.AddWithValue((object?)blockedUntil?.UtcDateTime ?? DBNull.Value);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new UnlockAttemptAdmission(true, true);
    }

    public async Task ResetUnlockAttemptsAsync(string id, Guid? auditRequestId = null, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using var command = new NpgsqlCommand("UPDATE secrets SET unlock_attempt_count = 0, unlock_attempt_window_started_at = NULL, unlock_blocked_until = NULL WHERE id = $1", connection, transaction);
        command.Parameters.AddWithValue(id);
        var updated = await command.ExecuteNonQueryAsync(cancellationToken);
        if (auditRequestId is not null && updated != 1) throw new FileNotFoundException();
        if (auditRequestId is { } requestId)
            await FinishAuditInTransactionAsync(connection, transaction, requestId, 200, "success", null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<StoredSecret?> RevokeAsync(string id, string revokeTokenHash, Guid? auditRequestId = null, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        StoredSecret? secret;
        await using (var select = new NpgsqlCommand("SELECT id, expires_at, protocol_version, nonce, blob_id, password_salt, message_outer_nonce, ciphertext_size, files_json, revoke_token_hash FROM secrets WHERE id=$1 AND revoke_token_hash=$2 FOR UPDATE", connection, transaction))
        {
            select.Parameters.AddWithValue(id);
            select.Parameters.AddWithValue(revokeTokenHash);
            await using var reader = await select.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken);
            secret = await reader.ReadAsync(cancellationToken) ? Read(reader) with { RevokeTokenHash = reader.GetString(9) } : null;
        }
        if (secret is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }
        await using (var delete = new NpgsqlCommand("DELETE FROM secrets WHERE id=$1", connection, transaction))
        {
            delete.Parameters.AddWithValue(id);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        if (auditRequestId is { } requestId)
            await FinishAuditInTransactionAsync(connection, transaction, requestId, 204, "success", null, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return secret;
    }

    private static async Task FinishAuditInTransactionAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Guid requestId, int status, string outcome, string? errorCode, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("UPDATE secret_request_audit SET completed_at=NOW(), duration_ms=GREATEST(0, (EXTRACT(EPOCH FROM (NOW()-started_at))*1000)::bigint), state='completed', outcome=$2, http_status=$3, error_code=$4 WHERE request_id=$1 AND state='started'", connection, transaction);
        command.Parameters.AddWithValue(requestId);
        command.Parameters.AddWithValue(outcome);
        command.Parameters.AddWithValue(status);
        command.Parameters.AddWithValue((object?)errorCode ?? DBNull.Value);
        try
        {
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidOperationException("Audit request was not in the started state.");
        }
        catch (Exception ex) when (ex is not SecretAuditUnavailableException)
        {
            throw new SecretAuditUnavailableException(ex);
        }
    }

    public async Task<IReadOnlyList<StoredSecret>> GetExpiredAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default)
    {
        var result = new List<StoredSecret>();
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT id, expires_at, protocol_version, nonce, blob_id, password_salt, message_outer_nonce, ciphertext_size, files_json FROM secrets WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2", connection);
        command.Parameters.AddWithValue(now.UtcDateTime);
        command.Parameters.AddWithValue(batchSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) result.Add(Read(reader));
        return result;
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("DELETE FROM secrets WHERE id = $1", connection);
        command.Parameters.AddWithValue(id);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static StoredSecret Read(NpgsqlDataReader reader) => new(
        reader.GetString(0),
        new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero),
        reader.IsDBNull(3) ? null : reader.GetString(3),
        reader.IsDBNull(4) ? null : reader.GetString(4),
        reader.GetInt64(7),
        System.Text.Json.JsonSerializer.Deserialize(reader.GetString(8), InfrastructureJsonContext.Default.ListStoredFile) ?? [],
        reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetString(6));
}

internal sealed class StorageHealth(IEnumerable<IInfrastructureHealthCheck> healthChecks) : IStorageReadiness
{
    private volatile bool _ready;
    public bool IsReady => _ready;
    public void MarkReady() => _ready = true;

    public async Task<bool> CheckReadinessAsync(CancellationToken requestCancellation)
    {
        if (!IsReady) return false;

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(requestCancellation, timeout.Token);
        try
        {
            await Task.WhenAll(healthChecks.Select(check => check.CheckHealthAsync(linked.Token)));
            return true;
        }
        catch (OperationCanceledException) when (requestCancellation.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }
}

internal sealed class StorageInitializer(IEnumerable<IInfrastructureInitializer> initializers, StorageHealth health, ILogger<StorageInitializer> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (var initializer in initializers)
                await initializer.InitializeAsync(cancellationToken);
            health.MarkReady();
        }
        catch (Exception ex) { logger.LogError(ex, "Persistent storage initialization failed"); throw; }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal sealed class ExpiredSecretCleanup(ISecretRepository repository, IBlobStorage blobs, TimeProvider clock, IConfiguration configuration, ILogger<ExpiredSecretCleanup> logger) : BackgroundService
{
    private readonly TimeSpan _interval = TimeSpan.FromMinutes(int.TryParse(configuration["Storage:CleanupIntervalMinutes"], out var minutes) && minutes > 0 ? minutes : 15);
    private readonly int _batchSize = int.TryParse(configuration["Storage:CleanupBatchSize"], out var batch) && batch > 0 ? batch : 100;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_interval, clock);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                foreach (var secret in await repository.GetExpiredAsync(clock.GetUtcNow(), _batchSize, stoppingToken))
                {
                    if (secret.MessageBlobId is not null) await blobs.DeleteAsync(secret.Id, secret.MessageBlobId, stoppingToken);
                    foreach (var file in secret.Files) await blobs.DeleteAsync(secret.Id, file.BlobId, stoppingToken);
                    await repository.DeleteAsync(secret.Id, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception ex) { logger.LogError(ex, "Expired secret cleanup failed"); }
        }
    }
}
