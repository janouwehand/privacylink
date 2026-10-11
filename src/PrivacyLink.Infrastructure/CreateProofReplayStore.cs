using System.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

internal sealed class UnavailableCreateProofReplayStore : ICreateProofReplayStore
{
    public Task<CreateProofConsumeResult> TryConsumeAsync(string challengeId, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(CreateProofConsumeResult.Full);
    }
}

internal sealed class PostgresCreateProofReplayStore(IConfiguration configuration) : ICreateProofReplayStore
{
    private readonly string _connectionString = configuration.GetConnectionString("PrivacyLink") ?? throw new InvalidOperationException("ConnectionStrings:PrivacyLink is required.");

    public async Task<CreateProofConsumeResult> TryConsumeAsync(string challengeId, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using (var lockCommand = new NpgsqlCommand("SELECT pg_advisory_xact_lock(738293)", connection, transaction))
            await lockCommand.ExecuteNonQueryAsync(cancellationToken);
        await using (var cleanup = new NpgsqlCommand("DELETE FROM create_proof_replays WHERE expires_at <= $1", connection, transaction))
        {
            cleanup.Parameters.AddWithValue(now);
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var duplicate = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM create_proof_replays WHERE challenge_id = $1)", connection, transaction))
        {
            duplicate.Parameters.AddWithValue(challengeId);
            if ((bool)(await duplicate.ExecuteScalarAsync(cancellationToken) ?? false))
            {
                await transaction.CommitAsync(cancellationToken);
                return CreateProofConsumeResult.Replay;
            }
        }
        await using (var count = new NpgsqlCommand("SELECT COUNT(*) FROM create_proof_replays", connection, transaction))
        {
            if (Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture) >= 10_000)
            {
                await transaction.CommitAsync(cancellationToken);
                return CreateProofConsumeResult.Full;
            }
        }
        await using (var insert = new NpgsqlCommand("INSERT INTO create_proof_replays (challenge_id, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", connection, transaction))
        {
            insert.Parameters.AddWithValue(challengeId);
            insert.Parameters.AddWithValue(expiresAt);
            if (await insert.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                await transaction.CommitAsync(cancellationToken);
                return CreateProofConsumeResult.Replay;
            }
        }
        await transaction.CommitAsync(cancellationToken);
        return CreateProofConsumeResult.Consumed;
    }
}

internal sealed class CreateProofReplayCleanupService(IConfiguration configuration, ILogger<CreateProofReplayCleanupService> logger) : BackgroundService
{
    private readonly string _connectionString = configuration.GetConnectionString("PrivacyLink") ?? throw new InvalidOperationException("ConnectionStrings:PrivacyLink is required.");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var connection = new NpgsqlConnection(_connectionString);
                await connection.OpenAsync(stoppingToken);
                await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, stoppingToken);
                await using (var lockCommand = new NpgsqlCommand("SELECT pg_advisory_xact_lock(738293)", connection, transaction))
                    await lockCommand.ExecuteNonQueryAsync(stoppingToken);
                await using (var delete = new NpgsqlCommand("DELETE FROM create_proof_replays WHERE expires_at <= NOW()", connection, transaction))
                    await delete.ExecuteNonQueryAsync(stoppingToken);
                await transaction.CommitAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception exception) { logger.LogWarning(exception, "Expired create proof replay cleanup failed"); }
        }
    }
}
