using Npgsql;
using NpgsqlTypes;
using Microsoft.Extensions.Configuration;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

internal sealed class PostgresSecretRequestAuditWriter(IConfiguration configuration) : ISecretRequestAuditWriter
{
    private readonly string _connectionString = configuration.GetConnectionString("PrivacyLink") ?? throw new InvalidOperationException("ConnectionStrings:PrivacyLink is required.");

    public async Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("INSERT INTO secret_request_audit (request_id, trace_id, secret_id, secret_id_source, requested_secret_id, action, http_method, route_template, started_at, state, client_ip, file_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'started',$10,$11)", connection);
        command.Parameters.AddWithValue(audit.RequestId);
        command.Parameters.AddWithValue(audit.TraceId);
        command.Parameters.AddWithValue(audit.SecretId);
        command.Parameters.AddWithValue(audit.SecretIdSource);
        command.Parameters.AddWithValue((object?)audit.RequestedSecretId ?? DBNull.Value);
        command.Parameters.AddWithValue(audit.Action);
        command.Parameters.AddWithValue(audit.HttpMethod);
        command.Parameters.AddWithValue(audit.RouteTemplate);
        command.Parameters.AddWithValue(audit.StartedAt.UtcDateTime);
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Inet, Value = (object?)audit.ClientIp ?? DBNull.Value });
        command.Parameters.AddWithValue((object?)audit.FileId ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("UPDATE secret_request_audit SET completed_at=$2, duration_ms=$3, state=$4, outcome=$5, http_status=$6, error_code=$7 WHERE request_id=$1 AND state='started'", connection);
        command.Parameters.AddWithValue(requestId);
        command.Parameters.AddWithValue(finish.CompletedAt.UtcDateTime);
        command.Parameters.AddWithValue(finish.DurationMs);
        command.Parameters.AddWithValue(finish.State);
        command.Parameters.AddWithValue((object?)finish.Outcome ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)finish.HttpStatus ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)finish.ErrorCode ?? DBNull.Value);
        if (await command.ExecuteNonQueryAsync(cancellationToken) == 1) return;
        await using var check = new NpgsqlCommand("SELECT state FROM secret_request_audit WHERE request_id=$1", connection);
        check.Parameters.AddWithValue(requestId);
        if (await check.ExecuteScalarAsync(cancellationToken) is not string state || state == "started")
            throw new InvalidOperationException("Audit request was not in the started state.");
    }
}

internal sealed class InMemorySecretRequestAuditWriter : ISecretRequestAuditWriter
{
    private readonly Dictionary<Guid, (SecretRequestAuditStart Start, SecretRequestAuditFinish? Finish)> _rows = new();
    private readonly object _gate = new();
    public Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default)
    {
        lock (_gate) _rows.Add(audit.RequestId, (audit, null));
        return Task.CompletedTask;
    }
    public Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_rows.TryGetValue(requestId, out var row)) throw new InvalidOperationException("Audit request was not started.");
            if (row.Finish is null) _rows[requestId] = (row.Start, finish);
        }
        return Task.CompletedTask;
    }

    internal IReadOnlyList<(SecretRequestAuditStart Start, SecretRequestAuditFinish? Finish)> Snapshot()
    {
        lock (_gate) return _rows.Values.ToArray();
    }
}
