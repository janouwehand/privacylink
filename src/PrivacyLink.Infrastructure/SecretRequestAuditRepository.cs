using Npgsql;
using NpgsqlTypes;
using Microsoft.Extensions.Configuration;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

internal sealed class PostgresSecretRequestAuditWriter(IConfiguration configuration) : ISecretRequestAuditWriter, ISecretRequestAuditReader
{
    private readonly string _connectionString = configuration.GetConnectionString("PrivacyLink") ?? throw new InvalidOperationException("ConnectionStrings:PrivacyLink is required.");

    public async Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default)
    {
        var clientIp = audit.ClientIp is { IsIPv4MappedToIPv6: true } mappedIp ? mappedIp.MapToIPv4() : audit.ClientIp;
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
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Inet, Value = (object?)clientIp ?? DBNull.Value });
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

    public async Task<SecretRequestAuditPage> ListAsync(SecretRequestAuditQuery query, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var sortColumn = query.SortBy switch
        {
            "time" => "started_at",
            "action" => "action",
            "secretId" => "secret_id",
            "clientIp" => "client_ip",
            "outcome" => "outcome",
            "httpStatus" => "http_status",
            "request" => "route_template",
            _ => "started_at"
        };
        var direction = query.Descending ? "DESC" : "ASC";
        var filterIp = query.ClientIp is null ? null : System.Net.IPAddress.Parse(query.ClientIp);
        var mappedFilterIp = filterIp is { } ip && ip.GetAddressBytes().Length == 4 ? ip.MapToIPv6() : null;
        const string filter = "($1::text IS NULL OR POSITION($1 IN secret_id) > 0) AND ($2::inet IS NULL OR client_ip = $2::inet OR client_ip = $3::inet)";
        await using var countCommand = new NpgsqlCommand($"SELECT COUNT(*) FROM secret_request_audit WHERE {filter}", connection);
        countCommand.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Text, Value = (object?)query.SecretId ?? DBNull.Value });
        countCommand.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Inet, Value = (object?)filterIp ?? DBNull.Value });
        countCommand.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Inet, Value = (object?)mappedFilterIp ?? DBNull.Value });
        var totalCount = (long)(await countCommand.ExecuteScalarAsync(cancellationToken) ?? 0L);

        await using var command = new NpgsqlCommand($"SELECT id, request_id, trace_id, secret_id, secret_id_source, requested_secret_id, action, http_method, route_template, started_at, completed_at, duration_ms, state, outcome, http_status, error_code, client_ip, file_id FROM secret_request_audit WHERE {filter} ORDER BY {sortColumn} {direction} NULLS LAST, id DESC LIMIT $4 OFFSET $5", connection);
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Text, Value = (object?)query.SecretId ?? DBNull.Value });
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Inet, Value = (object?)filterIp ?? DBNull.Value });
        command.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Inet, Value = (object?)mappedFilterIp ?? DBNull.Value });
        command.Parameters.AddWithValue(query.PageSize);
        command.Parameters.AddWithValue(checked((query.Page - 1) * query.PageSize));
        var records = new List<SecretRequestAuditRecord>(query.PageSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var startedAt = new DateTimeOffset(reader.GetDateTime(9));
            records.Add(new SecretRequestAuditRecord(
                reader.GetInt64(0), reader.GetGuid(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetString(8),
                startedAt, reader.IsDBNull(10) ? null : new DateTimeOffset(reader.GetDateTime(10)),
                reader.IsDBNull(11) ? null : reader.GetInt64(11), reader.GetString(12),
                reader.IsDBNull(13) ? null : reader.GetString(13), reader.IsDBNull(14) ? null : reader.GetInt16(14),
                reader.IsDBNull(15) ? null : reader.GetString(15), reader.IsDBNull(16) ? null : reader.GetFieldValue<System.Net.IPAddress>(16),
                reader.IsDBNull(17) ? null : reader.GetString(17)));
        }
        return new SecretRequestAuditPage(records, totalCount);
    }
}

internal sealed class InMemorySecretRequestAuditWriter : ISecretRequestAuditWriter, ISecretRequestAuditReader
{
    private readonly Dictionary<Guid, (long Id, SecretRequestAuditStart Start, SecretRequestAuditFinish? Finish)> _rows = new();
    private readonly object _gate = new();
    private long _nextId;
    public Task StartAsync(SecretRequestAuditStart audit, CancellationToken cancellationToken = default)
    {
        var clientIp = audit.ClientIp is { IsIPv4MappedToIPv6: true } mappedIp ? mappedIp.MapToIPv4() : audit.ClientIp;
        lock (_gate) _rows.Add(audit.RequestId, (++_nextId, audit with { ClientIp = clientIp }, null));
        return Task.CompletedTask;
    }
    public Task FinishAsync(Guid requestId, SecretRequestAuditFinish finish, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_rows.TryGetValue(requestId, out var row)) throw new InvalidOperationException("Audit request was not started.");
            if (row.Finish is null) _rows[requestId] = (row.Id, row.Start, finish);
        }
        return Task.CompletedTask;
    }

    internal IReadOnlyList<(SecretRequestAuditStart Start, SecretRequestAuditFinish? Finish)> Snapshot()
    {
        lock (_gate) return _rows.Values.Select(row => (row.Start, row.Finish)).ToArray();
    }

    public Task<SecretRequestAuditPage> ListAsync(SecretRequestAuditQuery query, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var rows = _rows.Values.Select(row => new SecretRequestAuditRecord(row.Id, row.Start.RequestId, row.Start.TraceId, row.Start.SecretId,
                    row.Start.SecretIdSource, row.Start.RequestedSecretId, row.Start.Action, row.Start.HttpMethod, row.Start.RouteTemplate,
                    row.Start.StartedAt, row.Finish?.CompletedAt, row.Finish?.DurationMs, row.Finish?.State ?? "started",
                    row.Finish?.Outcome, row.Finish?.HttpStatus, row.Finish?.ErrorCode, row.Start.ClientIp, row.Start.FileId))
                .Where(record => string.IsNullOrEmpty(query.SecretId) || record.SecretId.Contains(query.SecretId, StringComparison.Ordinal))
                .Where(record => query.ClientIp is null || record.ClientIp?.ToString() == query.ClientIp)
                .ToList();
            var totalCount = rows.Count;
        IOrderedEnumerable<SecretRequestAuditRecord> ordered = query.SortBy switch
            {
            "action" => query.Descending ? rows.OrderByDescending(record => record.Action, StringComparer.Ordinal) : rows.OrderBy(record => record.Action, StringComparer.Ordinal),
            "secretId" => query.Descending ? rows.OrderByDescending(record => record.SecretId, StringComparer.Ordinal) : rows.OrderBy(record => record.SecretId, StringComparer.Ordinal),
            "clientIp" => query.Descending ? rows.OrderBy(record => record.ClientIp is null).ThenByDescending(record => record.ClientIp, AuditIpComparer.Instance) : rows.OrderBy(record => record.ClientIp is null).ThenBy(record => record.ClientIp, AuditIpComparer.Instance),
            "outcome" => query.Descending ? rows.OrderBy(record => record.Outcome is null).ThenByDescending(record => record.Outcome, StringComparer.Ordinal) : rows.OrderBy(record => record.Outcome is null).ThenBy(record => record.Outcome, StringComparer.Ordinal),
            "httpStatus" => query.Descending ? rows.OrderBy(record => record.HttpStatus is null).ThenByDescending(record => record.HttpStatus) : rows.OrderBy(record => record.HttpStatus is null).ThenBy(record => record.HttpStatus),
            "request" => query.Descending ? rows.OrderByDescending(record => record.RouteTemplate, StringComparer.Ordinal) : rows.OrderBy(record => record.RouteTemplate, StringComparer.Ordinal),
                _ => query.Descending ? rows.OrderByDescending(record => record.StartedAt) : rows.OrderBy(record => record.StartedAt)
            };
            var page = ordered.ThenByDescending(record => record.Id).Skip((query.Page - 1) * query.PageSize).Take(query.PageSize).ToArray();
            return Task.FromResult(new SecretRequestAuditPage(page, totalCount));
        }
    }
}

internal sealed class AuditIpComparer : IComparer<System.Net.IPAddress?>
{
    public static readonly AuditIpComparer Instance = new();

    public int Compare(System.Net.IPAddress? left, System.Net.IPAddress? right)
    {
        if (ReferenceEquals(left, right)) return 0;
        if (left is null) return 1;
        if (right is null) return -1;
        if (left.IsIPv4MappedToIPv6) left = left.MapToIPv4();
        if (right.IsIPv4MappedToIPv6) right = right.MapToIPv4();
        var leftBytes = left.GetAddressBytes();
        var rightBytes = right.GetAddressBytes();
        var familyOrder = leftBytes.Length.CompareTo(rightBytes.Length);
        if (familyOrder != 0) return familyOrder;
        for (var index = 0; index < leftBytes.Length; index++)
        {
            var comparison = leftBytes[index].CompareTo(rightBytes[index]);
            if (comparison != 0) return comparison;
        }
        return 0;
    }
}
