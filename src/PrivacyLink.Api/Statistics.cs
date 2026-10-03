using System.Net;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using PrivacyLink.Contracts;

namespace PrivacyLink.Api;

internal sealed record StatisticsEvent(string Metric, string Dimension = "", string Value = "", long Count = 1, long Bytes = 0, byte[]? VisitorHash = null, DateOnly? Day = null);
internal sealed class StatisticsDayFinalizedException : Exception { }

internal sealed class StatisticsRecorder(IConfiguration configuration, TimeProvider clock, ILogger<StatisticsRecorder> logger)
{
    internal const int FinalizationLockId = 738293;
    private readonly string? _connectionString = configuration.GetConnectionString("PrivacyLink");

    public StatisticsEvent Event(HttpContext context, string metric, string dimension = "", string value = "", long bytes = 0)
    {
        var day = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
        byte[]? visitorHash = null;
        var keyText = configuration["Analytics:Key"];
        if (!string.IsNullOrWhiteSpace(keyText) &&
            TryKey(keyText, out var key) && !KeyEquals(keyText, configuration["Security:PasswordPepper"]) &&
            !KeyEquals(keyText, configuration["Security:AuditHashKey"]) && Normalize(context.Connection.RemoteIpAddress) is { } ip)
            visitorHash = VisitorToken(key, ip);
        return new StatisticsEvent(metric, dimension, value, 1, bytes, visitorHash, day);
    }

    public async Task RecordAsync(StatisticsEvent entry, CancellationToken cancellationToken = default)
    {
        if (_connectionString is null) return;
        try
        {
            await using var connection = new NpgsqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
            await RecordAsync(connection, transaction, entry, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception) { logger.LogWarning(exception, "Could not record a product statistic"); }
    }

    public async Task<DailyStatisticResponse[]> GetDailyStatisticsAsync(CancellationToken cancellationToken = default)
    {
        if (_connectionString is null) return [];
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT day, metric, dimension, dimension_value, count, bytes
            FROM stats_daily
            WHERE (metric IN ('creations','secret_open','unlock','file_retrieval','files','unique_ips') AND dimension='' AND dimension_value='')
               OR (metric='creation_content_type' AND dimension='content_type' AND dimension_value IN ('text','files','both'))
               OR (metric='creation_password_protected' AND dimension='password_protected' AND dimension_value IN ('true','false'))
               OR (metric='creation_expiry' AND dimension='expiry' AND dimension_value IN ('1d','7d','14d'))
               OR (metric='errors' AND dimension='category' AND dimension_value IN ('validation','rate_limit','capacity','server_error'))
            UNION ALL
            SELECT $1::date, 'unique_ips', '', '', COUNT(*), 0::bigint
            FROM stats_visitors_daily
            WHERE day=$1
              AND NOT EXISTS (SELECT 1 FROM stats_daily WHERE day=$1 AND metric='unique_ips' AND dimension='' AND dimension_value='')
            ORDER BY day DESC, metric, dimension, dimension_value
            """, connection);
        command.Parameters.AddWithValue(DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<DailyStatisticResponse>();
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = new DailyStatisticResponse(reader.GetFieldValue<DateOnly>(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4), reader.GetInt64(5));
            if (IsPublicStatistic(row)) rows.Add(row);
        }
        return rows.ToArray();
    }

    internal static bool IsPublicStatistic(DailyStatisticResponse row) => row.Metric switch
    {
        "creations" or "secret_open" or "unlock" or "file_retrieval" or "files" or "unique_ips" => row.Dimension == "" && row.DimensionValue == "",
        "creation_content_type" => row.Dimension == "content_type" && row.DimensionValue is "text" or "files" or "both",
        "creation_password_protected" => row.Dimension == "password_protected" && row.DimensionValue is "true" or "false",
        "creation_expiry" => row.Dimension == "expiry" && row.DimensionValue is "1d" or "7d" or "14d",
        "errors" => row.Dimension == "category" && row.DimensionValue is "validation" or "rate_limit" or "capacity" or "server_error",
        _ => false
    };

    internal static async Task RecordAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, StatisticsEvent entry, CancellationToken cancellationToken)
    {
        await RecordBatchAsync(connection, transaction, [entry], cancellationToken);
    }

    internal static async Task RecordBatchAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, IReadOnlyList<StatisticsEvent> entries, CancellationToken cancellationToken)
    {
        if (entries.Count == 0) return;
        var day = entries[0].Day ?? DateOnly.FromDateTime(DateTime.UtcNow);
        if (entries.Any(entry => entry.Day is { } entryDay && entryDay != day))
            throw new InvalidOperationException("Statistics events in one transaction must share a UTC day.");

        if (!await AcquireDayWriteLockAsync(connection, transaction, day, cancellationToken)) return;

        foreach (var entry in entries)
            await RecordUnlockedAsync(connection, transaction, entry, day, cancellationToken);
    }

    internal static async Task<bool> AcquireDayWriteLockAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, DateOnly day, CancellationToken cancellationToken)
    {
        // Share the finalization lock so closing a UTC day waits for active writers,
        // then holds off any writer until the unique-IP marker has been committed.
        await using (var lockCommand = new NpgsqlCommand($"SELECT pg_advisory_xact_lock_shared({FinalizationLockId})", connection, transaction))
            await lockCommand.ExecuteNonQueryAsync(cancellationToken);
        await using (var finalizedCommand = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM stats_daily WHERE day=$1 AND metric='unique_ips')", connection, transaction))
        {
            finalizedCommand.Parameters.AddWithValue(day);
            return !((bool)(await finalizedCommand.ExecuteScalarAsync(cancellationToken) ?? false));
        }
    }

    internal static byte[] VisitorToken(byte[] key, string normalizedAddress) =>
        HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(normalizedAddress));

    private static async Task RecordUnlockedAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, StatisticsEvent entry, DateOnly day, CancellationToken cancellationToken)
    {
        await using (var command = new NpgsqlCommand("INSERT INTO stats_daily (day, metric, dimension, dimension_value, count, bytes) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (day, metric, dimension, dimension_value) DO UPDATE SET count=stats_daily.count+EXCLUDED.count, bytes=stats_daily.bytes+EXCLUDED.bytes", connection, transaction))
        {
            command.Parameters.AddWithValue(day);
            command.Parameters.AddWithValue(entry.Metric);
            command.Parameters.AddWithValue(entry.Dimension);
            command.Parameters.AddWithValue(entry.Value);
            command.Parameters.AddWithValue(entry.Count);
            command.Parameters.AddWithValue(entry.Bytes);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        if (entry.VisitorHash is not null)
            await using (var command = new NpgsqlCommand("INSERT INTO stats_visitors_daily (day, visitor_hmac) VALUES ($1,$2) ON CONFLICT DO NOTHING", connection, transaction))
            {
                command.Parameters.AddWithValue(day);
                command.Parameters.AddWithValue(entry.VisitorHash);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
    }

    internal static string? Normalize(IPAddress? address)
    {
        if (address is null) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.ToString().ToLowerInvariant();
    }

    internal static bool TryKey(string text, out byte[] key)
    {
        try { key = Convert.FromBase64String(text); return key.Length >= 32; }
        catch (FormatException) { key = []; return false; }
    }

    internal static bool KeyEquals(string first, string? second) =>
        !string.IsNullOrWhiteSpace(second) && TryKey(first, out var firstKey) && TryKey(second, out var secondKey) &&
        firstKey.Length == secondKey.Length && CryptographicOperations.FixedTimeEquals(firstKey, secondKey);
}

internal sealed class StatisticsFinalizer(IConfiguration configuration, TimeProvider clock, ILogger<StatisticsFinalizer> logger) : BackgroundService
{
    private readonly string? _connectionString = configuration.GetConnectionString("PrivacyLink");
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_connectionString is null) return;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await FinalizePreviousDayAsync(stoppingToken);
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "Statistics finalization failed"); await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); }
        }
    }

    internal async Task FinalizePreviousDayAsync(CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using (var lockCommand = new NpgsqlCommand($"SELECT pg_advisory_xact_lock({StatisticsRecorder.FinalizationLockId})", connection, transaction))
            await lockCommand.ExecuteNonQueryAsync(cancellationToken);
        var today = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
        var previous = today.AddDays(-1);
        var first = today.AddMonths(-13);
        var days = new List<DateOnly>();
        await using (var dayCommand = new NpgsqlCommand("SELECT day FROM stats_daily WHERE day >= $1 AND day <= $2 UNION SELECT $2", connection, transaction))
        {
            dayCommand.Parameters.AddWithValue(first);
            dayCommand.Parameters.AddWithValue(previous);
            await using var reader = await dayCommand.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) days.Add(reader.GetFieldValue<DateOnly>(0));
        }
        foreach (var day in days)
        {
            await using var rollup = new NpgsqlCommand("INSERT INTO stats_daily (day,metric,dimension,dimension_value,count,bytes) VALUES ($1,'unique_ips','','',(SELECT COUNT(*) FROM stats_visitors_daily WHERE day=$1),0) ON CONFLICT (day,metric,dimension,dimension_value) DO NOTHING", connection, transaction);
            rollup.Parameters.AddWithValue(day);
            await rollup.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var cleanup = new NpgsqlCommand("DELETE FROM stats_daily WHERE day < $1", connection, transaction))
        {
            cleanup.Parameters.AddWithValue(today.AddMonths(-13));
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
    }
}
