using Dapper;

namespace Warden.Storage;

/// <summary>Dapper-backed tamper-event log persistence.</summary>
public sealed class TamperLogRepository : ITamperLogRepository
{
    private readonly IWardenDatabase _db;
    public TamperLogRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(TamperEventRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO tamper_log (Timestamp, Category, Detail, Severity)
            VALUES (@Timestamp, @Category, @Detail, @Severity);
            SELECT last_insert_rowid();
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TamperEventRecord>> GetRecentAsync(int limit = 500, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<TamperEventRecord>(
            new CommandDefinition("SELECT * FROM tamper_log ORDER BY Id DESC LIMIT @limit;", new { limit }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }
}
