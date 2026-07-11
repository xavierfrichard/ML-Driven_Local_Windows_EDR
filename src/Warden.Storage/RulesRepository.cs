using Dapper;

namespace Warden.Storage;

/// <summary>Dapper-backed rules persistence.</summary>
public sealed class RulesRepository : IRulesRepository
{
    private readonly IWardenDatabase _db;

    public RulesRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(RuleEntry rule, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        const string sql = """
            INSERT INTO rules (Kind, MatchValue, Action, RequireSignature, RequireWhitelist, Enabled, CreatedTs, Note)
            VALUES (@Kind, @MatchValue, @Action, @RequireSignature, @RequireWhitelist, @Enabled, @CreatedTs, @Note);
            SELECT last_insert_rowid();
            """;
        return await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(sql, rule, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RuleEntry>> GetEnabledAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        var rows = await connection.QueryAsync<RuleEntry>(
            new CommandDefinition("SELECT * FROM rules WHERE Enabled = 1;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task<IReadOnlyList<RuleEntry>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        var rows = await connection.QueryAsync<RuleEntry>(
            new CommandDefinition("SELECT * FROM rules ORDER BY Id DESC;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task DeleteAsync(long id, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        await connection.ExecuteAsync(
            new CommandDefinition("DELETE FROM rules WHERE Id = @id;", new { id }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }
}
