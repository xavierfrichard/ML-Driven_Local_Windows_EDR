using Dapper;

namespace Warden.Storage;

/// <summary>Dapper-backed whitelist persistence.</summary>
public sealed class WhitelistRepository : IWhitelistRepository
{
    private readonly IWardenDatabase _db;

    public WhitelistRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(WhitelistEntry entry, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        const string sql = """
            INSERT INTO whitelist
                (Timestamp, Action, ProcessName, ProcessPath, Sha256, SignerSubject, SignerIssuer,
                 CertThumbprint, LlmVerdict, MlScore, CommandLine, FileSize, ParentName, ParentPath, Source, RuleId)
            VALUES
                (@Timestamp, @Action, @ProcessName, @ProcessPath, @Sha256, @SignerSubject, @SignerIssuer,
                 @CertThumbprint, @LlmVerdict, @MlScore, @CommandLine, @FileSize, @ParentName, @ParentPath, @Source, @RuleId);
            SELECT last_insert_rowid();
            """;
        return await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(sql, entry, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<WhitelistEntry?> FindLatestBySha256Async(string sha256, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        const string sql =
            "SELECT * FROM whitelist WHERE Sha256 = @sha256 COLLATE NOCASE ORDER BY Id DESC LIMIT 1;";
        return await connection.QueryFirstOrDefaultAsync<WhitelistEntry>(
            new CommandDefinition(sql, new { sha256 }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<WhitelistEntry>> GetAllAsync(int limit = 1000, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        const string sql = "SELECT * FROM whitelist ORDER BY Id DESC LIMIT @limit;";
        var rows = await connection.QueryAsync<WhitelistEntry>(
            new CommandDefinition(sql, new { limit }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.ToList();
    }
}
