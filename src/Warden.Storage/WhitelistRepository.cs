using Dapper;

namespace Warden.Storage;

/// <summary>
/// Dapper-backed whitelist persistence. The table holds the <b>current</b> decision for a file, keyed
/// by SHA-256 — not a history of every evaluation — so <see cref="AddAsync"/> is an upsert and the
/// panel never shows the same hash twice.
/// </summary>
public sealed class WhitelistRepository : IWhitelistRepository
{
    private readonly IWardenDatabase _db;

    public WhitelistRepository(IWardenDatabase db) => _db = db;

    /// <summary>
    /// Records the decision for a file, replacing any previous decision for the same SHA-256.
    /// Returns the row id of the (inserted or updated) entry.
    /// </summary>
    public async Task<long> AddAsync(WhitelistEntry entry, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();

        // The conflict target repeats the index's COLLATE NOCASE so a hex-case difference in the hash
        // updates the existing row instead of raising a constraint violation.
        const string sql = """
            INSERT INTO whitelist
                (Timestamp, Action, ProcessName, ProcessPath, Sha256, SignerSubject, SignerIssuer,
                 CertThumbprint, LlmVerdict, MlScore, CommandLine, FileSize, ParentName, ParentPath, Source, RuleId)
            VALUES
                (@Timestamp, @Action, @ProcessName, @ProcessPath, @Sha256, @SignerSubject, @SignerIssuer,
                 @CertThumbprint, @LlmVerdict, @MlScore, @CommandLine, @FileSize, @ParentName, @ParentPath, @Source, @RuleId)
            ON CONFLICT(Sha256 COLLATE NOCASE) DO UPDATE SET
                Timestamp      = excluded.Timestamp,
                Action         = excluded.Action,
                ProcessName    = excluded.ProcessName,
                ProcessPath    = excluded.ProcessPath,
                SignerSubject  = excluded.SignerSubject,
                SignerIssuer   = excluded.SignerIssuer,
                CertThumbprint = excluded.CertThumbprint,
                LlmVerdict     = excluded.LlmVerdict,
                MlScore        = excluded.MlScore,
                CommandLine    = excluded.CommandLine,
                FileSize       = excluded.FileSize,
                ParentName     = excluded.ParentName,
                ParentPath     = excluded.ParentPath,
                Source         = excluded.Source,
                RuleId         = excluded.RuleId;

            SELECT Id FROM whitelist WHERE Sha256 = @Sha256 COLLATE NOCASE LIMIT 1;
            """;

        return await connection.ExecuteScalarAsync<long>(
            new CommandDefinition(sql, entry, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>
    /// The decision recorded for a SHA-256, or null. With one row per hash this is simply "the" entry;
    /// the name is kept for the <see cref="IWhitelistRepository"/> contract and its callers.
    /// </summary>
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

    /// <summary>
    /// Flips an existing entry between Allow and Block. Setting Block makes the whitelist tier replay a
    /// block for that hash, which is how a previously-allowed file is revoked from the panel.
    /// </summary>
    public async Task SetActionAsync(long id, PolicyAction action, CancellationToken cancellationToken = default)
    {
        await using var connection = _db.OpenConnection();
        const string sql = "UPDATE whitelist SET Action = @action WHERE Id = @id;";
        await connection.ExecuteAsync(
            new CommandDefinition(sql, new { id, action = (int)action }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }
}
