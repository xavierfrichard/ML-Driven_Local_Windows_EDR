using Dapper;

namespace Warden.Storage;

/// <summary>Dapper-backed Attack Chains persistence.</summary>
public sealed class AttackChainRepository : IAttackChainRepository
{
    private readonly IWardenDatabase _db;
    public AttackChainRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddNodeAsync(AttackChainRecord node, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO attack_chains
                (SessionGuid, NodePid, ParentPid, ImagePath, Sha256, CommandLine, Timestamp, Depth, SuspicionScore, LlmRationale)
            VALUES
                (@SessionGuid, @NodePid, @ParentPid, @ImagePath, @Sha256, @CommandLine, @Timestamp, @Depth, @SuspicionScore, @LlmRationale);
            SELECT last_insert_rowid();
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, node, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<AttackChainRecord>> GetRecentAsync(int limit = 500, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<AttackChainRecord>(
            new CommandDefinition("SELECT * FROM attack_chains ORDER BY Id DESC LIMIT @limit;", new { limit }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }
}

/// <summary>Dapper-backed Command Lines persistence.</summary>
public sealed class CommandLineRepository : ICommandLineRepository
{
    private readonly IWardenDatabase _db;
    public CommandLineRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(CommandLineRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO command_lines
                (Timestamp, Pid, ParentPid, ImagePath, Sha256, CommandLine, IsScript, Verdict, VerdictSource)
            VALUES
                (@Timestamp, @Pid, @ParentPid, @ImagePath, @Sha256, @CommandLine, @IsScript, @Verdict, @VerdictSource);
            SELECT last_insert_rowid();
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<CommandLineRecord>> GetAllAsync(int limit = 1000, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<CommandLineRecord>(
            new CommandDefinition("SELECT * FROM command_lines ORDER BY Id DESC LIMIT @limit;", new { limit }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }
}

/// <summary>Dapper-backed Quarantine persistence.</summary>
public sealed class QuarantineRepository : IQuarantineRepository
{
    private readonly IWardenDatabase _db;
    public QuarantineRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(QuarantineRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO quarantine
                (OriginalPath, QuarantinePath, Sha256, Size, Timestamp, Reason, RestoreAclSddl, VerdictSource, Restored)
            VALUES
                (@OriginalPath, @QuarantinePath, @Sha256, @Size, @Timestamp, @Reason, @RestoreAclSddl, @VerdictSource, @Restored);
            SELECT last_insert_rowid();
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<QuarantineRecord?> GetAsync(long id, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        return await c.QueryFirstOrDefaultAsync<QuarantineRecord>(
            new CommandDefinition("SELECT * FROM quarantine WHERE Id = @id;", new { id }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<QuarantineRecord>(
            new CommandDefinition("SELECT * FROM quarantine ORDER BY Id DESC;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task MarkRestoredAsync(long id, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        await c.ExecuteAsync(new CommandDefinition("UPDATE quarantine SET Restored = 1 WHERE Id = @id;", new { id }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }
}

/// <summary>Dapper-backed Protected Folders persistence.</summary>
public sealed class ProtectedFolderRepository : IProtectedFolderRepository
{
    private readonly IWardenDatabase _db;
    public ProtectedFolderRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(ProtectedFolder folder, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO protected_folders (Path, Recursive, MonitorMode, AddedTs)
            VALUES (@Path, @Recursive, @MonitorMode, @AddedTs);
            SELECT last_insert_rowid();
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, folder, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ProtectedFolder>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<ProtectedFolder>(
            new CommandDefinition("SELECT * FROM protected_folders ORDER BY Id;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task DeleteAsync(long id, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        await c.ExecuteAsync(new CommandDefinition("DELETE FROM protected_folders WHERE Id = @id;", new { id }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }
}

/// <summary>Dapper-backed VirusTotal reputation cache.</summary>
public sealed class ReputationCacheRepository : IReputationCacheRepository
{
    private readonly IWardenDatabase _db;
    public ReputationCacheRepository(IWardenDatabase db) => _db = db;

    // The key is a BINARY-collated TEXT PRIMARY KEY, so both sides normalize the hash to upper case: that
    // keeps the lookup on the index (a COLLATE NOCASE comparison would bypass it) and prevents the same hash
    // existing twice in different letter cases.
    public async Task<ReputationRecord?> GetAsync(string sha256, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        await using var c = _db.OpenConnection();
        return await c.QueryFirstOrDefaultAsync<ReputationRecord>(
            new CommandDefinition("SELECT * FROM reputation_cache WHERE Sha256 = @sha256;", new { sha256 = sha256.ToUpperInvariant() }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task UpsertAsync(ReputationRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        record = record with { Sha256 = record.Sha256.ToUpperInvariant() };
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO reputation_cache (Sha256, VtPositives, VtTotal, VtFirstSeen, CachedTs, TtlSecs)
            VALUES (@Sha256, @VtPositives, @VtTotal, @VtFirstSeen, @CachedTs, @TtlSecs)
            ON CONFLICT(Sha256) DO UPDATE SET
                VtPositives = excluded.VtPositives,
                VtTotal     = excluded.VtTotal,
                VtFirstSeen = excluded.VtFirstSeen,
                CachedTs    = excluded.CachedTs,
                TtlSecs     = excluded.TtlSecs;
            """;
        await c.ExecuteAsync(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
