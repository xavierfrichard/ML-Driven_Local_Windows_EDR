using Dapper;

namespace Warden.Storage;

/// <summary>Dapper-backed vulnerable-app list persistence.</summary>
public sealed class VulnerableAppRepository : IVulnerableAppRepository
{
    private readonly IWardenDatabase _db;
    public VulnerableAppRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddOrIgnoreAsync(VulnerableAppRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO vulnerable_apps (AppPath, Publisher, Reason, MitigationProfileId, FwInBlocked, FwOutBlocked)
            VALUES (@AppPath, @Publisher, @Reason, @MitigationProfileId, @FwInBlocked, @FwOutBlocked)
            ON CONFLICT(AppPath) DO NOTHING;
            SELECT Id FROM vulnerable_apps WHERE AppPath = @AppPath;
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<VulnerableAppRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<VulnerableAppRecord>(
            new CommandDefinition("SELECT * FROM vulnerable_apps ORDER BY AppPath;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task<int> CountAsync(CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        return await c.ExecuteScalarAsync<int>(
            new CommandDefinition("SELECT COUNT(*) FROM vulnerable_apps;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task DeleteAsync(long id, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        await c.ExecuteAsync(new CommandDefinition("DELETE FROM vulnerable_apps WHERE Id = @id;", new { id }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }
}

/// <summary>Dapper-backed mitigation-profile persistence.</summary>
public sealed class MitigationProfileRepository : IMitigationProfileRepository
{
    private readonly IWardenDatabase _db;
    public MitigationProfileRepository(IWardenDatabase db) => _db = db;

    public async Task UpsertAsync(MitigationProfileRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO mitigation_profiles (AppPath, XmlPath, AsrGuidsCsv, NoChildProcesses, CetUsermode, AppliedTs)
            VALUES (@AppPath, @XmlPath, @AsrGuidsCsv, @NoChildProcesses, @CetUsermode, @AppliedTs)
            ON CONFLICT(AppPath) DO UPDATE SET
                XmlPath          = excluded.XmlPath,
                AsrGuidsCsv      = excluded.AsrGuidsCsv,
                NoChildProcesses = excluded.NoChildProcesses,
                CetUsermode      = excluded.CetUsermode,
                AppliedTs        = excluded.AppliedTs;
            """;
        await c.ExecuteAsync(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<MitigationProfileRecord?> GetByPathAsync(string appPath, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        return await c.QueryFirstOrDefaultAsync<MitigationProfileRecord>(
            new CommandDefinition("SELECT * FROM mitigation_profiles WHERE AppPath = @appPath;", new { appPath }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<MitigationProfileRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<MitigationProfileRecord>(
            new CommandDefinition("SELECT * FROM mitigation_profiles ORDER BY AppPath;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }
}

/// <summary>Dapper-backed per-app firewall-rule persistence.</summary>
public sealed class FirewallRuleRepository : IFirewallRuleRepository
{
    private readonly IWardenDatabase _db;
    public FirewallRuleRepository(IWardenDatabase db) => _db = db;

    public async Task<long> AddAsync(FirewallRuleRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO firewall_rules (AppPath, Direction, FwRuleName, Enabled, CreatedTs)
            VALUES (@AppPath, @Direction, @FwRuleName, @Enabled, @CreatedTs);
            SELECT last_insert_rowid();
            """;
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<FirewallRuleRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<FirewallRuleRecord>(
            new CommandDefinition("SELECT * FROM firewall_rules ORDER BY Id;", cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }

    public async Task DeleteByAppAsync(string appPath, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        await c.ExecuteAsync(new CommandDefinition("DELETE FROM firewall_rules WHERE AppPath = @appPath;", new { appPath }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }
}

/// <summary>Dapper-backed Web Apps classification cache.</summary>
public sealed class WebAppClassificationRepository : IWebAppClassificationRepository
{
    private readonly IWardenDatabase _db;
    public WebAppClassificationRepository(IWardenDatabase db) => _db = db;

    public async Task UpsertAsync(WebAppClassificationRecord record, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        const string sql = """
            INSERT INTO webapp_classifications (AppPath, Engine, StaticScore, RuntimeConfirmed, SignalsJson, Ts)
            VALUES (@AppPath, @Engine, @StaticScore, @RuntimeConfirmed, @SignalsJson, @Ts)
            ON CONFLICT(AppPath) DO UPDATE SET
                Engine           = excluded.Engine,
                StaticScore      = excluded.StaticScore,
                RuntimeConfirmed = excluded.RuntimeConfirmed,
                SignalsJson      = excluded.SignalsJson,
                Ts               = excluded.Ts;
            """;
        await c.ExecuteAsync(new CommandDefinition(sql, record, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<WebAppClassificationRecord?> GetByPathAsync(string appPath, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        return await c.QueryFirstOrDefaultAsync<WebAppClassificationRecord>(
            new CommandDefinition("SELECT * FROM webapp_classifications WHERE AppPath = @appPath;", new { appPath }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<WebAppClassificationRecord>> GetAllAsync(int limit = 1000, CancellationToken cancellationToken = default)
    {
        await using var c = _db.OpenConnection();
        var rows = await c.QueryAsync<WebAppClassificationRecord>(
            new CommandDefinition("SELECT * FROM webapp_classifications ORDER BY Id DESC LIMIT @limit;", new { limit }, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
        return rows.ToList();
    }
}
