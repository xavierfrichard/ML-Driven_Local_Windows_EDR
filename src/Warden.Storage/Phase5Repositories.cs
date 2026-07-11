namespace Warden.Storage;

/// <summary>Advanced-panel vulnerable-app list persistence.</summary>
public interface IVulnerableAppRepository
{
    /// <summary>Insert an entry, ignoring a duplicate <see cref="VulnerableAppRecord.AppPath"/> (idempotent seeding).</summary>
    Task<long> AddOrIgnoreAsync(VulnerableAppRecord record, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<VulnerableAppRecord>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<int> CountAsync(CancellationToken cancellationToken = default);
    Task DeleteAsync(long id, CancellationToken cancellationToken = default);
}

/// <summary>Advanced-panel mitigation-profile persistence (one per app, by path).</summary>
public interface IMitigationProfileRepository
{
    Task UpsertAsync(MitigationProfileRecord record, CancellationToken cancellationToken = default);
    Task<MitigationProfileRecord?> GetByPathAsync(string appPath, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<MitigationProfileRecord>> GetAllAsync(CancellationToken cancellationToken = default);
}

/// <summary>Per-app firewall-rule persistence.</summary>
public interface IFirewallRuleRepository
{
    Task<long> AddAsync(FirewallRuleRecord record, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<FirewallRuleRecord>> GetAllAsync(CancellationToken cancellationToken = default);
    Task DeleteByAppAsync(string appPath, CancellationToken cancellationToken = default);
}

/// <summary>Web Apps panel classification cache (one per app, by path).</summary>
public interface IWebAppClassificationRepository
{
    Task UpsertAsync(WebAppClassificationRecord record, CancellationToken cancellationToken = default);
    Task<WebAppClassificationRecord?> GetByPathAsync(string appPath, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<WebAppClassificationRecord>> GetAllAsync(int limit = 1000, CancellationToken cancellationToken = default);
}
