namespace Warden.Storage;

/// <summary>Attack Chains persistence.</summary>
public interface IAttackChainRepository
{
    Task<long> AddNodeAsync(AttackChainRecord node, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AttackChainRecord>> GetRecentAsync(int limit = 500, CancellationToken cancellationToken = default);
}

/// <summary>Command Lines persistence.</summary>
public interface ICommandLineRepository
{
    Task<long> AddAsync(CommandLineRecord record, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CommandLineRecord>> GetAllAsync(int limit = 1000, CancellationToken cancellationToken = default);
}

/// <summary>Quarantine persistence.</summary>
public interface IQuarantineRepository
{
    Task<long> AddAsync(QuarantineRecord record, CancellationToken cancellationToken = default);
    Task<QuarantineRecord?> GetAsync(long id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(CancellationToken cancellationToken = default);
    Task MarkRestoredAsync(long id, CancellationToken cancellationToken = default);
}

/// <summary>Protected Folders persistence.</summary>
public interface IProtectedFolderRepository
{
    Task<long> AddAsync(ProtectedFolder folder, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ProtectedFolder>> GetAllAsync(CancellationToken cancellationToken = default);
    Task DeleteAsync(long id, CancellationToken cancellationToken = default);
}

/// <summary>VirusTotal reputation cache.</summary>
public interface IReputationCacheRepository
{
    Task<ReputationRecord?> GetAsync(string sha256, CancellationToken cancellationToken = default);
    Task UpsertAsync(ReputationRecord record, CancellationToken cancellationToken = default);
}
