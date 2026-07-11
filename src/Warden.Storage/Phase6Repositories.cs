namespace Warden.Storage;

/// <summary>Tamper / self-protection event log persistence.</summary>
public interface ITamperLogRepository
{
    Task<long> AddAsync(TamperEventRecord record, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<TamperEventRecord>> GetRecentAsync(int limit = 500, CancellationToken cancellationToken = default);
}
