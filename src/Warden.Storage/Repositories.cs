using Microsoft.Data.Sqlite;

namespace Warden.Storage;

/// <summary>
/// Owns the SQLite database file: creates the schema on first use (WAL mode) and hands out
/// connections. Implementations must be safe to resolve as a singleton.
/// </summary>
public interface IWardenDatabase
{
    /// <summary>Absolute path to the SQLite file (under %ProgramData%\Warden by default).</summary>
    string DatabasePath { get; }

    /// <summary>Creates the database + schema if they do not exist. Idempotent.</summary>
    void Initialize();

    /// <summary>Opens a new connection. Caller disposes.</summary>
    SqliteConnection OpenConnection();
}

/// <summary>Whitelist panel + verdict-history persistence.</summary>
public interface IWhitelistRepository
{
    Task<long> AddAsync(WhitelistEntry entry, CancellationToken cancellationToken = default);

    /// <summary>Most recent decision recorded for a SHA-256, or null.</summary>
    Task<WhitelistEntry?> FindLatestBySha256Async(string sha256, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<WhitelistEntry>> GetAllAsync(int limit = 1000, CancellationToken cancellationToken = default);
}

/// <summary>Rules panel persistence.</summary>
public interface IRulesRepository
{
    Task<long> AddAsync(RuleEntry rule, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<RuleEntry>> GetEnabledAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<RuleEntry>> GetAllAsync(CancellationToken cancellationToken = default);
    Task DeleteAsync(long id, CancellationToken cancellationToken = default);
}
