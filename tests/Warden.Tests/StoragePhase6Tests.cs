using Microsoft.Data.Sqlite;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>Integration test over the Phase 6 tamper-log repository (real temp-file SQLite).</summary>
public sealed class StoragePhase6Tests : IDisposable
{
    private readonly string _dbPath;
    private readonly WardenDb _db;

    public StoragePhase6Tests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "warden-p6-" + Guid.NewGuid().ToString("N") + ".db");
        _db = new WardenDb(_dbPath);
        _db.Initialize();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task Tamper_events_round_trip_newest_first()
    {
        var repo = new TamperLogRepository(_db);
        await repo.AddAsync(new TamperEventRecord { Timestamp = DateTimeOffset.UtcNow, Category = "db-acl-applied", Severity = "info" });
        await repo.AddAsync(new TamperEventRecord { Timestamp = DateTimeOffset.UtcNow, Category = "data-dir-lockdown-failed", Detail = "dir=False", Severity = "critical" });

        var recent = await repo.GetRecentAsync();
        Assert.Equal(2, recent.Count);
        Assert.Equal("data-dir-lockdown-failed", recent[0].Category); // newest first
        Assert.Equal("critical", recent[0].Severity);
        Assert.Equal("dir=False", recent[0].Detail);
    }
}
