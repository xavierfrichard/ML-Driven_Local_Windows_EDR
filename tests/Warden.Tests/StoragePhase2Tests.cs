using Microsoft.Data.Sqlite;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>Integration tests over the Phase 2 storage repositories (real temp-file SQLite).</summary>
public sealed class StoragePhase2Tests : IDisposable
{
    private readonly string _dbPath;
    private readonly WardenDb _db;

    public StoragePhase2Tests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "warden-p2-" + Guid.NewGuid().ToString("N") + ".db");
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
    public async Task AttackChain_nodes_round_trip()
    {
        var repo = new AttackChainRepository(_db);
        await repo.AddNodeAsync(new AttackChainRecord
        {
            SessionGuid = "S1", NodePid = 100, ParentPid = 4, ImagePath = @"C:\a\a.exe",
            CommandLine = "a.exe", Timestamp = DateTimeOffset.UtcNow, Depth = 1, SuspicionScore = 0.75,
        });
        var recent = await repo.GetRecentAsync();
        var node = Assert.Single(recent);
        Assert.Equal(0.75, node.SuspicionScore);
        Assert.Equal("S1", node.SessionGuid);
    }

    [Fact]
    public async Task CommandLine_records_round_trip_with_nullable_verdict()
    {
        var repo = new CommandLineRepository(_db);
        await repo.AddAsync(new CommandLineRecord
        {
            Timestamp = DateTimeOffset.UtcNow, Pid = 10, ParentPid = 4, ImagePath = @"C:\w\powershell.exe",
            CommandLine = "powershell -enc AAA=", IsScript = true, Verdict = PolicyAction.Block, VerdictSource = "AMSI",
        });
        await repo.AddAsync(new CommandLineRecord
        {
            Timestamp = DateTimeOffset.UtcNow, Pid = 11, ParentPid = 4, ImagePath = @"C:\w\notepad.exe",
            CommandLine = "notepad", IsScript = false, // Verdict null
        });

        var all = await repo.GetAllAsync();
        Assert.Equal(2, all.Count);
        Assert.Contains(all, r => r.IsScript && r.Verdict == PolicyAction.Block && r.VerdictSource == "AMSI");
        Assert.Contains(all, r => !r.IsScript && r.Verdict is null);
    }

    [Fact]
    public async Task Quarantine_records_round_trip_and_mark_restored()
    {
        var repo = new QuarantineRepository(_db);
        long id = await repo.AddAsync(new QuarantineRecord
        {
            OriginalPath = @"C:\bad\evil.exe", QuarantinePath = @"C:\q\x.quar", Sha256 = "ABC",
            Size = 1234, Timestamp = DateTimeOffset.UtcNow, Reason = "test", RestoreAclSddl = "D:PAI(A;;FA;;;SY)",
            VerdictSource = "UserPrompt", Restored = false,
        });

        var fetched = await repo.GetAsync(id);
        Assert.NotNull(fetched);
        Assert.False(fetched!.Restored);
        Assert.Equal(1234, fetched.Size);

        await repo.MarkRestoredAsync(id);
        Assert.True((await repo.GetAsync(id))!.Restored);
    }

    [Fact]
    public async Task ProtectedFolder_add_list_delete()
    {
        var repo = new ProtectedFolderRepository(_db);
        long id = await repo.AddAsync(new ProtectedFolder
        {
            Path = @"C:\Users\me\Documents", Recursive = true, MonitorMode = "monitor", AddedTs = DateTimeOffset.UtcNow,
        });
        Assert.Single(await repo.GetAllAsync());
        await repo.DeleteAsync(id);
        Assert.Empty(await repo.GetAllAsync());
    }

    [Fact]
    public async Task Reputation_cache_upserts_and_reads()
    {
        var repo = new ReputationCacheRepository(_db);
        var now = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(new ReputationRecord
        {
            Sha256 = "DEAD", VtPositives = 3, VtTotal = 70, VtFirstSeen = now.AddDays(-10), CachedTs = now, TtlSecs = 86400,
        });
        // Upsert again (conflict path) with new values.
        await repo.UpsertAsync(new ReputationRecord
        {
            Sha256 = "DEAD", VtPositives = 12, VtTotal = 72, CachedTs = now, TtlSecs = 86400,
        });

        var rec = await repo.GetAsync("dead"); // case-insensitive
        Assert.NotNull(rec);
        Assert.Equal(12, rec!.VtPositives);
        Assert.Equal(72, rec.VtTotal);
        Assert.True(rec.IsFresh(now));
        Assert.False(rec.IsFresh(now.AddDays(2)));
    }
}
