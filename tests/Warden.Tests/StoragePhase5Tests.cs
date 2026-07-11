using Microsoft.Data.Sqlite;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>Integration tests over the Phase 5 storage repositories (real temp-file SQLite).</summary>
public sealed class StoragePhase5Tests : IDisposable
{
    private readonly string _dbPath;
    private readonly WardenDb _db;

    public StoragePhase5Tests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "warden-p5-" + Guid.NewGuid().ToString("N") + ".db");
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
    public async Task VulnerableApps_add_is_idempotent_by_path()
    {
        var repo = new VulnerableAppRepository(_db);
        await repo.AddOrIgnoreAsync(new VulnerableAppRecord { AppPath = "winword.exe", Reason = "internet-facing" });
        await repo.AddOrIgnoreAsync(new VulnerableAppRecord { AppPath = "winword.exe", Reason = "internet-facing" }); // dup
        await repo.AddOrIgnoreAsync(new VulnerableAppRecord { AppPath = "mshta.exe", Reason = "lolbin" });

        Assert.Equal(2, await repo.CountAsync());
        var all = await repo.GetAllAsync();
        Assert.Contains(all, a => a.AppPath == "winword.exe" && a.Reason == "internet-facing");
        Assert.Contains(all, a => a.AppPath == "mshta.exe" && a.Reason == "lolbin");
    }

    [Fact]
    public async Task MitigationProfile_upserts_by_path()
    {
        var repo = new MitigationProfileRepository(_db);
        var now = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(new MitigationProfileRecord
        {
            AppPath = "winword.exe", XmlPath = @"C:\p\winword.xml", NoChildProcesses = false, CetUsermode = true, AppliedTs = now,
        });
        // Upsert again (conflict path) toggling a flag.
        await repo.UpsertAsync(new MitigationProfileRecord
        {
            AppPath = "winword.exe", XmlPath = @"C:\p\winword2.xml", NoChildProcesses = true, CetUsermode = true, AppliedTs = now,
        });

        var rec = await repo.GetByPathAsync("winword.exe");
        Assert.NotNull(rec);
        Assert.True(rec!.NoChildProcesses);
        Assert.Equal(@"C:\p\winword2.xml", rec.XmlPath);
        Assert.Single(await repo.GetAllAsync());
    }

    [Fact]
    public async Task FirewallRules_add_and_delete_by_app()
    {
        var repo = new FirewallRuleRepository(_db);
        var now = DateTimeOffset.UtcNow;
        await repo.AddAsync(new FirewallRuleRecord { AppPath = @"C:\a\x.exe", Direction = "inbound", FwRuleName = "Warden Block IN: x.exe", CreatedTs = now });
        await repo.AddAsync(new FirewallRuleRecord { AppPath = @"C:\a\x.exe", Direction = "outbound", FwRuleName = "Warden Block OUT: x.exe", CreatedTs = now });
        await repo.AddAsync(new FirewallRuleRecord { AppPath = @"C:\a\y.exe", Direction = "inbound", FwRuleName = "Warden Block IN: y.exe", CreatedTs = now });

        Assert.Equal(3, (await repo.GetAllAsync()).Count);
        await repo.DeleteByAppAsync(@"C:\a\x.exe");
        var remaining = await repo.GetAllAsync();
        Assert.Single(remaining);
        Assert.Equal(@"C:\a\y.exe", remaining[0].AppPath);
    }

    [Fact]
    public async Task WebAppClassification_upserts_by_path()
    {
        var repo = new WebAppClassificationRepository(_db);
        var now = DateTimeOffset.UtcNow;
        await repo.UpsertAsync(new WebAppClassificationRecord
        {
            AppPath = @"C:\Apps\Claude.exe", Engine = "electron", StaticScore = 100, RuntimeConfirmed = false, SignalsJson = "[]", Ts = now,
        });
        // Upsert again after runtime confirmation.
        await repo.UpsertAsync(new WebAppClassificationRecord
        {
            AppPath = @"C:\Apps\Claude.exe", Engine = "electron", StaticScore = 100, RuntimeConfirmed = true, SignalsJson = "[]", Ts = now,
        });

        var rec = await repo.GetByPathAsync(@"C:\Apps\Claude.exe");
        Assert.NotNull(rec);
        Assert.Equal("electron", rec!.Engine);
        Assert.True(rec.RuntimeConfirmed);
        Assert.Single(await repo.GetAllAsync());
    }
}
