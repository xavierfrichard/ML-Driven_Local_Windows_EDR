using Microsoft.Data.Sqlite;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>
/// Integration tests over a real (temp-file) SQLite database. These prove the schema, Dapper mapping
/// of enums + bools + DateTimeOffset, and the repository round-trips actually work.
/// </summary>
public sealed class SqliteStorageTests : IDisposable
{
    private readonly string _dbPath;
    private readonly WardenDb _db;

    public SqliteStorageTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "warden-test-" + Guid.NewGuid().ToString("N") + ".db");
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
    public async Task Whitelist_entry_round_trips_with_all_field_types()
    {
        var repo = new WhitelistRepository(_db);
        var when = DateTimeOffset.UtcNow;
        var entry = new WhitelistEntry
        {
            Timestamp = when,
            Action = PolicyAction.Allow,
            ProcessName = "app.exe",
            ProcessPath = @"C:\apps\app.exe",
            Sha256 = "ABCDEF0123456789",
            SignerSubject = "CN=Contoso",
            MlScore = 0.42,
            CommandLine = "app.exe --run",
            FileSize = 4096,
            ParentName = "explorer.exe",
            ParentPath = @"C:\Windows\explorer.exe",
            Source = "UserPrompt",
        };

        long id = await repo.AddAsync(entry);
        Assert.True(id > 0);

        // Lookup is case-insensitive on the hash.
        WhitelistEntry? found = await repo.FindLatestBySha256Async("abcdef0123456789");
        Assert.NotNull(found);
        Assert.Equal(PolicyAction.Allow, found!.Action);            // enum survived
        Assert.Equal("app.exe", found.ProcessName);
        Assert.Equal("CN=Contoso", found.SignerSubject);
        Assert.Equal(0.42, found.MlScore);
        Assert.Equal(4096, found.FileSize);
        Assert.Equal(when.ToUnixTimeSeconds(), found.Timestamp.ToUnixTimeSeconds()); // DateTimeOffset survived

        var all = await repo.GetAllAsync();
        Assert.Single(all);
    }

    [Fact]
    public async Task FindLatest_returns_most_recent_decision_for_a_hash()
    {
        var repo = new WhitelistRepository(_db);
        await repo.AddAsync(New("HASH1", PolicyAction.Block));
        await repo.AddAsync(New("HASH1", PolicyAction.Allow)); // newer

        WhitelistEntry? found = await repo.FindLatestBySha256Async("HASH1");
        Assert.Equal(PolicyAction.Allow, found!.Action);
    }

    [Fact]
    public async Task Rules_round_trip_enabled_filter_and_delete()
    {
        var repo = new RulesRepository(_db);
        long blockId = await repo.AddAsync(new RuleEntry
        {
            Kind = RuleKind.Hash,
            MatchValue = "DEADBEEF",
            Action = PolicyAction.Block,
            Enabled = true,
            CreatedTs = DateTimeOffset.UtcNow,
        });
        await repo.AddAsync(new RuleEntry
        {
            Kind = RuleKind.Extension,
            MatchValue = ".exe",
            Action = PolicyAction.Allow,
            RequireSignature = true,   // bool must survive
            Enabled = false,           // filtered out of GetEnabled
            CreatedTs = DateTimeOffset.UtcNow,
        });

        var enabled = await repo.GetEnabledAsync();
        Assert.Single(enabled);
        Assert.Equal(RuleKind.Hash, enabled[0].Kind);

        var all = await repo.GetAllAsync();
        Assert.Equal(2, all.Count);
        RuleEntry allowRule = all.Single(r => r.Kind == RuleKind.Extension);
        Assert.True(allowRule.RequireSignature);
        Assert.False(allowRule.Enabled);
        Assert.Equal(PolicyAction.Allow, allowRule.Action);

        await repo.DeleteAsync(blockId);
        Assert.Empty(await repo.GetEnabledAsync());
    }

    private static WhitelistEntry New(string sha, PolicyAction action) => new()
    {
        Timestamp = DateTimeOffset.UtcNow,
        Action = action,
        ProcessName = "x.exe",
        ProcessPath = @"C:\x\x.exe",
        Sha256 = sha,
        Source = "Test",
    };
}
