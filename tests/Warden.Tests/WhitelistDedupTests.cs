using Microsoft.Data.Sqlite;
using Warden.Ipc;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>
/// The whitelist holds the CURRENT decision per file, one row per SHA-256 — it is not a verdict log.
/// These tests cover the upsert, the action toggle, and the migration that repairs databases written
/// by the earlier insert-per-evaluation build (where one DLL could accumulate several identical rows).
/// </summary>
public sealed class WhitelistDedupTests : IDisposable
{
    private readonly string _dbPath;

    public WhitelistDedupTests() =>
        _dbPath = Path.Combine(Path.GetTempPath(), "warden-dedup-" + Guid.NewGuid().ToString("N") + ".db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch { /* best effort */ }
        }
    }

    private static WhitelistEntry Entry(string sha, string name, PolicyAction action = PolicyAction.Allow) => new()
    {
        Timestamp = DateTimeOffset.UtcNow,
        Action = action,
        ProcessName = name,
        ProcessPath = @"C:\apps\" + name,
        Sha256 = sha,
        Source = "UserPrompt",
    };

    [Fact]
    public async Task Adding_the_same_hash_twice_updates_one_row_instead_of_appending()
    {
        var db = new WardenDb(_dbPath);
        db.Initialize();
        var repo = new WhitelistRepository(db);

        long first = await repo.AddAsync(Entry("AABBCC", "promine.dll"));
        long second = await repo.AddAsync(Entry("AABBCC", "promine.dll", PolicyAction.Block));

        Assert.Equal(first, second);

        IReadOnlyList<WhitelistEntry> all = await repo.GetAllAsync();
        Assert.Single(all);

        // The newer decision wins.
        Assert.Equal(PolicyAction.Block, all[0].Action);
    }

    [Fact]
    public async Task A_hash_differing_only_in_case_is_the_same_entry()
    {
        var db = new WardenDb(_dbPath);
        db.Initialize();
        var repo = new WhitelistRepository(db);

        await repo.AddAsync(Entry("aabbcc", "app.exe"));
        await repo.AddAsync(Entry("AABBCC", "app.exe"));

        Assert.Single(await repo.GetAllAsync());
    }

    [Fact]
    public async Task Distinct_hashes_remain_distinct_rows()
    {
        var db = new WardenDb(_dbPath);
        db.Initialize();
        var repo = new WhitelistRepository(db);

        await repo.AddAsync(Entry("1111", "a.exe"));
        await repo.AddAsync(Entry("2222", "b.exe"));

        Assert.Equal(2, (await repo.GetAllAsync()).Count);
    }

    [Fact]
    public async Task Set_action_flips_an_entry_between_allow_and_block()
    {
        var db = new WardenDb(_dbPath);
        db.Initialize();
        var repo = new WhitelistRepository(db);

        long id = await repo.AddAsync(Entry("DEADBEEF", "tool.exe"));
        await repo.SetActionAsync(id, PolicyAction.Block);

        WhitelistEntry? found = await repo.FindLatestBySha256Async("DEADBEEF");
        Assert.NotNull(found);
        Assert.Equal(PolicyAction.Block, found!.Action);

        await repo.SetActionAsync(id, PolicyAction.Allow);
        Assert.Equal(PolicyAction.Allow, (await repo.FindLatestBySha256Async("DEADBEEF"))!.Action);
    }

    [Fact]
    public async Task Initialize_collapses_duplicate_rows_left_by_the_earlier_log_style_schema()
    {
        // Build a pre-migration database by hand: the old schema had a NON-unique index on Sha256, so
        // four evaluations of the same file wrote four rows. This is the shape found in the field.
        await using (var raw = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
        }.ToString()))
        {
            await raw.OpenAsync();
            await using var cmd = raw.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE whitelist (
                    Id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    Timestamp      TEXT    NOT NULL,
                    Action         INTEGER NOT NULL,
                    ProcessName    TEXT    NOT NULL,
                    ProcessPath    TEXT    NOT NULL,
                    Sha256         TEXT    NOT NULL,
                    SignerSubject  TEXT,
                    SignerIssuer   TEXT,
                    CertThumbprint TEXT,
                    LlmVerdict     TEXT,
                    MlScore        REAL,
                    CommandLine    TEXT    NOT NULL DEFAULT '',
                    FileSize       INTEGER NOT NULL DEFAULT -1,
                    ParentName     TEXT,
                    ParentPath     TEXT,
                    Source         TEXT    NOT NULL,
                    RuleId         INTEGER
                );
                CREATE INDEX IX_whitelist_sha256 ON whitelist(Sha256);

                INSERT INTO whitelist (Timestamp, Action, ProcessName, ProcessPath, Sha256, Source)
                VALUES ('2026-08-14T10:00:00+00:00', 0, 'promine.dll', 'C:\p\promine.dll', 'FEEDFACE', 'TrustGate'),
                       ('2026-08-14T10:01:00+00:00', 0, 'promine.dll', 'C:\p\promine.dll', 'FEEDFACE', 'TrustGate'),
                       ('2026-08-14T10:02:00+00:00', 0, 'promine.dll', 'C:\p\promine.dll', 'FEEDFACE', 'TrustGate'),
                       ('2026-08-14T10:03:00+00:00', 1, 'promine.dll', 'C:\p\promine.dll', 'FEEDFACE', 'UserPrompt'),
                       ('2026-08-14T10:04:00+00:00', 0, 'other.exe',   'C:\p\other.exe',   'CAFEBABE', 'Rules');
                """;
            await cmd.ExecuteNonQueryAsync();
        }

        // Opening the database with the current build must repair it, not fail on the unique index.
        var db = new WardenDb(_dbPath);
        db.Initialize();

        var repo = new WhitelistRepository(db);
        IReadOnlyList<WhitelistEntry> all = await repo.GetAllAsync();

        Assert.Equal(2, all.Count);

        // The surviving row for the duplicated hash is the most recent one (the user's Block decision).
        WhitelistEntry? survivor = await repo.FindLatestBySha256Async("FEEDFACE");
        Assert.NotNull(survivor);
        Assert.Equal(PolicyAction.Block, survivor!.Action);
        Assert.Equal("UserPrompt", survivor.Source);

        // Re-running Initialize stays idempotent.
        db.Initialize();
        Assert.Equal(2, (await repo.GetAllAsync()).Count);
    }
}

/// <summary>
/// Guards the management channel's authorization gate. Every operation that changes agent state must be
/// listed in <see cref="MgmtOperations.Mutations"/>: the pipe server refuses those for a non-elevated
/// caller, so an operation missing from the set would be silently writable by any local user.
/// </summary>
public sealed class MgmtAuthorizationTests
{
    [Theory]
    [InlineData(MgmtOperations.RulesAdd)]
    [InlineData(MgmtOperations.RulesDelete)]
    [InlineData(MgmtOperations.FoldersAdd)]
    [InlineData(MgmtOperations.FoldersDelete)]
    [InlineData(MgmtOperations.WhitelistAdd)]
    [InlineData(MgmtOperations.WhitelistSetAction)]
    [InlineData(MgmtOperations.VulnAppSetFirewall)]
    public void Every_state_changing_operation_requires_elevation(string operation) =>
        Assert.True(MgmtOperations.IsMutation(operation));

    [Theory]
    [InlineData(MgmtOperations.WhitelistList)]
    [InlineData(MgmtOperations.UserLogList)]
    [InlineData(MgmtOperations.RulesList)]
    [InlineData(MgmtOperations.CommandLinesList)]
    [InlineData(MgmtOperations.QuarantineList)]
    [InlineData(MgmtOperations.ChainsList)]
    [InlineData(MgmtOperations.FoldersList)]
    [InlineData(MgmtOperations.VulnAppsList)]
    [InlineData(MgmtOperations.MitigationsList)]
    [InlineData(MgmtOperations.FirewallList)]
    [InlineData(MgmtOperations.WebAppsList)]
    [InlineData(MgmtOperations.TamperList)]
    public void Read_operations_do_not_require_elevation(string operation) =>
        Assert.False(MgmtOperations.IsMutation(operation));

    [Fact]
    public void An_unknown_operation_is_not_treated_as_a_mutation_or_silently_accepted() =>
        Assert.False(MgmtOperations.IsMutation("something.invented"));
}
