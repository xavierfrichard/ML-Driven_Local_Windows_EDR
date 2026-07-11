using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Quarantine;
using Warden.Storage;

namespace Warden.Tests.Windows;

/// <summary>Integration test: quarantine moves a real temp file into the store and restores it.</summary>
public sealed class QuarantineStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly string _workRoot;
    private readonly WardenDb _db;
    private readonly QuarantineStore _store;

    public QuarantineStoreTests()
    {
        _workRoot = Path.Combine(Path.GetTempPath(), "warden-q-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workRoot);
        _dbPath = Path.Combine(_workRoot, "warden.db");
        _db = new WardenDb(_dbPath);
        _db.Initialize();
        var options = new QuarantineOptions { QuarantineDir = Path.Combine(_workRoot, "Quarantine") };
        _store = new QuarantineStore(options, new QuarantineRepository(_db), NullLogger<QuarantineStore>.Instance);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_workRoot, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task Quarantine_moves_file_out_and_restore_puts_it_back()
    {
        string original = Path.Combine(_workRoot, "evil.exe");
        await File.WriteAllTextAsync(original, "not really an exe");

        QuarantineResult q = await _store.QuarantineAsync(original, "test", "UnitTest");

        Assert.True(q.Success, q.Error);
        Assert.False(File.Exists(original));              // moved out of place
        Assert.True(File.Exists(q.QuarantinePath));       // now in the store
        Assert.True(q.RecordId > 0);

        bool restored = await _store.RestoreAsync(q.RecordId);

        Assert.True(restored);
        Assert.True(File.Exists(original));               // back where it started
        Assert.False(File.Exists(q.QuarantinePath));      // removed from the store
    }

    [Fact]
    public async Task Quarantine_missing_file_fails_gracefully()
    {
        QuarantineResult q = await _store.QuarantineAsync(
            Path.Combine(_workRoot, "does-not-exist.exe"), "test", "UnitTest");

        Assert.False(q.Success);
        Assert.NotNull(q.Error);
    }
}
