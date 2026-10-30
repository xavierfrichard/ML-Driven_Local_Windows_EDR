using Microsoft.Data.Sqlite;
using Warden.Storage;

namespace Warden.Tests;

/// <summary>
/// The native SQLite the service loads comes from SQLitePCLRaw.bundle_e_sqlite3, pinned in
/// Warden.Storage.csproj. SQLite before 3.50.2 is affected by CVE-2025-6965 (GHSA-2m69-gcr7-jv3q);
/// Microsoft.Data.Sqlite 8.0.10 on its own brings bundle 2.1.6, which ships an older SQLite.
/// </summary>
public sealed class SqliteNativeVersionTests : IDisposable
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), "warden-test-" + Guid.NewGuid().ToString("N") + ".db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(_dbPath + suffix); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Given_the_storage_layer_When_it_opens_a_connection_Then_the_bundled_SQLite_is_at_least_3_50_2()
    {
        var db = new WardenDb(_dbPath);
        using var connection = db.OpenConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT sqlite_version();";
        var version = Version.Parse((string)cmd.ExecuteScalar()!);

        Assert.True(version >= new Version(3, 50, 2), $"bundled SQLite is {version}");
    }
}
