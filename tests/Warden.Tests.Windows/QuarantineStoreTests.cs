using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Quarantine;
using Warden.Storage;

namespace Warden.Tests.Windows;

/// <summary>
/// Integration tests: quarantine moves a real temp file into the store and restores it, and refuses when a
/// junction, hard link or changed bytes would make SYSTEM move a file other than the one that was judged.
/// </summary>
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
        // Remove junctions first so a recursive delete never walks through one.
        foreach (string dir in Directory.EnumerateDirectories(_workRoot, "*", SearchOption.AllDirectories).ToList())
        {
            try
            {
                if (Directory.Exists(dir) && (new DirectoryInfo(dir).Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    Directory.Delete(dir);
                }
            }
            catch { /* best effort */ }
        }
        try { Directory.Delete(_workRoot, recursive: true); } catch { /* best effort */ }
    }

    private static string Sha(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private async Task<string> WriteSample(string path, string content = "not really an exe")
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, content);
        return Sha(path);
    }

    /// <summary>Runs <c>mklink</c> (junctions and hard links need no admin rights). False if it failed.</summary>
    private static bool Mklink(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", $"/c mklink {args}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using Process p = Process.Start(psi)!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return p.HasExited && p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    [Fact]
    public async Task Given_a_plain_file_and_its_hash_When_quarantined_and_restored_Then_it_moves_out_and_back()
    {
        string original = Path.Combine(_workRoot, "evil.exe");
        string sha = await WriteSample(original);

        QuarantineResult q = await _store.QuarantineAsync(original, sha, "test", "UnitTest");

        Assert.True(q.Success, q.Error);
        Assert.False(File.Exists(original));              // moved out of place
        Assert.True(File.Exists(q.QuarantinePath));       // now in the store
        Assert.True(q.RecordId > 0);

        bool restored = await _store.RestoreAsync(q.RecordId);

        Assert.True(restored);
        Assert.True(File.Exists(original));               // back where it started
        Assert.False(File.Exists(q.QuarantinePath));      // removed from the store
        Assert.Equal(sha, Sha(original));
    }

    [Fact]
    public async Task Given_a_lowercase_expected_hash_When_quarantined_Then_it_still_matches()
    {
        string original = Path.Combine(_workRoot, "evil.exe");
        string sha = await WriteSample(original);

        QuarantineResult q = await _store.QuarantineAsync(original, sha.ToLowerInvariant(), "test", "UnitTest");

        Assert.True(q.Success, q.Error);
    }

    [Fact]
    public async Task Given_a_missing_file_When_quarantined_Then_it_fails_gracefully()
    {
        QuarantineResult q = await _store.QuarantineAsync(
            Path.Combine(_workRoot, "does-not-exist.exe"), new string('0', 64), "test", "UnitTest");

        Assert.False(q.Success);
        Assert.NotNull(q.Error);
    }

    [Fact]
    public async Task Given_bytes_that_changed_since_judgement_When_quarantined_Then_it_is_refused_and_left_in_place()
    {
        string original = Path.Combine(_workRoot, "evil.exe");
        string judgedSha = await WriteSample(original, "the bytes that were judged");
        await File.WriteAllTextAsync(original, "different bytes now");

        QuarantineResult q = await _store.QuarantineAsync(original, judgedSha, "test", "UnitTest");

        Assert.False(q.Success);
        Assert.Contains("hash", q.Error, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(original));
        Assert.Equal("different bytes now", await File.ReadAllTextAsync(original));
        Assert.False(Directory.Exists(Path.Combine(_workRoot, "Quarantine"))
                     && Directory.EnumerateFiles(Path.Combine(_workRoot, "Quarantine")).Any());
    }

    [Fact]
    public async Task Given_no_expected_hash_When_quarantined_Then_it_is_refused()
    {
        string original = Path.Combine(_workRoot, "evil.exe");
        await WriteSample(original);

        QuarantineResult q = await _store.QuarantineAsync(original, string.Empty, "test", "UnitTest");

        Assert.False(q.Success);
        Assert.True(File.Exists(original));
    }

    /// <summary>
    /// The audit's exploit: the blocked file's parent directory is swapped for a junction pointing at another
    /// directory. SYSTEM must not move whatever now sits behind the junction, even when it has the same name
    /// and the same bytes.
    /// </summary>
    [Fact]
    public async Task Given_a_junction_in_an_ancestor_When_quarantined_Then_it_is_refused_and_the_target_is_untouched()
    {
        string victimDir = Path.Combine(_workRoot, "victim");
        string victim = Path.Combine(victimDir, "evil.exe");
        string sha = await WriteSample(victim, "same bytes as the blocked sample");

        string link = Path.Combine(_workRoot, "d");
        if (!Mklink($"/J \"{link}\" \"{victimDir}\""))
        {
            return; // cannot create junctions here (e.g. non-NTFS temp); nothing to prove
        }

        QuarantineResult q = await _store.QuarantineAsync(Path.Combine(link, "evil.exe"), sha, "test", "UnitTest");

        Assert.False(q.Success);
        Assert.Contains("reparse", q.Error, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public async Task Given_a_junction_higher_up_the_path_When_quarantined_Then_it_is_refused()
    {
        string realRoot = Path.Combine(_workRoot, "real");
        string victim = Path.Combine(realRoot, "sub", "evil.exe");
        string sha = await WriteSample(victim);

        string link = Path.Combine(_workRoot, "j");
        if (!Mklink($"/J \"{link}\" \"{realRoot}\""))
        {
            return;
        }

        QuarantineResult q = await _store.QuarantineAsync(Path.Combine(link, "sub", "evil.exe"), sha, "test", "UnitTest");

        Assert.False(q.Success);
        Assert.True(File.Exists(victim));
    }

    [Fact]
    public async Task Given_a_hard_linked_file_When_quarantined_Then_it_is_refused()
    {
        string other = Path.Combine(_workRoot, "other", "protected.dat");
        string sha = await WriteSample(other);
        string blocked = Path.Combine(_workRoot, "dl", "evil.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(blocked)!);
        if (!Mklink($"/H \"{blocked}\" \"{other}\""))
        {
            return;
        }

        QuarantineResult q = await _store.QuarantineAsync(blocked, sha, "test", "UnitTest");

        Assert.False(q.Success);
        Assert.Contains("hard link", q.Error, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(blocked));
        Assert.True(File.Exists(other));
    }

    [Fact]
    public async Task Given_the_original_directory_is_now_a_junction_When_restoring_Then_it_is_refused_and_nothing_is_written()
    {
        string dir = Path.Combine(_workRoot, "app");
        string original = Path.Combine(dir, "evil.exe");
        string sha = await WriteSample(original);
        QuarantineResult q = await _store.QuarantineAsync(original, sha, "test", "UnitTest");
        Assert.True(q.Success, q.Error);

        // Replace the original directory with a junction to somewhere else.
        string elsewhere = Path.Combine(_workRoot, "elsewhere");
        Directory.CreateDirectory(elsewhere);
        Directory.Delete(dir);
        if (!Mklink($"/J \"{dir}\" \"{elsewhere}\""))
        {
            return;
        }

        bool restored = await _store.RestoreAsync(q.RecordId);

        Assert.False(restored);
        Assert.Empty(Directory.EnumerateFileSystemEntries(elsewhere));
        Assert.True(File.Exists(q.QuarantinePath)); // still quarantined
    }

    [Fact]
    public void Given_a_path_with_a_junction_ancestor_When_checked_as_a_restore_target_Then_it_is_unsafe()
    {
        string real = Path.Combine(_workRoot, "real2");
        Directory.CreateDirectory(Path.Combine(real, "sub"));
        string link = Path.Combine(_workRoot, "j2");
        if (!Mklink($"/J \"{link}\" \"{real}\""))
        {
            return;
        }

        bool safe = QuarantineStore.IsSafeRestoreTarget(Path.Combine(link, "sub", "x.exe"), out _, out string? why);

        Assert.False(safe);
        Assert.Contains("reparse", why, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"\\server\share\x.exe")]
    [InlineData(@"\\?\C:\Temp\x.exe")]
    [InlineData(@"relative\x.exe")]
    [InlineData("")]
    public void Given_a_non_local_or_relative_path_When_checked_as_a_restore_target_Then_it_is_unsafe(string path)
    {
        Assert.False(QuarantineStore.IsSafeRestoreTarget(path, out _, out _));
    }

    [Fact]
    public void Given_a_path_under_Windows_When_checked_as_a_restore_target_Then_it_is_unsafe()
    {
        string target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "warden-test-" + Guid.NewGuid().ToString("N") + ".exe");

        Assert.False(QuarantineStore.IsSafeRestoreTarget(target, out _, out _));
    }

    [Fact]
    public async Task Given_tampered_quarantined_bytes_When_restoring_Then_it_is_refused()
    {
        string original = Path.Combine(_workRoot, "evil.exe");
        string sha = await WriteSample(original);
        QuarantineResult q = await _store.QuarantineAsync(original, sha, "test", "UnitTest");
        Assert.True(q.Success, q.Error);

        // Tamper with the stored record's hash (stands in for tampered bytes, which the locked ACL keeps a
        // non-elevated test from writing).
        using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
        {
            conn.Open();
            using SqliteCommand cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE quarantine SET sha256 = $s WHERE id = $id";
            cmd.Parameters.AddWithValue("$s", new string('A', 64));
            cmd.Parameters.AddWithValue("$id", q.RecordId);
            if (cmd.ExecuteNonQuery() != 1)
            {
                return; // schema differs; nothing to prove here
            }
        }

        bool restored = await _store.RestoreAsync(q.RecordId);

        Assert.False(restored);
        Assert.False(File.Exists(original));
    }

    [Fact]
    public async Task Given_a_large_file_over_the_cap_When_quarantined_Then_it_is_refused()
    {
        var options = new QuarantineOptions { QuarantineDir = Path.Combine(_workRoot, "Q2"), MaxFileBytes = 8 };
        var store = new QuarantineStore(options, new QuarantineRepository(_db), NullLogger<QuarantineStore>.Instance);
        string original = Path.Combine(_workRoot, "big.exe");
        string sha = await WriteSample(original, new string('x', 64));

        QuarantineResult q = await store.QuarantineAsync(original, sha, "test", "UnitTest");

        Assert.False(q.Success);
        Assert.True(File.Exists(original));
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetShortPathNameW(string longPath, [System.Runtime.InteropServices.Out] char[] shortPath, uint size);

    [Fact]
    public async Task Given_an_8dot3_short_path_When_quarantined_Then_it_is_accepted_and_recorded_in_long_form()
    {
        string longPath = Path.Combine(_workRoot, "Long Directory Name", "evil.exe");
        string sha = await WriteSample(longPath);
        var buffer = new char[1024];
        uint n = GetShortPathNameW(longPath, buffer, (uint)buffer.Length);
        string shortPath = n == 0 ? longPath : new string(buffer, 0, (int)n);
        if (string.Equals(shortPath, longPath, StringComparison.OrdinalIgnoreCase))
        {
            return; // 8.3 names are disabled on this volume
        }

        QuarantineResult q = await _store.QuarantineAsync(shortPath, sha, "test", "UnitTest");

        Assert.True(q.Success, q.Error);
        QuarantineRecord? record = await new QuarantineRepository(_db).GetAsync(q.RecordId);
        Assert.Equal(longPath, record!.OriginalPath, ignoreCase: true);
    }

    [Fact]
    public async Task Given_a_quarantined_file_When_inspected_Then_its_record_holds_the_canonical_path_and_hash()
    {
        string original = Path.Combine(_workRoot, "x", "..", "evil.exe");
        string sha = await WriteSample(Path.Combine(_workRoot, "evil.exe"), Encoding.UTF8.GetString(new byte[] { 0x4D, 0x5A }));

        QuarantineResult q = await _store.QuarantineAsync(original, sha, "test", "UnitTest");

        Assert.True(q.Success, q.Error);
        QuarantineRecord? record = await new QuarantineRepository(_db).GetAsync(q.RecordId);
        Assert.NotNull(record);
        Assert.Equal(Path.Combine(_workRoot, "evil.exe"), record!.OriginalPath, ignoreCase: true);
        Assert.Equal(sha, record.Sha256);
    }
}
