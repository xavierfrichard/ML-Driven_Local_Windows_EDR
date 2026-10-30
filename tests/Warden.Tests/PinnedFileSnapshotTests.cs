using System.Security.Cryptography;
using Warden.Rules;

namespace Warden.Tests;

/// <summary>
/// The copy+hash+lock helper every "allow this file now" management path pins its WDAC hash with (audit M2).
/// </summary>
public sealed class PinnedFileSnapshotTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "warden-snapshot-" + Guid.NewGuid().ToString("N"));
    private readonly string _snapshots;

    public PinnedFileSnapshotTests()
    {
        Directory.CreateDirectory(_root);
        _snapshots = Path.Combine(_root, "snapshots");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public void Given_a_file_When_snapshotted_Then_the_hash_is_of_its_bytes_and_the_copy_holds_the_same_bytes()
    {
        string file = WriteFile("app.exe", "MZ original bytes");

        using PinnedFileSnapshot? snap = PinnedFileSnapshot.TryTake(file, _snapshots, expectedSha256: null, out string? refusal);

        Assert.Null(refusal);
        Assert.NotNull(snap);
        Assert.Equal(Sha(file), snap!.Sha256);
        Assert.StartsWith(_snapshots, snap.SnapshotPath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(File.ReadAllBytes(file), ReadShared(snap.SnapshotPath));
    }

    [Fact]
    public void Given_the_hash_the_admin_judged_When_the_file_still_has_those_bytes_Then_the_snapshot_is_pinned_to_it()
    {
        string file = WriteFile("app.exe", "MZ judged bytes");
        string judged = Sha(file).ToLowerInvariant();

        using PinnedFileSnapshot? snap = PinnedFileSnapshot.TryTake(file, _snapshots, judged, out string? refusal);

        Assert.Null(refusal);
        Assert.Equal(judged.ToUpperInvariant(), snap!.Sha256);
    }

    [Fact]
    public void Given_the_hash_the_admin_judged_When_the_file_was_swapped_before_the_service_copied_it_Then_it_is_refused()
    {
        // The admin picked (and was shown the hash of) one file; same-user malware replaced it before the service read it.
        string file = WriteFile("app.exe", "MZ what the admin looked at");
        string judged = Sha(file);
        File.WriteAllText(file, "MZ malware");

        using PinnedFileSnapshot? snap = PinnedFileSnapshot.TryTake(file, _snapshots, judged, out string? refusal);

        Assert.Null(snap);
        Assert.NotNull(refusal);
        Assert.Contains("not the ones that were checked", refusal, StringComparison.Ordinal);
        Assert.Contains(Sha(file), refusal, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(_snapshots)); // the refused copy is not left behind
    }

    [Theory]
    [InlineData("ABC")]
    [InlineData("")]
    [InlineData("zz23456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    public void Given_an_expected_hash_that_is_not_a_SHA256_When_snapshotting_Then_it_is_refused(string expected)
    {
        string file = WriteFile("app.exe", "MZ bytes");

        using PinnedFileSnapshot? snap = PinnedFileSnapshot.TryTake(file, _snapshots, expected, out string? refusal);

        Assert.Null(snap);
        Assert.Equal("the expected SHA-256 is not 64 hex characters.", refusal);
    }

    [Fact]
    public void Given_a_file_over_the_size_cap_When_snapshotted_or_hashed_Then_it_is_refused()
    {
        string file = WriteFile("big.exe", new string('x', 2048));

        using PinnedFileSnapshot? snap = PinnedFileSnapshot.TryTake(file, _snapshots, null, out string? refusal, maxBytes: 1024);
        string? hash = PinnedFileSnapshot.TryHash(file, out string? hashRefusal, maxBytes: 1024);

        Assert.Null(snap);
        Assert.Equal("the file is larger than the size cap.", refusal);
        Assert.Null(hash);
        Assert.Equal("the file is larger than the size cap.", hashRefusal);
    }

    [Fact]
    public void Given_a_missing_file_When_snapshotted_or_hashed_Then_it_is_refused_not_thrown()
    {
        string missing = Path.Combine(_root, "missing.exe");

        Assert.Null(PinnedFileSnapshot.TryTake(missing, _snapshots, null, out string? refusal));
        Assert.Equal("it could not be read.", refusal);
        Assert.Null(PinnedFileSnapshot.TryHash(missing, out string? hashRefusal));
        Assert.Equal("it could not be read.", hashRefusal);
    }

    [Fact]
    public void Given_a_live_snapshot_When_something_tries_to_overwrite_or_delete_it_Then_it_cannot_until_disposed()
    {
        string file = WriteFile("app.exe", "MZ bytes");
        PinnedFileSnapshot snap = PinnedFileSnapshot.TryTake(file, _snapshots, null, out _)!;
        try
        {
            Assert.ThrowsAny<IOException>(() => File.WriteAllText(snap.SnapshotPath, "MZ swapped"));
            Assert.ThrowsAny<IOException>(() => File.Delete(snap.SnapshotPath));
            Assert.Equal(File.ReadAllBytes(file), ReadShared(snap.SnapshotPath));
        }
        finally
        {
            snap.Dispose();
        }

        Assert.False(File.Exists(snap.SnapshotPath)); // dispose deletes the copy
        snap.Dispose(); // idempotent
    }

    [Fact]
    public void Given_a_file_When_hashed_without_a_copy_Then_the_hash_is_of_its_bytes()
    {
        string file = WriteFile("lib.dll", "MZ library");

        Assert.Equal(Sha(file), PinnedFileSnapshot.TryHash(file, out string? refusal));
        Assert.Null(refusal);
    }

    [Fact]
    public void Given_a_symbolic_link_When_snapshotted_or_hashed_Then_it_is_refused()
    {
        string target = WriteFile("real.exe", "MZ real");
        string link = Path.Combine(_root, "link.exe");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Creating a file symlink needs Developer Mode or SeCreateSymbolicLinkPrivilege; nothing to check without one.
            return;
        }

        Assert.Null(PinnedFileSnapshot.TryTake(link, _snapshots, null, out string? refusal));
        Assert.Equal("it is a symbolic link or junction.", refusal);
        Assert.Null(PinnedFileSnapshot.TryHash(link, out string? hashRefusal));
        Assert.Equal("it is a symbolic link or junction.", hashRefusal);
    }

    private string WriteFile(string name, string content)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Sha(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static byte[] ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return ms.ToArray();
    }
}
