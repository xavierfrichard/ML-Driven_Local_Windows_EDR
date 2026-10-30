using System.Security.Cryptography;

namespace Warden.Rules;

/// <summary>
/// A private, locked copy of a file an administrator picked, and the SHA-256 of exactly those bytes.
/// Every "allow this file now" path hashes the file through here and pins the hash it returns in the WDAC
/// request, so the bytes allow-listed are the bytes the service read (and, when the caller sent the hash it
/// judged, the bytes the caller judged).
/// </summary>
/// <remarks>
/// <para>Steps: refuse a reparse point; open the source read-only, denying writers, and refuse it above the
/// size cap; copy and hash in one pass into <c>snapshotDirectory</c>; reopen the copy read-only, denying
/// writers and deleters, and confirm it still hashes the same; when an expected hash was given, refuse unless
/// it matches. The copy stays locked until <see cref="Dispose"/>, which deletes it, so a caller can verify
/// the snapshot (for example its signature) knowing the bytes cannot change underneath it.</para>
/// <para>Fails closed: any I/O failure is a refusal, never a snapshot without a hash.</para>
/// </remarks>
public sealed class PinnedFileSnapshot : IDisposable
{
    /// <summary>Largest file the management paths snapshot (an administrator's click must not copy gigabytes).</summary>
    public const long DefaultMaxBytes = 256L * 1024 * 1024;

    private FileStream? _lock;

    private PinnedFileSnapshot(string snapshotPath, string sha256, FileStream locked)
    {
        SnapshotPath = snapshotPath;
        Sha256 = sha256;
        _lock = locked;
    }

    /// <summary>Path of the locked copy. Read-only to everyone while this object is alive.</summary>
    public string SnapshotPath { get; }

    /// <summary>Flat SHA-256 (uppercase hex) of the snapshot's bytes.</summary>
    public string Sha256 { get; }

    /// <summary>
    /// Snapshots <paramref name="sourcePath"/>. Returns null with a reason (phrased to follow "not allowed
    /// because …") when the file is a reparse point, too large, unreadable, changed while it was copied, or does
    /// not match <paramref name="expectedSha256"/>.
    /// </summary>
    public static PinnedFileSnapshot? TryTake(
        string sourcePath,
        string snapshotDirectory,
        string? expectedSha256,
        out string? refusal,
        long maxBytes = DefaultMaxBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotDirectory);

        if (expectedSha256 is not null && !RuleValidator.IsSha256(expectedSha256))
        {
            refusal = "the expected SHA-256 is not 64 hex characters.";
            return null;
        }

        string? snapshot = null;
        FileStream? locked = null;
        try
        {
            if ((File.GetAttributes(sourcePath) & FileAttributes.ReparsePoint) != 0)
            {
                refusal = "it is a symbolic link or junction.";
                return null;
            }

            Directory.CreateDirectory(snapshotDirectory);
            snapshot = Path.Combine(snapshotDirectory, $"mgmt_{Guid.NewGuid():N}_{Path.GetFileName(sourcePath)}");

            // Copy and hash in one pass. FileShare.Read on the source: nobody can modify it during the copy.
            string copiedSha;
            using (var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (source.Length > maxBytes)
                {
                    refusal = "the file is larger than the size cap.";
                    return null;
                }

                using var target = new FileStream(snapshot, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[81920];
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    hasher.AppendData(buffer, 0, read);
                    target.Write(buffer, 0, read);
                }
                copiedSha = Convert.ToHexString(hasher.GetHashAndReset());
            }

            // Hold the copy open read-only, denying writers and deleters, and confirm it still holds the bytes
            // just copied, so whatever the caller checks next and the hash it pins are of the same bytes.
            locked = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read);
            string lockedSha = Convert.ToHexString(SHA256.HashData(locked));
            locked.Position = 0;
            if (!string.Equals(lockedSha, copiedSha, StringComparison.Ordinal))
            {
                refusal = "the copy changed while it was being checked.";
                return null;
            }

            if (expectedSha256 is not null && !string.Equals(lockedSha, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                refusal = $"its bytes (SHA-256 {lockedSha}) are not the ones that were checked (SHA-256 {expectedSha256.ToUpperInvariant()}); the file may have been replaced.";
                return null;
            }

            var result = new PinnedFileSnapshot(snapshot, lockedSha, locked);
            locked = null;
            snapshot = null;
            refusal = null;
            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            refusal = "it could not be read.";
            return null;
        }
        finally
        {
            // Only reached with these still set on a refusal: clean up the partial snapshot.
            locked?.Dispose();
            DeleteQuietly(snapshot);
        }
    }

    /// <summary>
    /// Hashes a file without keeping a copy, with the same reparse-point and size-cap refusals. Used where the
    /// file's folder is already known to be writable only by SYSTEM and Administrators (folder allow rules), so
    /// a copy adds nothing but I/O; the hash is still pinned so the WDAC step re-checks the bytes.
    /// </summary>
    public static string? TryHash(string path, out string? refusal, long maxBytes = DefaultMaxBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                refusal = "it is a symbolic link or junction.";
                return null;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > maxBytes)
            {
                refusal = "the file is larger than the size cap.";
                return null;
            }

            refusal = null;
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            refusal = "it could not be read.";
            return null;
        }
    }

    /// <summary>Releases the lock and deletes the snapshot.</summary>
    public void Dispose()
    {
        FileStream? locked = Interlocked.Exchange(ref _lock, null);
        if (locked is null)
        {
            return;
        }

        locked.Dispose();
        DeleteQuietly(SnapshotPath);
    }

    private static void DeleteQuietly(string? path)
    {
        if (path is null)
        {
            return;
        }

        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
