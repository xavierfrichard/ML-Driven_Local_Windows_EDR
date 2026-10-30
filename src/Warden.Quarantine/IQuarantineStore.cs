namespace Warden.Quarantine;

/// <summary>Outcome of a quarantine operation.</summary>
public sealed record QuarantineResult(bool Success, long RecordId, string? QuarantinePath, string? Error)
{
    public static QuarantineResult Fail(string error) => new(false, 0, null, error);
}

/// <summary>
/// Moves a file into an ACL-restricted quarantine store (no execute/read for normal users), records
/// restore metadata, and can restore it later. Fail-safe: never throws out of the enforcement path.
/// </summary>
public interface IQuarantineStore
{
    /// <summary>
    /// Moves <paramref name="filePath"/> into quarantine and records it, but only if the file really at that
    /// path (no junction, symlink or hard link in the way) still hashes to <paramref name="expectedSha256"/>,
    /// the flat SHA-256 the decision was made on. Any mismatch fails and leaves the file in place.
    /// </summary>
    Task<QuarantineResult> QuarantineAsync(
        string filePath, string expectedSha256, string reason, string verdictSource, CancellationToken cancellationToken = default);

    /// <summary>Restores a previously quarantined file to its original path.</summary>
    Task<bool> RestoreAsync(long recordId, CancellationToken cancellationToken = default);
}
