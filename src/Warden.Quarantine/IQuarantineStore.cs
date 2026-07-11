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
    /// <summary>Moves <paramref name="filePath"/> into quarantine and records it.</summary>
    Task<QuarantineResult> QuarantineAsync(
        string filePath, string reason, string verdictSource, CancellationToken cancellationToken = default);

    /// <summary>Restores a previously quarantined file to its original path.</summary>
    Task<bool> RestoreAsync(long recordId, CancellationToken cancellationToken = default);
}
