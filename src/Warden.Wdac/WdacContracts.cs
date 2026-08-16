namespace Warden.Wdac;

/// <summary>A request to add a WDAC allow for one image (the result of a user/pipeline "Allow").</summary>
/// <param name="ImagePath">
/// Full path to the image to allow. Prefer the pipeline's <b>snapshot</b> of the file (an immutable copy
/// taken before inspection) so the bytes that get allow-listed are the bytes that were judged.
/// </param>
/// <param name="Sha256">
/// Flat SHA-256 (uppercase hex) of the bytes the pipeline judged. The manager re-hashes the file it is
/// about to allow-list and <b>refuses</b> if this does not match — the defence against a swap between
/// inspection and deployment.
/// </param>
/// <param name="SignerSubject">Authenticode signer subject, or null if unsigned (informational).</param>
/// <param name="PreferPublisher">Reserved; only per-file hash rules are produced today.</param>
public sealed record WdacAllowRequest(string ImagePath, string Sha256, string? SignerSubject, bool PreferPublisher);

/// <summary>One file in a batch allow request.</summary>
/// <param name="Path">Full path of the file to allow-list.</param>
/// <param name="ExpectedSha256">
/// When set, the file is allow-listed only if its current bytes hash to this (the pipeline / whitelist
/// path). When null the caller is an administrator explicitly choosing the file; the bytes present at that
/// moment are hashed, allow-listed, and reported back so they can be recorded.
/// </param>
public sealed record WdacAllowFile(string Path, string? ExpectedSha256);

/// <summary>Per-file outcome of a batch allow.</summary>
public sealed record WdacFileAllowResult(string Path, string? Sha256, bool Success, string? Error);

/// <summary>Outcome of a batch allow: the deployment result plus what happened to each file.</summary>
public sealed record WdacBatchResult(
    bool Success,
    string PolicyGuid,
    IReadOnlyList<WdacFileAllowResult> Files,
    string? BackupPath,
    string? Error)
{
    public int Allowed => Files.Count(f => f.Success);
    public int Skipped => Files.Count(f => !f.Success);
}

/// <summary>Outcome of a supplemental-policy regeneration + deployment.</summary>
public sealed record WdacUpdateResult(
    bool Success,
    string RuleAdded,
    string PolicyGuid,
    string? BackupPath,
    string? Error)
{
    public static WdacUpdateResult Fail(string error) => new(false, string.Empty, string.Empty, null, error);
}

/// <summary>Summary of a deployed policy (from CiTool --list-policies).</summary>
public sealed record WdacPolicyInfo(string PolicyGuid, string FriendlyName, bool IsBase, bool IsEnforced);

/// <summary>
/// Manages the Warden allow-list supplemental WDAC policy: adds an allow for a file (per-file hash
/// rules), revokes one, regenerates + compiles the supplemental, backs up the previous version, and
/// deploys it via CiTool without a reboot. This is the "Allow" / "Revoke" side of the enforcement loop.
/// </summary>
/// <remarks>
/// Implementations MUST be safe by construction: keep the previous XML as a backup, never deploy a
/// supplemental whose BasePolicyID is unset/all-zeros, never allow-list bytes whose hash differs from the
/// judged hash, bump the policy version on every change, and never touch the base policy's audit/enforce
/// state here (that is an explicit, separate operation). All file writes go to %ProgramData%\Warden\wdac.
/// </remarks>
public interface IWdacAllowlistManager
{
    /// <summary>Adds an allow for the file and deploys the updated supplemental (no reboot).</summary>
    Task<WdacUpdateResult> AllowAsync(WdacAllowRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds allows for several files in ONE policy update (one New-CIPolicy scan, one merge, one CiTool
    /// deploy) — used by the management panel so an administrator's "allow this file" / "allow this
    /// folder" takes effect immediately instead of on the file's next block. Files whose bytes do not
    /// match their <see cref="WdacAllowFile.ExpectedSha256"/>, that are missing, reparse points or oversized
    /// are reported as skipped; the rest are deployed.
    /// </summary>
    Task<WdacBatchResult> AllowManyAsync(IReadOnlyList<WdacAllowFile> files, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the allow rules previously added for the file with this flat SHA-256 and deploys the
    /// updated supplemental, so the OS blocks the file again on its next launch. Succeeds (with nothing to
    /// do) when no rule for the hash is present. <paramref name="imageName"/> is used only as a fallback
    /// to locate rules recorded before the rule ledger existed.
    /// </summary>
    Task<WdacUpdateResult> RevokeAsync(string sha256, string? imageName = null, CancellationToken cancellationToken = default);

    /// <summary>Lists policies currently known to the system (CiTool --list-policies).</summary>
    Task<IReadOnlyList<WdacPolicyInfo>> ListPoliciesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// The base policy GUID the Warden supplemental attaches to, discovered from the deployed policies,
    /// or null if no Warden/base policy is active yet (enforcement not set up in this VM).
    /// </summary>
    Task<string?> GetActiveBasePolicyGuidAsync(CancellationToken cancellationToken = default);
}
