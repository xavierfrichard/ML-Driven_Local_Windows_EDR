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
