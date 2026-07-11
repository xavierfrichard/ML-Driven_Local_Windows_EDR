namespace Warden.Wdac;

/// <summary>A request to add a WDAC allow for one image (the result of a user/pipeline "Allow").</summary>
/// <param name="ImagePath">Full path to the image to allow.</param>
/// <param name="Sha256">Flat SHA-256 (uppercase hex) — fallback identity when unsigned.</param>
/// <param name="SignerSubject">Authenticode signer subject, or null if unsigned.</param>
/// <param name="PreferPublisher">
/// When true and the file is validly signed, add a publisher rule (collapses many hashes) rather than
/// a per-file hash rule.
/// </param>
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
/// Manages the Warden allow-list supplemental WDAC policy: adds an allow for a file (publisher or
/// hash), regenerates + compiles the supplemental, backs up the previous version, and deploys it via
/// CiTool without a reboot. This is the "Allow" side of the enforcement loop.
/// </summary>
/// <remarks>
/// Implementations MUST be safe by construction: keep the previous .cip as a backup, never deploy a
/// supplemental whose BasePolicyID is unset/all-zeros, and never touch the base policy's audit/enforce
/// state here (that is an explicit, separate operation). All file writes go to
/// %ProgramData%\Warden\wdac.
/// </remarks>
public interface IWdacAllowlistManager
{
    /// <summary>Adds an allow for the file and deploys the updated supplemental (no reboot).</summary>
    Task<WdacUpdateResult> AllowAsync(WdacAllowRequest request, CancellationToken cancellationToken = default);

    /// <summary>Lists policies currently known to the system (CiTool --list-policies).</summary>
    Task<IReadOnlyList<WdacPolicyInfo>> ListPoliciesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// The base policy GUID the Warden supplemental attaches to, discovered from the deployed policies,
    /// or null if no Warden/base policy is active yet (enforcement not set up in this VM).
    /// </summary>
    Task<string?> GetActiveBasePolicyGuidAsync(CancellationToken cancellationToken = default);
}
