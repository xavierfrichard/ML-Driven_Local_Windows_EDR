namespace Warden.Wdac;

/// <summary>Configuration for the WDAC allow-list manager.</summary>
public sealed class WdacOptions
{
    /// <summary>Working directory for the supplemental XML/.cip, the rule ledger and backups.</summary>
    public string WorkDir { get; set; } = Warden.Core.WardenPaths.Under("wdac");

    /// <summary>
    /// Optional explicit base policy GUID the supplemental attaches to (registry-brace or plain form).
    /// When null, the manager discovers the active non-system base policy from CiTool at runtime. Set it
    /// from configuration (<c>WARDEN_WDAC_BASE_POLICY_GUID</c>) — never hard-code a machine's GUID in source.
    /// </summary>
    public string? BasePolicyGuid { get; set; }

    /// <summary>
    /// Path to CiTool. Pinned to the System32 copy (Windows 11 22H2+ ships it there); a LocalSystem service
    /// must never resolve executables through the PATH search order.
    /// </summary>
    public string CiToolPath { get; set; } = Path.Combine(Environment.SystemDirectory, "CiTool.exe");

    /// <summary>Timeout for each ConfigCI / CiTool invocation.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(3);
}
