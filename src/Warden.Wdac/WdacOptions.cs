namespace Warden.Wdac;

/// <summary>Configuration for the WDAC allow-list manager.</summary>
public sealed class WdacOptions
{
    /// <summary>Working directory for the supplemental XML/.cip and backups.</summary>
    public string WorkDir { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden", "wdac");

    /// <summary>
    /// Optional explicit base policy GUID the supplemental attaches to. When null, the manager discovers
    /// the active non-system base policy from CiTool at runtime.
    /// </summary>
    public string? BasePolicyGuid { get; set; }

    /// <summary>Path to CiTool (Windows 11 22H2+ ships it in System32).</summary>
    public string CiToolPath { get; set; } = "CiTool.exe";

    /// <summary>Timeout for each ConfigCI / CiTool invocation.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(3);
}
