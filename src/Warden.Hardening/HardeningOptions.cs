namespace Warden.Hardening;

/// <summary>Configuration for the self-protection / hardening layer.</summary>
public sealed class HardeningOptions
{
    /// <summary>The Windows service name (for the installer's sc.exe hardening).</summary>
    public string ServiceName { get; set; } = "WardenAgent";

    /// <summary>The agent's on-disk data directory (database, quarantine, logs).</summary>
    public string DataDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden");

    /// <summary>The database file to lock down. Defaults to <c>&lt;DataDirectory&gt;\warden.db</c>.</summary>
    public string? DatabasePath { get; set; }

    /// <summary>The log directory (Serilog rolling files).</summary>
    public string LogDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden", "logs");

    /// <summary>
    /// Apply the data-directory / database ACL lockdown when the service starts. <b>Off by default</b> so
    /// a plain dev/console run never re-ACLs <c>%ProgramData%\Warden</c>; the installer turns this on
    /// (via the <c>WARDEN_ENFORCE_HARDENING</c> environment variable) on the target machine / VM.
    /// </summary>
    public bool EnforceOnStartup { get; set; }

    /// <summary>Seconds after which the service failure counter resets (for <c>sc failure</c>).</summary>
    public int RecoveryResetSeconds { get; set; } = 86400;

    /// <summary>Delay before each recovery restart, in milliseconds (for <c>sc failure</c>).</summary>
    public int RecoveryRestartDelayMs { get; set; } = 60000;

    /// <summary>Effective database path.</summary>
    public string ResolvedDatabasePath => DatabasePath ?? Path.Combine(DataDirectory, "warden.db");
}
