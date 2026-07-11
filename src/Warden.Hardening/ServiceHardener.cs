namespace Warden.Hardening;

/// <summary>
/// Builds the <c>sc.exe</c> argument strings that harden the Windows service — its access-control
/// descriptor (stop/delete protection) and its failure/recovery actions (restart-on-kill). Pure and
/// unit-tested; the installer runs <c>sc.exe</c> with these arguments (a real, elevated system change,
/// applied on the target machine / in the VM, not on a dev console).
/// </summary>
public static class ServiceHardener
{
    /// <summary>Arguments for <c>sc sdset &lt;service&gt; &lt;dacl&gt;</c> (hardens who can control the service).</summary>
    public static string BuildSdSetArguments(string serviceName, string serviceDacl) =>
        $"sdset {serviceName} {serviceDacl}";

    /// <summary>
    /// Arguments for <c>sc failure</c> — restart the service on each of the first three failures
    /// (restart-on-kill), with the failure counter reset after <paramref name="resetSeconds"/>. The
    /// spaces after <c>reset=</c> / <c>actions=</c> are required by <c>sc.exe</c>.
    /// </summary>
    public static string BuildFailureArguments(string serviceName, int resetSeconds, int restartDelayMs)
    {
        string action = $"restart/{restartDelayMs}";
        return $"failure {serviceName} reset= {resetSeconds} actions= {action}/{action}/{action}";
    }

    /// <summary>Arguments for <c>sc failureflag</c> — also trigger recovery on non-crash stops (e.g. a kill).</summary>
    public static string BuildFailureFlagArguments(string serviceName) => $"failureflag {serviceName} 1";
}
