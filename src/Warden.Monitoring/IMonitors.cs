namespace Warden.Monitoring;

/// <summary>
/// Records every observed process launch into the Command Lines panel (image, cmdline, parent, script
/// flag). Consumes the ETW process-start source; started/stopped by the host.
/// </summary>
public interface ICommandLineRecorder
{
    void Start();
    void Stop();
}

/// <summary>
/// Watches the user-configured protected folders for file changes (especially newly-created,
/// internet-tagged executables) and logs them. Started/stopped by the host.
/// </summary>
public interface IProtectedFolderMonitor
{
    void Start();
    void Stop();
}
