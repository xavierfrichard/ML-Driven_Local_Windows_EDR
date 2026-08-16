using Warden.Hardening;
using Warden.Ipc;

namespace Warden.Service;

/// <summary>
/// Routes IPC security refusals (rejected peer, non-admin Allow, squatted pipe name, oversized frame)
/// into the tamper log so they land in both Serilog and the <c>tamper_log</c> table.
/// </summary>
internal sealed class PipeSecurityTamperSink : IPipeSecurityEventSink
{
    private readonly ITamperLog _tamperLog;

    public PipeSecurityTamperSink(ITamperLog tamperLog) => _tamperLog = tamperLog;

    public void OnSecurityEvent(string message)
    {
        // Fire-and-forget by design: the pipe loops must never block on the database.
        _ = _tamperLog.LogAsync("ipc", message, "warning");
    }
}
