using System.Collections.Concurrent;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Warden.Spike;

/// <summary>
/// A single process-start event, normalized for the correlator. Sourced from the NT Kernel Logger,
/// which â€” unlike the <c>Microsoft-Windows-Kernel-Process</c> manifest provider â€” actually carries
/// the command line (a load-bearing finding from the ETW research).
/// </summary>
/// <param name="Pid">Process id of the started process.</param>
/// <param name="ParentPid">Process id of its creator.</param>
/// <param name="ImagePath">Image path, already drive-letter normalized by TraceEvent.</param>
/// <param name="CommandLine">Full command line (populated on Win10/11).</param>
/// <param name="Timestamp">Wall-clock start time, used for time-window correlation.</param>
/// <param name="Elevated">Best-effort token-elevation flag from the manifest provider, if seen.</param>
internal sealed record ProcessStartRecord(
    int Pid,
    int ParentPid,
    string ImagePath,
    string CommandLine,
    DateTimeOffset Timestamp,
    bool? Elevated);

/// <summary>
/// Wraps a real-time TraceEvent session capturing process starts.
/// <para>
/// Primary provider is the <b>NT Kernel Logger</b> process keyword, consumed through the typed
/// <c>Kernel.ProcessStart</c> parser â€” this is the only source that yields <c>CommandLine</c> plus
/// <c>ParentID</c> in one event. The <c>Microsoft-Windows-Kernel-Process</c> manifest provider is
/// additionally enabled purely for enrichment (token elevation / package identity); it deliberately
/// is NOT relied on for the command line, which it does not contain.
/// </para>
/// Requires elevation and an x64 host. Dispose (or <see cref="Stop"/> then Dispose) to tear the
/// kernel logger down; a hard kill leaks the named session, recoverable via
/// <c>logman stop &lt;name&gt; -ets</c>.
/// </summary>
internal sealed class KernelProcessSession : IDisposable
{
    private const string DefaultSessionName = "Warden-Spike-KernelProc";

    private readonly TraceEventSession _session;
    private readonly ConcurrentDictionary<int, bool> _elevationByPid = new();
    private bool _disposed;

    /// <summary>Raised on the ETW processing thread for every observed process start.</summary>
    public event Action<ProcessStartRecord>? ProcessStarted;

    /// <param name="sessionName">Stable ETW session name so a leak is findable via <c>logman -ets</c>.</param>
    public KernelProcessSession(string sessionName = DefaultSessionName)
    {
        // Clear a stale session left by a previous hard-killed run before claiming the name.
        TraceEventSession.GetActiveSession(sessionName)?.Stop();

        _session = new TraceEventSession(sessionName) { StopOnDispose = true };

        // Primary: NT Kernel Logger -> ImageFileName (normalized) + CommandLine + ParentID.
        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

        // Optional enrichment: manifest provider for token elevation. WINEVENT_KEYWORD_PROCESS = 0x10.
        // Wrapped defensively: if the OS build rejects combining it with the kernel logger, we still
        // run with kernel-only data (which is sufficient for correlation).
        try
        {
            _session.EnableProvider(
                "Microsoft-Windows-Kernel-Process",
                TraceEventLevel.Informational,
                matchAnyKeywords: 0x10);
        }
        catch (Exception)
        {
            // Non-fatal: enrichment only.
        }

        _session.Source.Kernel.ProcessStart += OnKernelProcessStart;
        _session.Source.Dynamic.All += OnManifestEvent;
    }

    /// <summary>Reports whether the current process is elevated enough to open a kernel session.</summary>
    public static bool IsElevated() => TraceEventSession.IsElevated() == true;

    /// <summary>
    /// Blocks the calling thread, pumping ETW events until <see cref="Stop"/> is called. Run this on a
    /// dedicated thread; the <see cref="ProcessStarted"/> callback fires on that same thread.
    /// </summary>
    public void Process() => _session.Source.Process();

    /// <summary>Unblocks <see cref="Process"/>. Safe to call from another thread (e.g. Ctrl+C handler).</summary>
    public void Stop()
    {
        if (!_disposed)
        {
            _session.Source.StopProcessing();
        }
    }

    private void OnManifestEvent(TraceEvent data)
    {
        // ProcessStart (Event ID 1) on the manifest provider: capture elevation for later merge.
        if (data.ProviderName != "Microsoft-Windows-Kernel-Process" || (int)data.ID != 1)
        {
            return;
        }

        object? elevated = data.PayloadByName("ProcessTokenIsElevated");
        if (elevated is not null && int.TryParse(elevated.ToString(), out int flag))
        {
            _elevationByPid[data.ProcessID] = flag != 0;
        }
    }

    private void OnKernelProcessStart(ProcessTraceData data)
    {
        // TryRemove reports (via its return value) whether an elevation entry existed for this PID;
        // ContainsKey after removal would always be false, so use the return value directly.
        bool hadElevation = _elevationByPid.TryRemove(data.ProcessID, out bool elevated);

        var record = new ProcessStartRecord(
            Pid: data.ProcessID,
            ParentPid: data.ParentID, // NB: property is ParentID, not ParentProcessID
            ImagePath: data.ImageFileName, // TraceEvent already maps this to a drive letter
            CommandLine: data.CommandLine ?? string.Empty,
            Timestamp: new DateTimeOffset(data.TimeStamp),
            Elevated: hadElevation ? elevated : (bool?)null);

        ProcessStarted?.Invoke(record);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _session.Dispose(); // StopOnDispose => stops the ETW session / kernel logger
    }
}
