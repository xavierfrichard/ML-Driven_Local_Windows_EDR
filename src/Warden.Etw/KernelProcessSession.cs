using System.Collections.Concurrent;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Warden.Etw;

/// <summary>
/// Captures process starts (with command line + parent) from the NT Kernel Logger via TraceEvent.
/// Heavy resources are created in <see cref="Start"/> (not the constructor) so a non-elevated host does
/// not fault at DI time; <see cref="Start"/> throws only when actually asked to run without rights.
/// </summary>
public sealed class KernelProcessSession : IProcessStartSource
{
    private const string SessionName = "Warden-KernelProc";

    private readonly ConcurrentDictionary<int, bool> _elevationByPid = new();
    private TraceEventSession? _session;
    private Thread? _pump;
    private bool _disposed;

    public event Action<ProcessStartRecord>? ProcessStarted;

    /// <summary>Whether the current process can open a kernel ETW session.</summary>
    public static bool IsElevated() => TraceEventSession.IsElevated() == true;

    public void Start()
    {
        if (_disposed || _session is not null)
        {
            return;
        }

        // Clear a stale session left by a previous hard-killed run.
        try
        {
            using var existing = new TraceEventSession(SessionName, TraceEventSessionOptions.Attach);
            existing.Stop();
        }
        catch
        {
            // no stale session
        }

        _session = new TraceEventSession(SessionName) { StopOnDispose = true };
        _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
        try
        {
            // Enrichment only (token elevation). WINEVENT_KEYWORD_PROCESS = 0x10.
            _session.EnableProvider("Microsoft-Windows-Kernel-Process", TraceEventLevel.Informational, 0x10);
        }
        catch
        {
            // non-fatal: kernel-logger data alone is sufficient for correlation
        }

        _session.Source.Kernel.ProcessStart += OnKernelProcessStart;
        _session.Source.Dynamic.All += OnManifestEvent;

        _pump = new Thread(PumpLoop) { IsBackground = true, Name = "warden-kernelproc-pump" };
        _pump.Start();
    }

    public void Stop()
    {
        try
        {
            _session?.Source.StopProcessing();
        }
        catch
        {
            // session already torn down
        }
        _pump?.Join(TimeSpan.FromSeconds(3));
        _pump = null;
    }

    private void PumpLoop()
    {
        try
        {
            _session?.Source.Process();
        }
        catch
        {
            // session stopped/disposed
        }
    }

    private void OnManifestEvent(TraceEvent data)
    {
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
        bool hadElevation = _elevationByPid.TryRemove(data.ProcessID, out bool elevated);

        ProcessStarted?.Invoke(new ProcessStartRecord(
            Pid: data.ProcessID,
            ParentPid: data.ParentID,
            ImagePath: data.ImageFileName,
            CommandLine: data.CommandLine ?? string.Empty,
            Timestamp: new DateTimeOffset(data.TimeStamp),
            Elevated: hadElevation ? elevated : null));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        Stop();
        _session?.Dispose();
        _session = null;
    }
}
