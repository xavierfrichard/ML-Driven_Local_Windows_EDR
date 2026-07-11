using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Warden.Amsi;
using Warden.Etw;
using Warden.Storage;

namespace Warden.Monitoring;

/// <summary>
/// Records every observed process launch into the Command Lines panel. Subscribes to the shared ETW
/// process-start source (started separately by the host). The ETW callback does the bare minimum —
/// enqueue the raw record — and ALL heavy work (AMSI scanning of script command lines, SQLite writes)
/// runs on a background writer, so the ETW pump thread is never blocked (which would drop kernel events).
/// </summary>
public sealed class CommandLineRecorder : ICommandLineRecorder, IDisposable
{
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "python.exe", "node.exe",
    };

    private readonly IProcessStartSource _source;
    private readonly ICommandLineRepository _repo;
    private readonly IAmsiScanner _amsi;
    private readonly ILogger<CommandLineRecorder> _logger;
    private readonly object _lifecycle = new();

    private Channel<ProcessStartRecord>? _channel;
    private Task? _writer;
    private bool _started;
    private bool _disposed;

    public CommandLineRecorder(
        IProcessStartSource source, ICommandLineRepository repo, IAmsiScanner amsi, ILogger<CommandLineRecorder> logger)
    {
        _source = source;
        _repo = repo;
        _amsi = amsi;
        _logger = logger;
    }

    public void Start()
    {
        lock (_lifecycle)
        {
            if (_started || _disposed)
            {
                return;
            }
            _started = true;
            // Fresh channel each cycle so a prior Stop() (which completes the channel) does not silently
            // drop every record on restart.
            _channel = Channel.CreateBounded<ProcessStartRecord>(new BoundedChannelOptions(8192)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
            });
            Channel<ProcessStartRecord> channel = _channel;
            _writer = Task.Run(() => WriteLoopAsync(channel));
            _source.ProcessStarted += OnProcessStarted;
        }
    }

    public void Stop()
    {
        Task? writer;
        lock (_lifecycle)
        {
            if (!_started)
            {
                return;
            }
            _started = false;
            _source.ProcessStarted -= OnProcessStarted;
            _channel?.Writer.TryComplete();
            writer = _writer;
            _writer = null;
        }
        try { writer?.Wait(TimeSpan.FromSeconds(3)); }
        catch { /* best effort */ }
    }

    // ETW thread: do the minimum — no AMSI, no I/O.
    private void OnProcessStarted(ProcessStartRecord start) => _channel?.Writer.TryWrite(start);

    private async Task WriteLoopAsync(Channel<ProcessStartRecord> channel)
    {
        try
        {
            await foreach (ProcessStartRecord start in channel.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                try
                {
                    await _repo.AddAsync(BuildRecord(start)).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed persisting command line for pid {Pid}.", start.Pid);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
    }

    // Runs on the writer thread — safe to do the (potentially slow) synchronous AMSI P/Invoke here.
    private CommandLineRecord BuildRecord(ProcessStartRecord start)
    {
        string image = string.IsNullOrEmpty(start.ImagePath) ? string.Empty : Path.GetFileName(start.ImagePath);
        bool isScript = ScriptHosts.Contains(image);

        PolicyAction? verdict = null;
        string? verdictSource = null;
        if (isScript && !string.IsNullOrWhiteSpace(start.CommandLine))
        {
            AmsiScanOutcome outcome = _amsi.Scan(start.CommandLine, image);
            if (outcome.Verdict == AmsiVerdict.Detected)
            {
                verdict = PolicyAction.Block;
                verdictSource = "AMSI";
                _logger.LogWarning("AMSI flagged command line for {Image} (pid {Pid}).", image, start.Pid);
            }
        }

        return new CommandLineRecord
        {
            Timestamp = start.Timestamp,
            Pid = start.Pid,
            ParentPid = start.ParentPid,
            ImagePath = start.ImagePath,
            CommandLine = start.CommandLine,
            IsScript = isScript,
            Verdict = verdict,
            VerdictSource = verdictSource,
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        Stop();
    }
}
