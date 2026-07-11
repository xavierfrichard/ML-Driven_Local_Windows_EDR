using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Warden.Amsi;
using Warden.Etw;
using Warden.Storage;

namespace Warden.Monitoring;

/// <summary>
/// Records every observed process launch into the Command Lines panel. Subscribes to the shared ETW
/// process-start source (started separately by the host) and persists on a background writer so the ETW
/// thread never blocks. For script-host launches it AMSI-scans the command line and flags detections.
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
    private readonly Channel<CommandLineRecord> _channel =
        Channel.CreateBounded<CommandLineRecord>(new BoundedChannelOptions(8192)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });

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
        if (_started || _disposed)
        {
            return;
        }
        _started = true;
        _writer = Task.Run(WriteLoopAsync);
        _source.ProcessStarted += OnProcessStarted;
    }

    public void Stop()
    {
        if (!_started)
        {
            return;
        }
        _started = false;
        _source.ProcessStarted -= OnProcessStarted;
        _channel.Writer.TryComplete();
        try { _writer?.Wait(TimeSpan.FromSeconds(3)); }
        catch { /* best effort */ }
    }

    private void OnProcessStarted(ProcessStartRecord start)
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

        _channel.Writer.TryWrite(new CommandLineRecord
        {
            Timestamp = start.Timestamp,
            Pid = start.Pid,
            ParentPid = start.ParentPid,
            ImagePath = start.ImagePath,
            CommandLine = start.CommandLine,
            IsScript = isScript,
            Verdict = verdict,
            VerdictSource = verdictSource,
        });
    }

    private async Task WriteLoopAsync()
    {
        try
        {
            await foreach (CommandLineRecord record in _channel.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                try
                {
                    await _repo.AddAsync(record).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed persisting command line for pid {Pid}.", record.Pid);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // shutting down
        }
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
