using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Warden.Etw;
using Warden.Storage;

namespace Warden.Service;

/// <summary>
/// The hosted background service. Initializes the database, wires the ETW sources to the enforcement
/// controller, starts them, and runs the controller's block-handling loop until shutdown.
/// </summary>
public sealed class WardenWorker : BackgroundService
{
    private readonly IWardenDatabase _database;
    private readonly IProcessStartSource _processStarts;
    private readonly ICodeIntegrityBlockSource _blocks;
    private readonly EnforcementController _controller;
    private readonly ILogger<WardenWorker> _logger;

    public WardenWorker(
        IWardenDatabase database,
        IProcessStartSource processStarts,
        ICodeIntegrityBlockSource blocks,
        EnforcementController controller,
        ILogger<WardenWorker> logger)
    {
        _database = database;
        _processStarts = processStarts;
        _blocks = blocks;
        _controller = controller;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _database.Initialize();
        _logger.LogInformation("Warden database ready at {Path}", _database.DatabasePath);

        _processStarts.ProcessStarted += _controller.RecordProcessStart;
        _blocks.BlockObserved += _controller.EnqueueBlock;

        bool telemetryUp = TryStartTelemetry();
        if (!telemetryUp)
        {
            _logger.LogWarning(
                "ETW/CodeIntegrity telemetry did not start (needs an elevated session, ideally in the test VM). "
                + "The service stays up so the IPC/UI channel works, but no blocks will be observed.");
        }

        try
        {
            await _controller.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        finally
        {
            _processStarts.ProcessStarted -= _controller.RecordProcessStart;
            _blocks.BlockObserved -= _controller.EnqueueBlock;
            SafeStop(_processStarts.Stop, nameof(IProcessStartSource));
            SafeStop(_blocks.Stop, nameof(ICodeIntegrityBlockSource));
        }
    }

    private bool TryStartTelemetry()
    {
        bool ok = true;
        try
        {
            _blocks.Start();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start CodeIntegrity block source.");
            ok = false;
        }

        try
        {
            _processStarts.Start();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start process-start ETW source.");
            ok = false;
        }

        return ok;
    }

    private void SafeStop(Action stop, string name)
    {
        try
        {
            stop();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error stopping {Source}", name);
        }
    }
}
