using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Warden.AntiExploit;
using Warden.AttackChain;
using Warden.Etw;
using Warden.Monitoring;
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
    private readonly IProcessTreeBuilder _tree;
    private readonly ICommandLineRecorder _commandLines;
    private readonly IProtectedFolderMonitor _folders;
    private readonly IVulnerableAppRepository _vulnerableApps;
    private readonly ILogger<WardenWorker> _logger;

    public WardenWorker(
        IWardenDatabase database,
        IProcessStartSource processStarts,
        ICodeIntegrityBlockSource blocks,
        EnforcementController controller,
        IProcessTreeBuilder tree,
        ICommandLineRecorder commandLines,
        IProtectedFolderMonitor folders,
        IVulnerableAppRepository vulnerableApps,
        ILogger<WardenWorker> logger)
    {
        _database = database;
        _processStarts = processStarts;
        _blocks = blocks;
        _controller = controller;
        _tree = tree;
        _commandLines = commandLines;
        _folders = folders;
        _vulnerableApps = vulnerableApps;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _database.Initialize();
        _logger.LogInformation("Warden database ready at {Path}", _database.DatabasePath);

        await SeedVulnerableAppsAsync(stoppingToken).ConfigureAwait(false);

        _processStarts.ProcessStarted += _controller.RecordProcessStart;
        _processStarts.ProcessStarted += _tree.RecordStart;
        _blocks.BlockObserved += _controller.EnqueueBlock;

        // Telemetry panels: command-line recorder subscribes to the same process-start source; the
        // protected-folder monitor spins up its file watchers. Both are best-effort.
        SafeStart(_commandLines.Start, nameof(ICommandLineRecorder));
        SafeStart(_folders.Start, nameof(IProtectedFolderMonitor));

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
            SafeStop(_commandLines.Stop, nameof(ICommandLineRecorder));
            SafeStop(_folders.Stop, nameof(IProtectedFolderMonitor));
            _processStarts.ProcessStarted -= _controller.RecordProcessStart;
            _processStarts.ProcessStarted -= _tree.RecordStart;
            _blocks.BlockObserved -= _controller.EnqueueBlock;
            SafeStop(_processStarts.Stop, nameof(IProcessStartSource));
            SafeStop(_blocks.Stop, nameof(ICodeIntegrityBlockSource));
        }
    }

    /// <summary>
    /// Populate the Advanced panel's vulnerable-app list from the built-in seed (EP-reset ∪ LOLBAS) if it
    /// is empty. This only writes data rows — it applies no mitigation and changes nothing on the system.
    /// </summary>
    private async Task SeedVulnerableAppsAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (await _vulnerableApps.CountAsync(cancellationToken).ConfigureAwait(false) > 0)
            {
                return; // already seeded / user-curated
            }

            foreach (VulnerableApp app in VulnerableAppSeeder.Seed())
            {
                await _vulnerableApps.AddOrIgnoreAsync(new VulnerableAppRecord
                {
                    AppPath = app.FileName,
                    Reason = VulnerableAppSeeder.ReasonToString(app.Reason),
                    Publisher = null,
                }, cancellationToken).ConfigureAwait(false);
            }

            _logger.LogInformation("Seeded the vulnerable-app list (EP-reset ∪ LOLBAS).");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Vulnerable-app seeding failed (non-fatal).");
        }
    }

    private void SafeStart(Action start, string name)
    {
        try
        {
            start();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error starting {Component}", name);
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
