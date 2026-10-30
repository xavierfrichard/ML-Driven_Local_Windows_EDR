using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Warden.AntiExploit;
using Warden.AttackChain;
using Warden.Etw;
using Warden.Hardening;
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
    private readonly IRulesRepository _rules;
    private readonly HardeningOptions _hardening;
    private readonly DataDirectoryHardener _dirHardener;
    private readonly ITamperLog _tamperLog;
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
        IRulesRepository rules,
        HardeningOptions hardening,
        DataDirectoryHardener dirHardener,
        ITamperLog tamperLog,
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
        _rules = rules;
        _hardening = hardening;
        _dirHardener = dirHardener;
        _tamperLog = tamperLog;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Before anything reads or writes the data directory (database, WDAC files, ML model, quarantine).
        PrepareDataDirectory();

        _database.Initialize();
        _logger.LogInformation("Warden database ready at {Path}", _database.DatabasePath);

        await ApplyStartupHardeningAsync(stoppingToken).ConfigureAwait(false);
        await SeedVulnerableAppsAsync(stoppingToken).ConfigureAwait(false);
        await AuditFolderAllowRulesAsync(stoppingToken).ConfigureAwait(false);

        _processStarts.ProcessStarted += _controller.RecordProcessStart;
        _processStarts.ProcessStarted += _tree.RecordStart;
        _blocks.BlockObserved += _controller.EnqueueBlock;
        if (_blocks is CodeIntegritySession ciSession)
        {
            // A block Warden cannot parse is a block it never adjudicates — never let that be silent.
            ciSession.ParseFailed += (id, ex) =>
                _logger.LogWarning(ex, "Unparseable CodeIntegrity event {EventId}; the OS block stands but was not adjudicated.", id);
        }

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
    /// Makes sure the data directory can be trusted before the service uses it, and stops the service if it
    /// cannot (fail closed: a database or WDAC file someone else can edit could hold Allow rows).
    /// <list type="bullet">
    /// <item>Installed service (<c>WARDEN_ENFORCE_HARDENING=1</c>): refuse any junction, symlink, mount
    /// point or hard link in the tree, then reset the owner and ACLs of the whole tree to SYSTEM +
    /// Administrators and verify the result.</item>
    /// <item>Dev run: only refuse redirects; nothing is re-ACLed.</item>
    /// </list>
    /// A failure is logged as a critical tamper event to the log only: the <c>tamper_log</c> table lives in
    /// the directory that just failed. The exit code is set to 1 so the service's recovery actions retry.
    /// </summary>
    private void PrepareDataDirectory()
    {
        string dir = _hardening.DataDirectory;
        DataDirectoryReport report = _hardening.EnforceOnStartup
            ? _dirHardener.HardenDataDirectory(dir)
            : _dirHardener.VerifyDataDirectory(dir, requireTrustedOwnership: false);

        if (report.Success)
        {
            if (_hardening.EnforceOnStartup)
            {
                _logger.LogInformation("Data directory {Dir}: owner and access lists reset to SYSTEM + Administrators.", dir);
            }
            return;
        }

        string category = report.Redirects.Count > 0 ? "data-dir-redirect" : "data-dir-untrusted";
        _logger.LogCritical("TAMPER [{Category}] Refusing to use the data directory {Dir}: {Detail}", category, dir, report.Summary());
        Environment.ExitCode = 1;
        throw new InvalidOperationException($"Refusing to use the data directory {dir} ({category}).");
    }

    /// <summary>
    /// Installed service only (<c>WARDEN_ENFORCE_HARDENING=1</c>): lock the database file and check that
    /// nobody but SYSTEM, Administrators or TrustedInstaller owns or can write the code this LocalSystem
    /// process loads (its binaries, <c>dotnet.exe</c>, <c>hostfxr</c>, the shared runtime, and their parent
    /// folders). Each problem is a critical tamper event; the service keeps running.
    /// </summary>
    private async Task ApplyStartupHardeningAsync(CancellationToken cancellationToken)
    {
        if (!_hardening.EnforceOnStartup)
        {
            return;
        }

        try
        {
            if (!_dirHardener.HardenFile(_database.DatabasePath))
            {
                await _tamperLog.LogAsync("data-dir-lockdown-incomplete",
                    $"Could not lock the database file {_database.DatabasePath}.", "critical", cancellationToken)
                    .ConfigureAwait(false);
            }

            string? runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location);
            IReadOnlyList<string> problems = InstallSelfCheck.FindProblems(
                AppContext.BaseDirectory, Environment.ProcessPath, runtimeDir);
            foreach (string problem in problems)
            {
                await _tamperLog.LogAsync("install-dir-writable",
                    problem + @" Reinstall with installer/install.ps1 (which copies to %ProgramFiles%\Warden and locks it).",
                    "critical", cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Startup self-check failed.");
            await _tamperLog.LogAsync("startup-self-check-failed", ex.GetType().Name, "critical", cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Before any block is adjudicated, disable stored Folder → Allow rules on folders that non-administrators
    /// can change (rules saved before that check existed). Runs on every start, in dev runs too. If the audit
    /// itself fails, the folder allow rules stay as they were and the failure is recorded as a tamper event.
    /// </summary>
    private async Task AuditFolderAllowRulesAsync(CancellationToken cancellationToken)
    {
        try
        {
            int disabled = await FolderRuleAudit.DisableUnsafeFolderAllowsAsync(
                _rules, _tamperLog, _logger, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (disabled > 0)
            {
                _logger.LogWarning("Disabled {Count} folder allow rule(s) on folders non-administrators can change.", disabled);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Folder allow rule audit failed.");
            await _tamperLog.LogAsync("folder-allow-rule-audit-failed", ex.GetType().Name, "critical", cancellationToken)
                .ConfigureAwait(false);
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
