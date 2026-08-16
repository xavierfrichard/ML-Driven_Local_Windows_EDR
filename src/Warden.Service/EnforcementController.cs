using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Warden.AttackChain;
using Warden.Core;
using Warden.Etw;
using Warden.Ipc;
using Warden.Ml;
using Warden.Quarantine;
using Warden.Storage;
using Warden.Trust;
using Warden.Wdac;
using Warden.WebApps;

namespace Warden.Service;

/// <summary>
/// The Phase 1 enforcement loop. Consumes WDAC block events, correlates each with a recent
/// process-start (for command line + parent), builds a <see cref="VerdictContext"/>, runs the
/// <see cref="DecisionPipeline"/>, and applies the outcome: record the decision in the whitelist and,
/// on an allow, add a WDAC allow rule so the file runs on relaunch. Non-decisive results prompt the
/// user via <see cref="IPromptPresenter"/>; the fail-safe default is to keep the launch blocked.
/// </summary>
/// <remarks>
/// <para>Block events are handled one at a time on a dedicated loop (via a bounded <see cref="Channel{T}"/>)
/// so prompts never interleave and the WDAC policy is never regenerated concurrently. Process-start
/// records arrive on the ETW thread and land in a small locked ring buffer used only for correlation.</para>
/// <para><b>Snapshot first.</b> Before anything is inspected, the blocked image is copied into the
/// SYSTEM-only snapshot directory. Hash, signature, PE features and — on an allow — the WDAC rule are all
/// derived from that one immutable copy, so an attacker cannot swap the file between "judged" and
/// "allow-listed". Path-dependent facts (trusted-path, MOTW, owner) still use the original location.</para>
/// </remarks>
public sealed class EnforcementController
{
    private const int AutoDismissSeconds = 20;
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ParentLookupWindow = TimeSpan.FromMinutes(10);
    private const int MaxBufferedStarts = 1024;

    /// <summary>Block events queued but not yet handled; beyond this the oldest are dropped (and logged).</summary>
    private const int MaxQueuedBlocks = 512;

    /// <summary>Largest image that is snapshotted; bigger files are inspected in place (with the hash re-check at allow time).</summary>
    private const long MaxSnapshotBytes = 256L * 1024 * 1024;

    private readonly DecisionPipeline _pipeline;
    private readonly IFileInspector _inspector;
    private readonly IWdacAllowlistManager _wdac;
    private readonly IPromptPresenter _presenter;
    private readonly IWhitelistRepository _whitelist;
    private readonly IProcessTreeBuilder _tree;
    private readonly IQuarantineStore _quarantine;
    private readonly WebAppClassifier? _webApps;
    private readonly IPeFeaturesReader? _peReader;
    private readonly ILogger<EnforcementController> _logger;
    private readonly string _snapshotDir;

    private readonly Channel<CiBlockEvent> _blocks =
        Channel.CreateBounded<CiBlockEvent>(new BoundedChannelOptions(MaxQueuedBlocks)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropOldest,
        });

    private readonly object _startsGate = new();
    private readonly LinkedList<ProcessStartRecord> _recentStarts = new();
    private long _correlationCounter;
    private long _droppedBlocks;

    public EnforcementController(
        DecisionPipeline pipeline,
        IFileInspector inspector,
        IWdacAllowlistManager wdac,
        IPromptPresenter presenter,
        IWhitelistRepository whitelist,
        IProcessTreeBuilder tree,
        IQuarantineStore quarantine,
        ILogger<EnforcementController> logger,
        WebAppClassifier? webApps = null,
        string? snapshotDirectory = null,
        IPeFeaturesReader? peReader = null)
    {
        _pipeline = pipeline;
        _inspector = inspector;
        _wdac = wdac;
        _presenter = presenter;
        _whitelist = whitelist;
        _tree = tree;
        _quarantine = quarantine;
        _webApps = webApps;
        _peReader = peReader;
        _logger = logger;
        _snapshotDir = snapshotDirectory ?? WardenPaths.Under("snapshots");
    }

    /// <summary>Records a process start for later correlation (called from the ETW thread).</summary>
    public void RecordProcessStart(ProcessStartRecord start)
    {
        lock (_startsGate)
        {
            _recentStarts.AddLast(start);
            while (_recentStarts.Count > MaxBufferedStarts)
            {
                _recentStarts.RemoveFirst();
            }
        }
    }

    /// <summary>Queues a WDAC block event for handling (called from the CodeIntegrity watcher thread).</summary>
    public void EnqueueBlock(CiBlockEvent block)
    {
        if (!_blocks.Writer.TryWrite(block))
        {
            // Bounded + DropOldest never refuses, but keep the accounting honest should the mode change.
            Interlocked.Increment(ref _droppedBlocks);
        }
    }

    /// <summary>Runs the block-handling loop until cancellation.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Enforcement loop started.");
        try
        {
            Directory.CreateDirectory(_snapshotDir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Snapshot directory {Dir} unavailable; images will be inspected in place.", _snapshotDir);
        }

        try
        {
            await foreach (var block in _blocks.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    await HandleBlockAsync(block, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed handling block for {Path}", block.BlockedFilePath);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        _logger.LogInformation("Enforcement loop stopped.");
    }

    private async Task HandleBlockAsync(CiBlockEvent block, CancellationToken ct)
    {
        VerdictContext ctx = BuildContext(block, out ProcessStartRecord? correlated);
        try
        {
            VerdictResult result = await _pipeline.EvaluateAsync(ctx, ct).ConfigureAwait(false);

            _logger.LogInformation(
                "Block {Mode} {File}: pipeline -> {Verdict} ({Source}: {Reason})",
                block.Mode, ctx.ImageName, result.Verdict, result.Source, result.Reason);

            switch (result.Verdict)
            {
                case Verdict.Allow:
                    await ApplyAllowAsync(ctx, result.Source.ToString(), ct).ConfigureAwait(false);
                    break;

                case Verdict.Block:
                    await RecordAsync(ctx, PolicyAction.Block, result.Source.ToString(), ct).ConfigureAwait(false);
                    break;

                case Verdict.Quarantine:
                    await ApplyQuarantineAsync(ctx, result.Source.ToString(), ct).ConfigureAwait(false);
                    break;

                case Verdict.Prompt:
                default:
                    await PromptAsync(ctx, result, block, ct).ConfigureAwait(false);
                    break;
            }

            // Always-ON Web Apps classification of the blocked image (read-only; feeds the Web Apps panel).
            // Best-effort — it must never affect the enforcement outcome.
            await ClassifyWebAppBestEffortAsync(ctx.ImagePath, ct).ConfigureAwait(false);
        }
        finally
        {
            DeleteSnapshot(ctx.SnapshotPath);
        }
    }

    private async Task ClassifyWebAppBestEffortAsync(string appPath, CancellationToken ct)
    {
        if (_webApps is null || string.IsNullOrEmpty(appPath))
        {
            return;
        }
        try
        {
            await _webApps.ClassifyAsync(appPath, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Web-app classification failed for {File}", Path.GetFileName(appPath));
        }
    }

    private async Task PromptAsync(VerdictContext ctx, VerdictResult result, CiBlockEvent block, CancellationToken ct)
    {
        var request = new PromptRequest(
            RequestId: Guid.NewGuid(),
            Sha256: ctx.Sha256,
            ImagePath: ctx.ImagePath,
            FileName: ctx.ImageName,
            CommandLine: ctx.CommandLine,
            ParentPath: ctx.ParentPath,
            SignerSummary: DescribeSigner(ctx.Signer),
            MotwZone: ctx.MotwZone,
            Reason: result.Reason,
            BlockMode: block.Mode,
            MlScore: null,
            LlmVerdict: null,
            Timestamp: ctx.Timestamp,
            AutoDismissSeconds: AutoDismissSeconds);

        PromptResponse response = await _presenter.PromptAsync(request, ct).ConfigureAwait(false);
        _logger.LogInformation("User decision for {File}: {Decision}", ctx.ImageName, response.Decision);

        switch (response.Decision)
        {
            case PromptDecision.Allow:
                await ApplyAllowAsync(ctx, VerdictSourceKind.UserPrompt.ToString(), ct).ConfigureAwait(false);
                break;

            case PromptDecision.Quarantine:
                await ApplyQuarantineAsync(ctx, VerdictSourceKind.UserPrompt.ToString(), ct).ConfigureAwait(false);
                break;

            case PromptDecision.KeepBlocked:
                await RecordAsync(ctx, PolicyAction.Block, VerdictSourceKind.UserPrompt.ToString(), ct).ConfigureAwait(false);
                break;

            case PromptDecision.Timeout:
            default:
                // Nobody decided (auto-dismiss, no UI, disconnect). The OS block stands, but do NOT persist a
                // Block — that would silently make the file permanently blocked and never ask again.
                _logger.LogInformation("Prompt for {File} was not answered; keeping blocked without recording a decision.", ctx.ImageName);
                break;
        }
    }

    private async Task ApplyAllowAsync(VerdictContext ctx, string source, CancellationToken ct)
    {
        // Deploy first, record second: the whitelist must never claim an Allow that WDAC did not accept.
        var request = new WdacAllowRequest(
            ImagePath: ctx.BytesPath,
            Sha256: ctx.Sha256,
            SignerSubject: ctx.Signer.SubjectName,
            PreferPublisher: ctx.Signer.IsTrustedSignature);

        WdacUpdateResult update = await _wdac.AllowAsync(request, ct).ConfigureAwait(false);
        if (update.Success)
        {
            _logger.LogInformation(
                "WDAC allow deployed for {File}: {Rule} (policy {Policy}); relaunch to run.",
                ctx.ImageName, update.RuleAdded, update.PolicyGuid);
            await RecordAsync(ctx, PolicyAction.Allow, source, ct).ConfigureAwait(false);
        }
        else
        {
            _logger.LogError("WDAC allow FAILED for {File}: {Error}", ctx.ImageName, update.Error);
            // Not recorded as Allow (the OS still blocks it) and not recorded as Block (a human may retry).
        }
    }

    private async Task ApplyQuarantineAsync(VerdictContext ctx, string source, CancellationToken ct)
    {
        // The launch is already blocked by WDAC; quarantine additionally removes the file. Record the
        // real outcome (distinct source) rather than downgrading a failure to a plain block.
        QuarantineResult result = await _quarantine
            .QuarantineAsync(ctx.ImagePath, $"Quarantined by {source}", source, ct)
            .ConfigureAwait(false);

        if (result.Success)
        {
            _logger.LogWarning("Quarantined {File} -> {Dest}", ctx.ImageName, result.QuarantinePath);
            await RecordAsync(ctx, PolicyAction.Block, $"{source}/Quarantined", ct).ConfigureAwait(false);
        }
        else
        {
            _logger.LogError("Quarantine FAILED for {File}: {Error}", ctx.ImageName, result.Error);
            await RecordAsync(ctx, PolicyAction.Block, $"{source}/QuarantineFailed", ct).ConfigureAwait(false);
        }
    }

    private async Task RecordAsync(VerdictContext ctx, PolicyAction action, string source, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(ctx.Sha256))
        {
            // Nothing to key the row on; a hash-less row would never be matched again.
            _logger.LogWarning("Not recording {Action} for {File}: no hash.", action, ctx.ImageName);
            return;
        }

        var entry = new WhitelistEntry
        {
            Timestamp = ctx.Timestamp,
            Action = action,
            ProcessName = ctx.ImageName,
            ProcessPath = ctx.ImagePath,
            Sha256 = ctx.Sha256,
            SignerSubject = ctx.Signer.SubjectName,
            SignerIssuer = ctx.Signer.IssuerName,
            CertThumbprint = ctx.Signer.Thumbprint,
            CommandLine = ctx.CommandLine,
            FileSize = _inspector.GetFileSize(ctx.BytesPath),
            ParentName = string.IsNullOrEmpty(ctx.ParentPath) ? null : Path.GetFileName(ctx.ParentPath),
            ParentPath = string.IsNullOrEmpty(ctx.ParentPath) ? null : ctx.ParentPath,
            Source = source,
        };

        try
        {
            await _whitelist.AddAsync(entry, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed writing whitelist row for {File}", ctx.ImageName);
        }
    }

    private VerdictContext BuildContext(CiBlockEvent block, out ProcessStartRecord? correlated)
    {
        string path = block.BlockedFilePath;

        // 1) Snapshot the bytes before anything looks at them.
        string? snapshot = TrySnapshot(path, block.TimeCreated);
        string bytesPath = snapshot ?? path;

        // 2) Byte-level facts come from the snapshot; location facts from the original path.
        // Deliberately NO fallback to the CI event's Authenticode hash: it is a different digest and would
        // silently poison the flat-hash whitelist. An unreadable file simply has no hash (tiers defer).
        string sha = _inspector.ComputeSha256(bytesPath) ?? string.Empty;
        SignerInfo signer = _inspector.ReadSigner(bytesPath);
        int motw = _inspector.ReadMotwZone(path);

        // Only audit blocks (3076) leave a running process to correlate; enforce (3077) never starts one.
        correlated = block.EventId == 3076 ? FindMatchingStart(block) : null;

        string cmdline = correlated?.CommandLine ?? string.Empty;
        int pid = correlated?.Pid ?? 0;
        int parentPid = correlated?.ParentPid ?? 0;
        string parentPath = correlated is null
            ? block.ProcessName // the loader/requestor named by the CI event
            : ResolveParentPath(correlated.ParentPid, correlated.Timestamp);

        return new VerdictContext(
            Sha256: sha,
            ImagePath: path,
            CommandLine: cmdline,
            Pid: pid,
            ParentPid: parentPid,
            ParentPath: parentPath,
            ParentSha256: null,
            Signer: signer,
            MotwZone: motw,
            // Real PE facts (imports, sections, entropy) for the LLM dossier / web-app classifier, parsed
            // lazily from the snapshot; without a reader (tests) the tiers see "not a PE".
            Pe: new Lazy<PeFeatures>(() => _peReader?.Read(bytesPath) ?? PeFeatures.NotPortableExecutable),
            Chain: correlated is not null ? _tree.BuildChainFor(correlated.Pid) : AttackChainNode.None,
            Timestamp: block.TimeCreated,
            CorrelationId: NextCorrelationId(block))
        {
            SnapshotPath = snapshot,
        };
    }

    /// <summary>
    /// Copies the image into the snapshot directory. Returns null (inspect in place) when the file is
    /// missing, unreadable, a reparse point, oversized, or the snapshot directory is unavailable.
    /// </summary>
    private string? TrySnapshot(string path, DateTimeOffset when)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                return null;
            }

            var info = new FileInfo(path);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                _logger.LogWarning("Not snapshotting {File}: reparse point.", path);
                return null;
            }
            if (info.Length > MaxSnapshotBytes)
            {
                _logger.LogInformation("Not snapshotting {File}: {Size} bytes exceeds the cap.", path, info.Length);
                return null;
            }

            string name = $"{when.ToUnixTimeMilliseconds()}_{Guid.NewGuid():N}_{Path.GetFileName(path)}";
            string dest = Path.Combine(_snapshotDir, name);
            File.Copy(path, dest, overwrite: false);
            return dest;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            _logger.LogWarning(ex, "Could not snapshot {File}; inspecting in place.", path);
            return null;
        }
    }

    private void DeleteSnapshot(string? snapshot)
    {
        if (snapshot is null)
        {
            return;
        }
        try
        {
            File.Delete(snapshot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not delete snapshot {Snapshot}.", snapshot);
        }
    }

    /// <summary>
    /// Correlates a block with a recent process start by <b>full path</b> only. A file-name-only match would
    /// let an attacker start a same-named decoy elsewhere and have its command line / parent / ancestry
    /// attributed to the blocked file (i.e. steer the evidence the ML/LLM tiers and the user see).
    /// </summary>
    private ProcessStartRecord? FindMatchingStart(CiBlockEvent block)
    {
        lock (_startsGate)
        {
            for (var node = _recentStarts.Last; node is not null; node = node.Previous)
            {
                ProcessStartRecord s = node.Value;
                if (PathUtil.PathsEqualStrict(s.ImagePath, block.BlockedFilePath) &&
                    (block.TimeCreated - s.Timestamp).Duration() <= CorrelationWindow)
                {
                    return s;
                }
            }
        }
        return null;
    }

    /// <summary>Resolves a parent PID to its image, only among starts that precede the child within a bounded window (PIDs are recycled).</summary>
    private string ResolveParentPath(int parentPid, DateTimeOffset childStart)
    {
        lock (_startsGate)
        {
            for (var node = _recentStarts.Last; node is not null; node = node.Previous)
            {
                ProcessStartRecord s = node.Value;
                if (s.Pid == parentPid && s.Timestamp <= childStart && childStart - s.Timestamp <= ParentLookupWindow)
                {
                    return s.ImagePath;
                }
            }
        }
        return string.Empty;
    }

    private ulong NextCorrelationId(CiBlockEvent block)
    {
        ulong seq = (ulong)Interlocked.Increment(ref _correlationCounter);
        return ((ulong)block.TimeCreated.ToUnixTimeSeconds() << 20) ^ seq;
    }

    private static string DescribeSigner(SignerInfo signer)
    {
        if (!signer.IsSigned)
        {
            return "unsigned (or catalog-signed)";
        }
        // "INVALID" here means the embedded signature does not verify for these bytes (e.g. a certificate
        // copied from another binary) — say so plainly, because that is a strong malicious indicator.
        string trust = signer.IsValid ? "verified" : "INVALID SIGNATURE — does not match file";
        string ms = signer.IsMicrosoft ? ", Microsoft" : string.Empty;
        return $"{signer.SubjectCommonName ?? signer.SubjectName} ({trust}{ms})";
    }
}
