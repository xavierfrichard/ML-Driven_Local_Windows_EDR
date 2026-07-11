using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Warden.AttackChain;
using Warden.Core;
using Warden.Etw;
using Warden.Ipc;
using Warden.Quarantine;
using Warden.Storage;
using Warden.Trust;
using Warden.Wdac;

namespace Warden.Service;

/// <summary>
/// The Phase 1 enforcement loop. Consumes WDAC block events, correlates each with a recent
/// process-start (for command line + parent), builds a <see cref="VerdictContext"/>, runs the
/// <see cref="DecisionPipeline"/>, and applies the outcome: record the decision in the whitelist and,
/// on an allow, add a WDAC allow rule so the file runs on relaunch. Non-decisive results prompt the
/// user via <see cref="IPromptPresenter"/>; the fail-safe default is to keep the launch blocked.
/// </summary>
/// <remarks>
/// Block events are handled one at a time on a dedicated loop (via a <see cref="Channel{T}"/>) so
/// prompts never interleave and the WDAC policy is never regenerated concurrently. Process-start
/// records arrive on the ETW thread and land in a small locked ring buffer used only for correlation.
/// </remarks>
public sealed class EnforcementController
{
    private const int AutoDismissSeconds = 20;
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(5);
    private const int MaxBufferedStarts = 1024;

    private readonly DecisionPipeline _pipeline;
    private readonly IFileInspector _inspector;
    private readonly IWdacAllowlistManager _wdac;
    private readonly IPromptPresenter _presenter;
    private readonly IWhitelistRepository _whitelist;
    private readonly IProcessTreeBuilder _tree;
    private readonly IQuarantineStore _quarantine;
    private readonly ILogger<EnforcementController> _logger;

    private readonly Channel<CiBlockEvent> _blocks =
        Channel.CreateUnbounded<CiBlockEvent>(new UnboundedChannelOptions { SingleReader = true });

    private readonly object _startsGate = new();
    private readonly LinkedList<ProcessStartRecord> _recentStarts = new();
    private long _correlationCounter;

    public EnforcementController(
        DecisionPipeline pipeline,
        IFileInspector inspector,
        IWdacAllowlistManager wdac,
        IPromptPresenter presenter,
        IWhitelistRepository whitelist,
        IProcessTreeBuilder tree,
        IQuarantineStore quarantine,
        ILogger<EnforcementController> logger)
    {
        _pipeline = pipeline;
        _inspector = inspector;
        _wdac = wdac;
        _presenter = presenter;
        _whitelist = whitelist;
        _tree = tree;
        _quarantine = quarantine;
        _logger = logger;
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
    public void EnqueueBlock(CiBlockEvent block) => _blocks.Writer.TryWrite(block);

    /// <summary>Runs the block-handling loop until cancellation.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Enforcement loop started.");
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
            default:
                await RecordAsync(ctx, PolicyAction.Block, VerdictSourceKind.UserPrompt.ToString(), ct).ConfigureAwait(false);
                break;
        }
    }

    private async Task ApplyAllowAsync(VerdictContext ctx, string source, CancellationToken ct)
    {
        await RecordAsync(ctx, PolicyAction.Allow, source, ct).ConfigureAwait(false);

        var request = new WdacAllowRequest(
            ImagePath: ctx.ImagePath,
            Sha256: ctx.Sha256,
            SignerSubject: ctx.Signer.SubjectName,
            PreferPublisher: ctx.Signer.IsTrustedSignature);

        WdacUpdateResult update = await _wdac.AllowAsync(request, ct).ConfigureAwait(false);
        if (update.Success)
        {
            _logger.LogInformation(
                "WDAC allow deployed for {File}: {Rule} (policy {Policy}); relaunch to run.",
                ctx.ImageName, update.RuleAdded, update.PolicyGuid);
        }
        else
        {
            _logger.LogError("WDAC allow FAILED for {File}: {Error}", ctx.ImageName, update.Error);
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
            FileSize = _inspector.GetFileSize(ctx.ImagePath),
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
        string sha = _inspector.ComputeSha256(path)
                     ?? (string.IsNullOrEmpty(block.Sha256Authenticode) ? string.Empty : block.Sha256Authenticode);
        SignerInfo signer = _inspector.ReadSigner(path);
        int motw = _inspector.ReadMotwZone(path);

        // Only audit blocks (3076) leave a running process to correlate; enforce (3077) never starts one.
        correlated = block.EventId == 3076 ? FindMatchingStart(block) : null;

        string cmdline = correlated?.CommandLine ?? string.Empty;
        int pid = correlated?.Pid ?? 0;
        int parentPid = correlated?.ParentPid ?? 0;
        string parentPath = correlated is null
            ? block.ProcessName // the loader/requestor named by the CI event
            : ResolveParentPath(correlated.ParentPid);

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
            Pe: new Lazy<PeFeatures>(() => PeFeatures.NotPortableExecutable),
            Chain: correlated is not null ? _tree.BuildChainFor(correlated.Pid) : AttackChainNode.None,
            Timestamp: block.TimeCreated,
            CorrelationId: NextCorrelationId(block));
    }

    private ProcessStartRecord? FindMatchingStart(CiBlockEvent block)
    {
        lock (_startsGate)
        {
            for (var node = _recentStarts.Last; node is not null; node = node.Previous)
            {
                ProcessStartRecord s = node.Value;
                if (PathUtil.PathsEqual(s.ImagePath, block.BlockedFilePath) &&
                    (block.TimeCreated - s.Timestamp).Duration() <= CorrelationWindow)
                {
                    return s;
                }
            }
        }
        return null;
    }

    private string ResolveParentPath(int parentPid)
    {
        lock (_startsGate)
        {
            for (var node = _recentStarts.Last; node is not null; node = node.Previous)
            {
                if (node.Value.Pid == parentPid)
                {
                    return node.Value.ImagePath;
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
        string trust = signer.IsValid ? "valid" : "INVALID";
        string ms = signer.IsMicrosoft ? ", Microsoft" : string.Empty;
        return $"{signer.SubjectName} ({trust}{ms})";
    }
}
