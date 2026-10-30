namespace Warden.Core;

/// <summary>Per-tier time budgets for <see cref="DecisionPipeline"/>.</summary>
public sealed class DecisionPipelineOptions
{
    /// <summary>Budget for any tier without an entry in <see cref="TierTimeouts"/>.</summary>
    public TimeSpan DefaultTierTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Per-tier overrides. The defaults leave room for each tier's own network budget: VirusTotal has a
    /// 10 s request timeout, and the LLM tier can run the Claude CLI for up to 90 s.
    /// </summary>
    public IDictionary<VerdictSourceKind, TimeSpan> TierTimeouts { get; } = new Dictionary<VerdictSourceKind, TimeSpan>
    {
        [VerdictSourceKind.VirusTotal] = TimeSpan.FromSeconds(30),
        [VerdictSourceKind.Llm] = TimeSpan.FromSeconds(150),
    };

    /// <summary>The budget for <paramref name="kind"/>.</summary>
    public TimeSpan TimeoutFor(VerdictSourceKind kind) =>
        TierTimeouts.TryGetValue(kind, out TimeSpan t) ? t : DefaultTierTimeout;
}

/// <summary>Passed to the error callback (never thrown to callers) when a tier runs past its budget.</summary>
public sealed class VerdictSourceTimeoutException : TimeoutException
{
    public VerdictSourceTimeoutException(VerdictSourceKind kind, TimeSpan budget)
        : base($"Verdict source {kind} did not answer within {budget.TotalSeconds:0.#} s; treated as undecided.")
    {
        Kind = kind;
        Budget = budget;
    }

    public VerdictSourceKind Kind { get; }

    public TimeSpan Budget { get; }
}

/// <summary>
/// Runs the ordered chain of <see cref="IVerdictSource"/> tiers and returns the first decisive
/// verdict, or a fail-safe <see cref="VerdictResult.PromptFallthrough"/> if none is decisive.
/// </summary>
/// <remarks>
/// <para>Registration order is the evaluation order and defines the policy — cheap, high-confidence
/// gates first (rules, trust, whitelist), expensive tiers last (VirusTotal, ML, LLM).</para>
/// <para>The pipeline is fail-safe by construction: a source that throws is treated as undecided and
/// the chain continues; if every source declines, the result is <see cref="Verdict.Prompt"/>, which
/// keeps the OS-level block in place. A bug in one tier can therefore never turn into a silent allow.</para>
/// <para><b>Time budgets.</b> Each tier runs on the thread pool and the pipeline waits at most
/// <see cref="DecisionPipelineOptions.TimeoutFor"/> for it. A tier that runs over is reported through the
/// error callback (as a <see cref="VerdictSourceTimeoutException"/>), its token is cancelled, and it is
/// treated as undecided. Synchronous work cannot be interrupted, so a stuck tier may keep a pool thread
/// busy, but the single decision loop is no longer stalled by it.</para>
/// <para><b>Byte pinning.</b> When the context is not byte-pinned (<see cref="VerdictContext.IsBytePinned"/>
/// is false: no immutable snapshot, so the bytes a tier inspected may differ from the bytes WDAC will
/// allow-list), an Allow from a content-inspecting tier is downgraded to <see cref="Verdict.Prompt"/>.
/// Only <see cref="VerdictSourceKind.Rules"/> and <see cref="VerdictSourceKind.Whitelist"/> may Allow
/// such a file, because their allows are keyed on the hash that WDAC re-checks.</para>
/// </remarks>
public sealed class DecisionPipeline
{
    private readonly IReadOnlyList<IVerdictSource> _sources;
    private readonly Action<VerdictSourceKind, Exception>? _onSourceError;
    private readonly DecisionPipelineOptions _options;

    /// <summary>
    /// Creates a pipeline over the given sources, evaluated in the order supplied.
    /// </summary>
    /// <param name="sources">The verdict tiers, cheapest/highest-confidence first.</param>
    /// <param name="onSourceError">
    /// Optional callback invoked when a source throws or runs past its budget. The source is then treated
    /// as undecided. Use this to log; do not throw from it.
    /// </param>
    /// <param name="options">Per-tier time budgets; defaults apply when null.</param>
    /// <exception cref="ArgumentNullException"><paramref name="sources"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="sources"/> is empty.</exception>
    public DecisionPipeline(
        IEnumerable<IVerdictSource> sources,
        Action<VerdictSourceKind, Exception>? onSourceError = null,
        DecisionPipelineOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sources);
        _sources = sources.ToList();
        if (_sources.Count == 0)
        {
            throw new ArgumentException("A decision pipeline needs at least one verdict source.", nameof(sources));
        }

        _onSourceError = onSourceError;
        _options = options ?? new DecisionPipelineOptions();
    }

    /// <summary>The tiers in evaluation order.</summary>
    public IReadOnlyList<IVerdictSource> Sources => _sources;

    /// <summary>
    /// True when an Allow from <paramref name="kind"/> is safe on a context that is not byte-pinned: the
    /// allow is keyed on the file hash, which WDAC re-checks at launch. Every other tier (including any
    /// added later) judges file content and must not Allow unpinned bytes.
    /// </summary>
    public static bool MayAllowUnpinned(VerdictSourceKind kind) =>
        kind is VerdictSourceKind.Rules or VerdictSourceKind.Whitelist;

    /// <summary>
    /// Evaluates <paramref name="context"/> against each source in order and returns the first
    /// decisive verdict, or <see cref="VerdictResult.PromptFallthrough"/> if none decides.
    /// </summary>
    /// <exception cref="OperationCanceledException">Cancellation was requested.</exception>
    public async ValueTask<VerdictResult> EvaluateAsync(
        VerdictContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var source in _sources)
        {
            cancellationToken.ThrowIfCancellationRequested();

            VerdictResult? result = await RunTierAsync(source, context, cancellationToken).ConfigureAwait(false);
            if (result is null || !result.Decisive)
            {
                continue;
            }

            if (result.Verdict == Verdict.Allow && !context.IsBytePinned && !MayAllowUnpinned(source.Kind))
            {
                // M7: the bytes this tier judged are not pinned to the bytes WDAC would allow-list.
                return new VerdictResult(
                    Verdict.Prompt,
                    source.Kind,
                    result.Confidence,
                    $"{source.Kind} would allow, but the file could not be snapshotted, so the inspected bytes "
                    + "are not pinned; asking the user instead (default: keep blocked).",
                    result.Reason);
            }

            return result;
        }

        return VerdictResult.PromptFallthrough;
    }

    /// <summary>Runs one tier within its budget. Returns null when it threw or timed out.</summary>
    private async Task<VerdictResult?> RunTierAsync(
        IVerdictSource source, VerdictContext context, CancellationToken cancellationToken)
    {
        TimeSpan budget = _options.TimeoutFor(source.Kind);
        using var tierCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Task.Run so a tier that blocks synchronously (PE parsing, WinVerifyTrust) cannot hold the loop:
        // the wait below can give up on it.
        Task<VerdictResult> task = Task.Run(
            () => source.EvaluateAsync(context, tierCts.Token).AsTask(),
            CancellationToken.None);

        try
        {
            if (budget > TimeSpan.Zero && budget != Timeout.InfiniteTimeSpan)
            {
                return await task.WaitAsync(budget, cancellationToken).ConfigureAwait(false);
            }
            return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            CancelQuietly(tierCts);
            ObserveLateFault(task);
            throw;
        }
        catch (TimeoutException) when (!task.IsCompleted)
        {
            CancelQuietly(tierCts);
            ObserveLateFault(task);
            _onSourceError?.Invoke(source.Kind, new VerdictSourceTimeoutException(source.Kind, budget));
            return null;
        }
        catch (Exception ex)
        {
            // Fail safe: a broken tier is skipped, never allowed to short-circuit into an allow.
            _onSourceError?.Invoke(source.Kind, ex);
            return null;
        }
    }

    private static void CancelQuietly(CancellationTokenSource cts)
    {
        try
        {
            cts.Cancel();
        }
        catch (AggregateException)
        {
            // A tier's cancellation callback threw; the tier is being abandoned anyway.
        }
    }

    /// <summary>An abandoned tier may fault later; observe it so it does not surface as an unobserved exception.</summary>
    private static void ObserveLateFault(Task task) =>
        _ = task.ContinueWith(
            static t => _ = t.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
}
