namespace Warden.Core;

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
/// </remarks>
public sealed class DecisionPipeline
{
    private readonly IReadOnlyList<IVerdictSource> _sources;
    private readonly Action<VerdictSourceKind, Exception>? _onSourceError;

    /// <summary>
    /// Creates a pipeline over the given sources, evaluated in the order supplied.
    /// </summary>
    /// <param name="sources">The verdict tiers, cheapest/highest-confidence first.</param>
    /// <param name="onSourceError">
    /// Optional callback invoked when a source throws. The source is then treated as undecided.
    /// Use this to log; do not throw from it.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="sources"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="sources"/> is empty.</exception>
    public DecisionPipeline(
        IEnumerable<IVerdictSource> sources,
        Action<VerdictSourceKind, Exception>? onSourceError = null)
    {
        ArgumentNullException.ThrowIfNull(sources);
        _sources = sources.ToList();
        if (_sources.Count == 0)
        {
            throw new ArgumentException("A decision pipeline needs at least one verdict source.", nameof(sources));
        }

        _onSourceError = onSourceError;
    }

    /// <summary>The tiers in evaluation order.</summary>
    public IReadOnlyList<IVerdictSource> Sources => _sources;

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

            VerdictResult result;
            try
            {
                result = await source.EvaluateAsync(context, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Fail safe: a broken tier is skipped, never allowed to short-circuit into an allow.
                _onSourceError?.Invoke(source.Kind, ex);
                continue;
            }

            if (result.Decisive)
            {
                return result;
            }
        }

        return VerdictResult.PromptFallthrough;
    }
}
