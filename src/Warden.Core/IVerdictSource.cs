namespace Warden.Core;

/// <summary>
/// One tier of the decision pipeline. Sources are ordered cheap-to-expensive and consulted in turn
/// until one returns a <see cref="VerdictResult.Decisive"/> result.
/// </summary>
/// <remarks>
/// A source that has no opinion must return <see cref="VerdictResult.Undecided"/> (verdict
/// <see cref="Verdict.Unknown"/>) so the pipeline continues. Because the fallthrough is
/// <see cref="Verdict.Prompt"/> (deny-and-ask), a source that declines — or throws — never causes a
/// silent allow, which is what makes the pipeline fail safe.
/// </remarks>
public interface IVerdictSource
{
    /// <summary>Which tier this source represents (used for logging and result attribution).</summary>
    VerdictSourceKind Kind { get; }

    /// <summary>
    /// Evaluate a blocked launch. Return a decisive verdict to stop the pipeline, or
    /// <see cref="VerdictResult.Undecided"/> to defer to the next source.
    /// </summary>
    ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken);
}
