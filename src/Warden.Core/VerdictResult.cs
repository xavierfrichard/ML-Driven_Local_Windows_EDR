namespace Warden.Core;

/// <summary>
/// The result of evaluating a single <see cref="IVerdictSource"/>, or of running the whole pipeline.
/// A result is <see cref="Decisive"/> when its verdict is anything other than <see cref="Verdict.Unknown"/>.
/// </summary>
/// <param name="Verdict">The verdict this source assigned.</param>
/// <param name="Source">Which tier produced the verdict.</param>
/// <param name="Confidence">Confidence in [0,1]. Deterministic gates use 1.0; probabilistic tiers (ML/LLM) report their score.</param>
/// <param name="Reason">Short human-readable justification, surfaced in logs and the UI.</param>
/// <param name="Detail">Optional longer rationale (e.g. the LLM's evidence list), surfaced on demand.</param>
public sealed record VerdictResult(
    Verdict Verdict,
    VerdictSourceKind Source,
    double Confidence,
    string Reason,
    string? Detail = null)
{
    /// <summary>True when this source reached a decision and the pipeline should stop.</summary>
    public bool Decisive => Verdict != Verdict.Unknown;

    /// <summary>
    /// A non-decisive result: the source has no opinion and the pipeline continues.
    /// </summary>
    public static VerdictResult Undecided(VerdictSourceKind source, string reason) =>
        new(Verdict.Unknown, source, 0d, reason);

    /// <summary>
    /// The pipeline's fail-safe fallthrough: no source was decisive, so keep the launch blocked and prompt.
    /// </summary>
    public static readonly VerdictResult PromptFallthrough = new(
        Verdict.Prompt,
        VerdictSourceKind.Fallthrough,
        1d,
        "No decisive verdict source; prompting the user (default: keep blocked).");
}
