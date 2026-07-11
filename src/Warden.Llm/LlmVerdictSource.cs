using Microsoft.Extensions.Logging;
using Warden.Core;

namespace Warden.Llm;

/// <summary>
/// LLM analyst tier of the decision pipeline (tier 6, the last before the user prompt). Builds a typed
/// dossier and asks the highest-priority enabled provider for a structured verdict, falling back to the
/// next provider if one fails. Decisive only when the model is confidently malicious (block) or —
/// opt-in — confidently benign (allow); everything else defers to the prompt. When no provider is
/// enabled the tier is silent, so the pipeline is unchanged until an LLM is configured.
/// </summary>
public sealed class LlmVerdictSource : IVerdictSource
{
    private readonly IReadOnlyList<IVerdictLlmProvider> _providers;
    private readonly DossierBuilder _dossierBuilder;
    private readonly LlmOptions _options;
    private readonly ILogger<LlmVerdictSource> _logger;

    public LlmVerdictSource(
        IEnumerable<IVerdictLlmProvider> providers,
        DossierBuilder dossierBuilder,
        LlmOptions options,
        ILogger<LlmVerdictSource> logger)
    {
        _providers = providers.OrderBy(p => p.Priority).ToArray();
        _dossierBuilder = dossierBuilder;
        _options = options;
        _logger = logger;
    }

    public VerdictSourceKind Kind => VerdictSourceKind.Llm;

    public async ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        // Cheap gate first: if no provider is enabled, do not build the dossier (which reads the file).
        if (!_providers.Any(p => p.IsEnabled))
        {
            return VerdictResult.Undecided(Kind, "LLM analyst disabled (no provider configured).");
        }

        Dossier dossier;
        try
        {
            dossier = _dossierBuilder.Build(context);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to build LLM dossier for {File}.", context.ImageName);
            return VerdictResult.Undecided(Kind, "Dossier build error.");
        }

        bool escalate = _options.AlwaysEscalate || context.IsFromInternet;

        foreach (IVerdictLlmProvider provider in _providers)
        {
            if (!provider.IsEnabled)
            {
                continue;
            }

            LlmVerdict? verdict;
            try
            {
                verdict = await provider.AnalyzeAsync(dossier, escalate, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw; // caller asked to cancel — propagate
            }
            catch (Exception ex)
            {
                // A misbehaving provider must not abort the fallback chain. The built-in providers
                // already demote failures to null; this guards a custom provider that throws.
                _logger.LogWarning(ex, "LLM provider {Provider} threw; falling through to the next.", provider.Name);
                continue;
            }

            if (verdict is null)
            {
                continue; // provider failed / had no opinion — try the next
            }

            return Map(verdict, provider.Name);
        }

        return VerdictResult.Undecided(Kind, "No LLM provider produced a verdict.");
    }

    private VerdictResult Map(LlmVerdict verdict, string providerName)
    {
        string detail = verdict.Describe(providerName);

        switch (verdict.Disposition)
        {
            case LlmDisposition.Malicious when verdict.Confidence >= _options.MaliciousConfidenceThreshold:
                return new VerdictResult(Verdict.Block, Kind, verdict.Confidence,
                    $"LLM analyst ({providerName}): malicious at {verdict.Confidence:F2} confidence.", detail);

            // Auto-allow requires a verdict that came through the forced tool call. A "benign" scraped
            // from free-form content (the local content fallback) can never clear a block — it defers.
            case LlmDisposition.Benign when _options.AllowOnBenign
                    && verdict.FromToolCall && verdict.Confidence >= _options.BenignConfidenceThreshold:
                return new VerdictResult(Verdict.Allow, Kind, verdict.Confidence,
                    $"LLM analyst ({providerName}): benign at {verdict.Confidence:F2} confidence.", detail);

            case LlmDisposition.Suspicious when _options.BlockOnSuspicious:
            case LlmDisposition.Malicious when _options.BlockOnSuspicious:
                // Low-confidence malicious is treated as suspicious; block only if configured to.
                return new VerdictResult(Verdict.Block, Kind, verdict.Confidence,
                    $"LLM analyst ({providerName}): {verdict.Disposition.ToString().ToLowerInvariant()} (block-on-suspicious).", detail);

            default:
                // Not decisive → keep blocked and fall through to the user prompt.
                return VerdictResult.Undecided(Kind,
                    $"LLM analyst ({providerName}): {verdict.Disposition.ToString().ToLowerInvariant()} at {verdict.Confidence:F2}; deferring to prompt.");
        }
    }
}
