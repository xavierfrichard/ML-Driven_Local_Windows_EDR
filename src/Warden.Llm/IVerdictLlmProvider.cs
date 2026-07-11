namespace Warden.Llm;

/// <summary>
/// One LLM backend that turns a <see cref="Dossier"/> into a structured <see cref="LlmVerdict"/> via a
/// forced tool/JSON call. Implementations are consulted by <see cref="LlmVerdictSource"/> in
/// <see cref="Priority"/> order; the first <see cref="IsEnabled"/> provider that returns a non-null
/// verdict wins (giving both config-priority and runtime fallback).
/// </summary>
public interface IVerdictLlmProvider
{
    /// <summary>Short provider name for logs and the verdict rationale (e.g. "anthropic", "local").</summary>
    string Name { get; }

    /// <summary>Lower is tried first. Anthropic API (0) &lt; local (10) &lt; Claude Code OAuth (20).</summary>
    int Priority { get; }

    /// <summary>True when the provider is configured (has credentials / is enabled).</summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Analyze a dossier. Returns null on any failure (disabled, network error, non-2xx, refusal, or an
    /// unparseable response) so the source falls through to the next provider or to the user prompt —
    /// a provider failure can never become a silent allow.
    /// </summary>
    /// <param name="dossier">The typed, capped dossier (delivered to the model strictly as data).</param>
    /// <param name="escalate">True to use the stronger/escalation model where the provider supports one.</param>
    Task<LlmVerdict?> AnalyzeAsync(Dossier dossier, bool escalate, CancellationToken cancellationToken);
}
