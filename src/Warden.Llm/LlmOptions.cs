namespace Warden.Llm;

/// <summary>
/// Configuration for the LLM analyst tier (pipeline tier 6, the last before the user prompt).
/// The tier is <b>disabled</b> until at least one provider is configured, so the pipeline runs
/// unchanged out of the box. Provider selection is by priority: Anthropic API first, then the local
/// OpenAI-compatible endpoint, then the off-by-default Claude Code OAuth provider.
/// </summary>
public sealed class LlmOptions
{
    // ---- Anthropic API provider (the supported backend for any distributed build) ----------------

    /// <summary>Anthropic API key. When null/empty the Anthropic provider is disabled.</summary>
    public string? AnthropicApiKey { get; set; }

    /// <summary>Base address of the Anthropic API.</summary>
    public Uri AnthropicBaseAddress { get; set; } = new("https://api.anthropic.com/");

    /// <summary>The <c>anthropic-version</c> header value.</summary>
    public string AnthropicVersion { get; set; } = "2023-06-01";

    /// <summary>Default model for volume classification (cheap tier).</summary>
    public string Model { get; set; } = "claude-haiku-4-5";

    /// <summary>Stronger model used for escalated (ambiguous / internet-origin) samples.</summary>
    public string EscalationModel { get; set; } = "claude-sonnet-5";

    // ---- Local (Ollama / llama.cpp, OpenAI-compatible) provider -----------------------------------

    /// <summary>Enable the local OpenAI-compatible provider (offline, free).</summary>
    public bool EnableLocal { get; set; }

    /// <summary>Base address of the local OpenAI-compatible server (Ollama's default shown).</summary>
    public Uri LocalBaseAddress { get; set; } = new("http://localhost:11434/");

    /// <summary>Model name/tag on the local server (e.g. a security-tuned Llama-3.1-8B). User-set.</summary>
    public string LocalModel { get; set; } = "foundation-sec-8b";

    /// <summary>Optional bearer key for the local endpoint (most local servers need none).</summary>
    public string? LocalApiKey { get; set; }

    // ---- Claude Code OAuth provider — PERSONAL MACHINE ONLY ----------------------------------------
    // Uses a Claude Pro/Max subscription OAuth token as a backend. That is against Anthropic's terms
    // for product/backend use (see README.md); this provider is DISABLED by default and must never be
    // the default in a distributed build. Distributed builds use the API key or a local model.

    /// <summary>Enable the Claude Code OAuth provider. Off by default; personal use only.</summary>
    public bool EnableClaudeCodeOAuth { get; set; }

    /// <summary>The <c>CLAUDE_CODE_OAUTH_TOKEN</c> value (personal machine only).</summary>
    public string? ClaudeCodeOAuthToken { get; set; }

    // ---- Request shape ----------------------------------------------------------------------------

    /// <summary>Max output tokens. The forced-JSON verdict is small; the default is generous.</summary>
    public int MaxTokens { get; set; } = 1024;

    /// <summary>Per-request timeout applied via a linked cancellation token.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Send <c>strict: true</c> on the Anthropic tool so the verdict input is schema-validated. Off
    /// only if a proxy/model rejects strict tool use. The schema is strict-compliant regardless.
    /// </summary>
    public bool UseStrictToolSchema { get; set; } = true;

    // ---- Verdict → pipeline mapping ---------------------------------------------------------------

    /// <summary>Block decisively only when the model reports "malicious" at/above this confidence.</summary>
    public double MaliciousConfidenceThreshold { get; set; } = 0.70;

    /// <summary>Treat a "suspicious" verdict as a decisive block. Off by default (defers to the prompt).</summary>
    public bool BlockOnSuspicious { get; set; }

    /// <summary>
    /// Allow decisively on a confident "benign" verdict. Off by default — like the other tiers, the
    /// analyst only ever blocks and lets unknowns fall through to the user, so a model error or an
    /// injection can never auto-allow. Enable to let the analyst clear confident-benign unknowns.
    /// </summary>
    public bool AllowOnBenign { get; set; }

    /// <summary>Minimum confidence for a "benign" verdict to auto-allow (only when <see cref="AllowOnBenign"/>).</summary>
    public double BenignConfidenceThreshold { get; set; } = 0.85;

    /// <summary>Always use <see cref="EscalationModel"/>. Off by default; only internet-origin files escalate.</summary>
    public bool AlwaysEscalate { get; set; }

    // ---- Dossier caps (prompt-injection defense: every free-text field is capped, delivered as data) -

    /// <summary>Maximum number of extracted printable strings placed in the dossier.</summary>
    public int MaxDossierStrings { get; set; } = 40;

    /// <summary>Maximum characters kept per extracted string / per free-text field.</summary>
    public int MaxStringLength { get; set; } = 160;

    /// <summary>Maximum characters kept from a command line.</summary>
    public int MaxCommandLineLength { get; set; } = 2048;

    /// <summary>Maximum ancestry depth included from the attack chain.</summary>
    public int MaxChainDepth { get; set; } = 8;

    /// <summary>Maximum bytes read from the image when extracting strings (a big file is not fully read).</summary>
    public int MaxStringScanBytes { get; set; } = 1_048_576;

    /// <summary>Maximum imported module names listed in the dossier.</summary>
    public int MaxImportedModules { get; set; } = 40;

    /// <summary>Maximum notable (suspicious) imported function names listed in the dossier.</summary>
    public int MaxSuspiciousFunctions { get; set; } = 40;

    /// <summary>Maximum items kept from the model's evidence / MITRE lists.</summary>
    public int MaxVerdictListItems { get; set; } = 20;
}
