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

    /// <summary>
    /// Base address of the local OpenAI-compatible server (Ollama's default shown). A plain-<c>http</c>
    /// address is honoured only for loopback; a remote <c>http://</c> endpoint would send the dossier and
    /// <see cref="LocalApiKey"/> in clear text and is refused by the provider.
    /// </summary>
    public Uri LocalBaseAddress { get; set; } = new("http://localhost:11434/");

    /// <summary>Hard cap on any provider's HTTP response body.</summary>
    public const long MaxResponseBytes = 4L * 1024 * 1024;

    /// <summary>True when <see cref="LocalBaseAddress"/> is https, or http to a loopback host.</summary>
    public bool LocalBaseAddressIsAcceptable =>
        LocalBaseAddress is not null
        && (string.Equals(LocalBaseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || (string.Equals(LocalBaseAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && LocalBaseAddress.IsLoopback));

    /// <summary>Model name/tag on the local server (e.g. a security-tuned Llama-3.1-8B). User-set.</summary>
    public string LocalModel { get; set; } = "foundation-sec-8b";

    /// <summary>Optional bearer key for the local endpoint (most local servers need none).</summary>
    public string? LocalApiKey { get; set; }

    // ---- Claude Code CLI provider — PERSONAL MACHINE, subscription-backed --------------------------
    // Shells out to the installed `claude` CLI in headless print mode (`claude -p --output-format
    // json`). This runs Claude Code AS THE PRODUCT under the user's own login, so it draws on a Claude
    // Pro/Max subscription rather than API-key billing — distinct from ClaudeCodeOAuth below, which
    // extracts the session token and hits the raw API (against terms). The CLI is invoked with no tools
    // (--tools ""), no auto-discovered hooks/MCP/CLAUDE.md (--bare), auto-denied permissions and a constant
    // system prompt; its free-text result is parsed for the verdict JSON, so the verdict is marked
    // FromToolCall=false and can never auto-allow (block/prompt only).
    //
    // AUTH CAVEAT: the CLI reads the subscription login from the invoking user's profile. WardenAgent
    // runs as LocalSystem, which has no Claude login — under the service this provider will fail auth
    // and return null (fail-safe: the tier stays silent and the pipeline falls through to the prompt).
    // To use it under the service, run `claude setup-token` and expose the token to the service account
    // (e.g. a machine env var the CLI honors), or drive classification from the user-session tray UI.

    /// <summary>Enable the Claude Code CLI provider. Off by default; personal / subscription use.</summary>
    public bool EnableClaudeCli { get; set; }

    /// <summary>
    /// <b>Absolute</b> path to the <c>claude</c> executable (e.g. <c>C:\Program Files\Claude\claude.exe</c>).
    /// The provider stays disabled for a relative/bare value: a LocalSystem service must never resolve an
    /// executable through the PATH search order (a user-writable PATH entry would be SYSTEM code execution).
    /// </summary>
    public string ClaudeCliPath { get; set; } = string.Empty;

    /// <summary>
    /// Per-invocation timeout for the CLI. Generous by default: a cold CLI start plus model latency runs
    /// well past the HTTP <see cref="RequestTimeout"/>, so the CLI has its own budget.
    /// </summary>
    public TimeSpan ClaudeCliTimeout { get; set; } = TimeSpan.FromSeconds(90);

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
