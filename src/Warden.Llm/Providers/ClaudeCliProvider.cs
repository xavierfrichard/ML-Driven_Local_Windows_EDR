using Microsoft.Extensions.Logging;

namespace Warden.Llm.Providers;

/// <summary>
/// PERSONAL-MACHINE, SUBSCRIPTION-BACKED provider that shells out to the installed <c>claude</c> CLI in
/// headless print mode (<c>claude -p --output-format json</c>) instead of calling the Messages API with
/// an API key.
/// <para>
/// This runs Claude Code <b>as the product</b> under the user's own login, so it draws on a Claude
/// Pro/Max subscription — unlike <see cref="ClaudeCodeOAuthProvider"/>, which lifts the session token and
/// posts to the raw API (against Anthropic's terms). The CLI is invoked with the constant analyst system
/// prompt, the dossier on stdin, no tools at all (<c>--tools ""</c>), no auto-discovered hooks/MCP/CLAUDE.md
/// (<c>--bare</c>) and auto-deny permissions, so an injection smuggled in the dossier can never make the
/// agent run a tool or reach the machine. The verdict is parsed from the
/// CLI's free-text <c>result</c>, so it is marked <see cref="LlmVerdict.FromToolCall"/> = false and can
/// only block or defer to the prompt — never auto-allow.
/// </para>
/// <para>
/// AUTH: the CLI reads its login from the invoking user's profile. Under the LocalSystem service this
/// provider fails auth and returns null (fail-safe); see <see cref="LlmOptions.EnableClaudeCli"/>.
/// </para>
/// </summary>
public sealed class ClaudeCliProvider : IVerdictLlmProvider
{
    // `--tools ""` is the documented way to remove every built-in tool from the session (as opposed to
    // `--allowedTools`, which only pre-approves permission prompts and leaves read-only tools available).
    // `--bare` additionally skips auto-discovery of hooks, MCP servers, skills and CLAUDE.md from the working
    // directory, and `--permission-mode dontAsk` auto-denies anything that would still ask.
    private const string NoTools = "";

    private readonly IClaudeCliRunner _runner;
    private readonly LlmOptions _options;
    private readonly ILogger<ClaudeCliProvider> _logger;

    public ClaudeCliProvider(IClaudeCliRunner runner, LlmOptions options, ILogger<ClaudeCliProvider> logger)
    {
        _runner = runner;
        _options = options;
        _logger = logger;
    }

    public string Name => "claude-cli";

    // Frontier subscription model is preferred over a local 8B (10) but yields to a configured API key
    // (0), which is the supported backend for any distributed build.
    public int Priority => 5;

    // Enabled only with an ABSOLUTE executable path: a bare "claude" would be resolved through the PATH
    // search order by a LocalSystem service, where a user-writable PATH entry means SYSTEM code execution.
    public bool IsEnabled =>
        _options.EnableClaudeCli
        && !string.IsNullOrWhiteSpace(_options.ClaudeCliPath)
        && Path.IsPathRooted(_options.ClaudeCliPath)
        && !_options.ClaudeCliPath.StartsWith(@"\\", StringComparison.Ordinal);

    public async Task<LlmVerdict?> AnalyzeAsync(Dossier dossier, bool escalate, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            return null;
        }

        string model = escalate ? _options.EscalationModel : _options.Model;
        string[] args = BuildArguments(model);
        string stdin = LlmAnalystPrompt.UserContent(dossier.ToJson());

        try
        {
            ClaudeCliResult result = await _runner
                .RunAsync(_options.ClaudeCliPath, args, stdin, _options.ClaudeCliTimeout, cancellationToken)
                .ConfigureAwait(false);

            if (!result.Started)
            {
                _logger.LogWarning("claude CLI did not run for {File}: {Err}", dossier.ImageName, Trim(result.Stderr));
                return null;
            }
            if (result.ExitCode != 0)
            {
                _logger.LogWarning("claude CLI exited {Code} for {File}: {Err}",
                    result.ExitCode, dossier.ImageName, Trim(result.Stderr));
                return null;
            }

            LlmVerdict? verdict = LlmAnalystPrompt.ParseClaudeCliResult(result.Stdout, _options.MaxVerdictListItems);
            if (verdict is null)
            {
                _logger.LogWarning("claude CLI produced no usable verdict for {File}.", dossier.ImageName);
                return null;
            }
            return verdict with { Model = model };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw; // caller asked to cancel — propagate
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "claude CLI provider failed for {File}.", dossier.ImageName);
            return null;
        }
    }

    private static string[] BuildArguments(string model) => new[]
    {
        "-p",
        "--output-format", "json",
        "--model", model,
        // CLI transport has no submit_verdict tool → the JSON-emitting prompt variant (replaces the whole
        // system prompt; --exclude-dynamic-system-prompt-sections is ignored when --system-prompt is set).
        "--system-prompt", LlmAnalystPrompt.CliSystemPrompt,
        "--tools", NoTools,
        "--bare",
        "--permission-mode", "dontAsk",
    };

    private static string Trim(string s) => s.Length > 400 ? s[..400] : s;
}
