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
/// prompt, the dossier on stdin, and a no-tools sentinel (<c>--allowed-tools __none__</c>) so an
/// injection smuggled in the dossier can never make the agent run a tool. The verdict is parsed from the
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
    // A single non-existent tool name as the entire allow-list: the CLI accepts the flag (it is
    // variadic and rejects an empty value) while granting the agent no usable tool.
    private const string NoToolsSentinel = "__none__";

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

    public bool IsEnabled => _options.EnableClaudeCli && !string.IsNullOrWhiteSpace(_options.ClaudeCliPath);

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
        // CLI transport has no submit_verdict tool → the JSON-emitting prompt variant.
        "--system-prompt", LlmAnalystPrompt.CliSystemPrompt,
        "--allowed-tools", NoToolsSentinel,
        "--exclude-dynamic-system-prompt-sections",
    };

    private static string Trim(string s) => s.Length > 400 ? s[..400] : s;
}
