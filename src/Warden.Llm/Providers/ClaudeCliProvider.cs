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

    // The CLI never auto-allows: its verdict is scraped from free text (FromToolCall = false) and, even if that
    // changed, only the Anthropic API provider may produce an Allow.
    public bool MayAutoAllow => false;

    // Enabled only with a well-formed, fully-qualified local path to an .exe. The file-system trust check
    // (owner + write access on the file and every parent folder) runs before every launch, in AnalyzeAsync.
    public bool IsEnabled => _options.EnableClaudeCli && DescribePathProblem(_options.ClaudeCliPath) is null;

    /// <summary>
    /// Syntactic check of a configured CLI path. Returns null when the path is acceptable, otherwise a reason.
    /// </summary>
    /// <remarks>
    /// Refused: empty values; anything that is not fully qualified (<c>claude</c>, <c>.\claude.exe</c>,
    /// drive-relative <c>C:claude.exe</c>, rooted-without-drive <c>\claude.exe</c>); UNC and device paths in
    /// either slash style (<c>\\host\share</c>, <c>//host/share</c>, <c>\\?\</c>, <c>\\.\</c>); a path that is
    /// not already canonical (<c>..</c> segments, trailing dots or spaces, forward slashes); alternate data
    /// streams; and any file that is not an <c>.exe</c> (a <c>.cmd</c>/<c>.bat</c>/<c>.ps1</c> runs through an
    /// interpreter that loads further user-writable files).
    /// </remarks>
    public static string? DescribePathProblem(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "No claude CLI path is configured.";
        }
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal)
            || path.StartsWith(@"\/", StringComparison.Ordinal) || path.StartsWith(@"/\", StringComparison.Ordinal))
        {
            return "The claude CLI path is a UNC or device path; only a local path is accepted.";
        }
        if (!Path.IsPathFullyQualified(path))
        {
            return "The claude CLI path must be a fully-qualified local path (for example C:\\Program Files\\Claude\\claude.exe).";
        }
        if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
        {
            return "The claude CLI path must start with a drive letter and a backslash.";
        }
        if (path.IndexOf(':', 2) >= 0)
        {
            return "The claude CLI path names an alternate data stream.";
        }
        if (path.Contains('/', StringComparison.Ordinal))
        {
            return "The claude CLI path must use backslashes.";
        }

        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return "The claude CLI path is not a valid path.";
        }
        if (!string.Equals(full, path, StringComparison.OrdinalIgnoreCase))
        {
            return "The claude CLI path is not canonical (it has '..', '.', repeated separators, or trailing dots or spaces).";
        }
        if (!string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            return "The claude CLI path must name an .exe; scripts such as .cmd, .bat or .ps1 are refused.";
        }
        return null;
    }

    public async Task<LlmVerdict?> AnalyzeAsync(Dossier dossier, bool escalate, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            return null;
        }

        // The service runs as LocalSystem: whoever can replace claude.exe, or plant a DLL next to it, runs code
        // as SYSTEM on the next launch. Verify ownership and write access of the file and every parent folder
        // before EVERY launch. No check configured means no launch (fail closed).
        Func<string, string?>? trustCheck = _options.ClaudeCliTrustCheck;
        if (trustCheck is null)
        {
            _logger.LogError("claude CLI not launched: no file-trust check is configured for {Path}.", _options.ClaudeCliPath);
            return null;
        }
        string? untrusted;
        try
        {
            untrusted = trustCheck(_options.ClaudeCliPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "claude CLI not launched: the file-trust check for {Path} failed.", _options.ClaudeCliPath);
            return null;
        }
        if (untrusted is not null)
        {
            _logger.LogError("claude CLI not launched: {Path} is not safe to run as SYSTEM: {Problem}", _options.ClaudeCliPath, untrusted);
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
