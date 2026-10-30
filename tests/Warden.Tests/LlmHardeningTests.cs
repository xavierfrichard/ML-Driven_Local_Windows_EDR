using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Core;
using Warden.Llm;
using Warden.Llm.Providers;

namespace Warden.Tests;

/// <summary>
/// Audit H5 (claude CLI path runs as SYSTEM), the local-endpoint and auto-allow lows, and the evidence cap.
/// </summary>
public sealed class LlmHardeningTests
{
    private const string CliExe = @"C:\Program Files\Claude\claude.exe";

    // ---- H5: CLI path syntax ------------------------------------------------------------------------

    [Theory]
    [InlineData("claude")]
    [InlineData(@".\claude.exe")]
    [InlineData(@"C:claude.exe")]                           // drive-relative
    [InlineData(@"\claude.exe")]                            // rooted, no drive
    [InlineData(@"\\server\share\claude.exe")]              // UNC
    [InlineData(@"//server/share/claude.exe")]              // UNC, forward slashes
    [InlineData(@"\/server/share/claude.exe")]              // mixed-slash UNC
    [InlineData(@"\\?\C:\Program Files\Claude\claude.exe")] // device path
    [InlineData(@"\\.\C:\Program Files\Claude\claude.exe")] // device path
    [InlineData(@"C:/Program Files/Claude/claude.exe")]     // forward slashes
    [InlineData(@"C:\Program Files\Claude\..\..\Users\Public\claude.exe")]
    [InlineData(@"C:\Program Files\Claude\claude.exe.")]    // trailing dot is stripped by Windows
    [InlineData(@"C:\Program Files\Claude\claude.exe ")]    // trailing space is stripped by Windows
    [InlineData(@"C:\Program Files\Claude\claude.exe:evil")] // alternate data stream
    [InlineData(@"C:\Users\me\AppData\Roaming\npm\claude.cmd")]
    [InlineData(@"C:\Tools\claude.bat")]
    [InlineData(@"C:\Tools\claude.ps1")]
    [InlineData(@"C:\Tools\claude.com")]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Given_an_unsafe_cli_path_When_configured_Then_the_provider_is_disabled_and_never_launches(string path)
    {
        var runner = FakeClaudeCliRunner.Ok(LlmTest.CliEnvelope("malicious", 0.99));
        var options = new LlmOptions { EnableClaudeCli = true, ClaudeCliPath = path, ClaudeCliTrustCheck = _ => null };
        var provider = new ClaudeCliProvider(runner, options, NullLogger<ClaudeCliProvider>.Instance);

        Assert.NotNull(ClaudeCliProvider.DescribePathProblem(path));
        Assert.False(provider.IsEnabled);
        Assert.Null(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.Equal(0, runner.Calls);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Claude\claude.exe")]
    [InlineData(@"D:\Apps\claude.EXE")]
    public void Given_a_canonical_local_exe_path_When_checked_Then_it_is_accepted(string path)
    {
        Assert.Null(ClaudeCliProvider.DescribePathProblem(path));
    }

    // ---- H5: ownership check before every launch ----------------------------------------------------

    [Fact]
    public async Task Given_no_trust_check_When_analyzing_Then_the_cli_is_not_launched()
    {
        var runner = FakeClaudeCliRunner.Ok(LlmTest.CliEnvelope("malicious", 0.99));
        var options = new LlmOptions { EnableClaudeCli = true, ClaudeCliPath = CliExe }; // ClaudeCliTrustCheck = null
        var provider = new ClaudeCliProvider(runner, options, NullLogger<ClaudeCliProvider>.Instance);

        Assert.Null(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.Equal(0, runner.Calls); // fail closed: no check, no launch
    }

    [Fact]
    public async Task Given_a_user_writable_cli_When_analyzing_Then_the_cli_is_not_launched()
    {
        var runner = FakeClaudeCliRunner.Ok(LlmTest.CliEnvelope("malicious", 0.99));
        string? checkedPath = null;
        var options = new LlmOptions
        {
            EnableClaudeCli = true,
            ClaudeCliPath = CliExe,
            ClaudeCliTrustCheck = p => { checkedPath = p; return @"BUILTIN\Users can write to C:\Program Files\Claude."; },
        };
        var provider = new ClaudeCliProvider(runner, options, NullLogger<ClaudeCliProvider>.Instance);

        Assert.Null(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.Equal(CliExe, checkedPath);
        Assert.Equal(0, runner.Calls);
    }

    [Fact]
    public async Task Given_a_trust_check_that_throws_When_analyzing_Then_the_cli_is_not_launched()
    {
        var runner = FakeClaudeCliRunner.Ok(LlmTest.CliEnvelope("malicious", 0.99));
        var options = new LlmOptions
        {
            EnableClaudeCli = true,
            ClaudeCliPath = CliExe,
            ClaudeCliTrustCheck = _ => throw new UnauthorizedAccessException("cannot read ACL"),
        };
        var provider = new ClaudeCliProvider(runner, options, NullLogger<ClaudeCliProvider>.Instance);

        Assert.Null(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.Equal(0, runner.Calls);
    }

    [Fact]
    public async Task Given_a_trusted_cli_When_analyzing_twice_Then_the_check_runs_before_each_launch()
    {
        var runner = FakeClaudeCliRunner.Ok(LlmTest.CliEnvelope("malicious", 0.9));
        int checks = 0;
        var options = new LlmOptions
        {
            EnableClaudeCli = true,
            ClaudeCliPath = CliExe,
            ClaudeCliTrustCheck = _ => { checks++; return null; },
        };
        var provider = new ClaudeCliProvider(runner, options, NullLogger<ClaudeCliProvider>.Instance);

        Assert.NotNull(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.NotNull(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));

        Assert.Equal(2, checks); // not cached: a file can become writable between launches
        Assert.Equal(2, runner.Calls);
    }

    [Fact]
    public async Task Given_a_script_path_When_the_runner_is_called_directly_Then_it_refuses_without_starting_a_process()
    {
        var runner = new ClaudeCliRunner();

        ClaudeCliResult result = await runner.RunAsync(
            @"C:\Windows\System32\cmd.cmd", Array.Empty<string>(), string.Empty, TimeSpan.FromSeconds(5), default);

        Assert.False(result.Started);
    }

    // ---- H5: child environment is an allow-list -----------------------------------------------------

    [Fact]
    public void Given_service_secrets_in_the_environment_When_building_the_child_environment_Then_only_allow_listed_variables_pass()
    {
        var current = new Dictionary<string, string?>
        {
            ["SystemRoot"] = @"C:\Windows",
            ["TEMP"] = @"C:\Windows\Temp",
            ["USERPROFILE"] = @"C:\Windows\system32\config\systemprofile",
            ["WARDEN_VT_API_KEY"] = "vt-secret",
            ["WARDEN_ANTHROPIC_API_KEY"] = "sk-secret",
            ["ANTHROPIC_API_KEY"] = "sk-secret-2",
            ["CLAUDE_CODE_OAUTH_TOKEN"] = "oauth-secret",
            ["SOME_FUTURE_TOKEN"] = "not-on-any-deny-list",
            ["NODE_OPTIONS"] = "--require C:\\Users\\Public\\evil.js",
            ["PATH"] = @"C:\Users\Public\bin;C:\Windows\System32",
        };

        Dictionary<string, string> env = ClaudeCliRunner.BuildEnvironment(current, @"C:\Windows");

        Assert.Equal(@"C:\Windows", env["SystemRoot"]);
        Assert.Equal(@"C:\Windows\Temp", env["TEMP"]);
        Assert.DoesNotContain(env.Values, v => v.Contains("secret", StringComparison.OrdinalIgnoreCase));
        Assert.False(env.ContainsKey("SOME_FUTURE_TOKEN"));
        Assert.False(env.ContainsKey("NODE_OPTIONS"));
        Assert.DoesNotContain(@"C:\Users\Public\bin", env["PATH"], StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith(@"C:\Windows\System32", env["PATH"], StringComparison.OrdinalIgnoreCase);
    }

    // ---- Local endpoint: explicit opt-in + token for plain http on loopback --------------------------

    [Fact]
    public async Task Given_default_local_options_When_enabled_Then_plain_http_loopback_is_refused()
    {
        var handler = new RecordingHandler(_ => RecordingHandler.Ok(LlmTest.OpenAiToolCall("malicious", 0.99)));
        var options = new LlmOptions { EnableLocal = true }; // default http://localhost:11434, no opt-in, no key
        var provider = new LocalLlmProvider(new StubHttpClientFactory(handler, LlmTest.LocalBase), options,
            NullLogger<LocalLlmProvider>.Instance);

        Assert.False(provider.IsEnabled);
        Assert.Null(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.Equal(0, handler.CallCount);
    }

    [Theory]
    [InlineData("http://localhost:11434/", true, null, false)]          // opt-in but no token
    [InlineData("http://localhost:11434/", false, "tok", false)]        // token but no opt-in
    [InlineData("http://localhost:11434/", true, "tok", true)]          // both
    [InlineData("http://127.0.0.1:11434/", true, "tok", true)]
    [InlineData("http://192.168.1.10:11434/", true, "tok", false)]      // remote http: never
    [InlineData("https://llm.example.internal/", false, null, true)]    // https: certificate authenticates the server
    public void Given_a_local_endpoint_When_checking_Then_only_https_or_opted_in_loopback_http_with_a_token_is_accepted(
        string address, bool allowLoopbackHttp, string? key, bool expected)
    {
        var options = new LlmOptions
        {
            EnableLocal = true,
            LocalBaseAddress = new Uri(address),
            LocalAllowLoopbackHttp = allowLoopbackHttp,
            LocalApiKey = key,
        };
        var provider = new LocalLlmProvider(new StubHttpClientFactory(new RecordingHandler(_ => RecordingHandler.Ok("{}")), LlmTest.LocalBase),
            options, NullLogger<LocalLlmProvider>.Instance);

        Assert.Equal(expected, provider.IsEnabled);
    }

    [Fact]
    public async Task Given_an_opted_in_loopback_endpoint_When_analyzing_Then_the_token_is_sent()
    {
        var handler = new RecordingHandler(_ => RecordingHandler.Ok(LlmTest.OpenAiToolCall("malicious", 0.9)));
        var options = new LlmOptions { EnableLocal = true, LocalAllowLoopbackHttp = true, LocalApiKey = "local-token" };
        var provider = new LocalLlmProvider(new StubHttpClientFactory(handler, LlmTest.LocalBase), options,
            NullLogger<LocalLlmProvider>.Instance);

        Assert.NotNull(await provider.AnalyzeAsync(LlmTest.Dossier(options), false, default));
        Assert.Equal("Bearer", handler.LastRequest!.Headers.Authorization!.Scheme);
        Assert.Equal("local-token", handler.LastRequest.Headers.Authorization.Parameter);
    }

    // ---- Auto-allow: only the Anthropic API provider --------------------------------------------------

    [Fact]
    public void Given_the_built_in_providers_When_asked_Then_only_the_anthropic_api_may_auto_allow()
    {
        var options = new LlmOptions();
        var factory = new StubHttpClientFactory(new RecordingHandler(_ => RecordingHandler.Ok("{}")), LlmTest.AnthropicBase);

        Assert.True(new AnthropicApiProvider(factory, options, NullLogger<AnthropicApiProvider>.Instance).MayAutoAllow);
        Assert.False(new LocalLlmProvider(factory, options, NullLogger<LocalLlmProvider>.Instance).MayAutoAllow);
        Assert.False(new ClaudeCodeOAuthProvider(factory, options, NullLogger<ClaudeCodeOAuthProvider>.Instance).MayAutoAllow);
        Assert.False(new ClaudeCliProvider(FakeClaudeCliRunner.Ok("{}"), options, NullLogger<ClaudeCliProvider>.Instance).MayAutoAllow);
    }

    [Fact]
    public async Task Given_allow_on_benign_When_a_non_api_provider_says_confidently_benign_via_a_tool_call_Then_it_defers()
    {
        var options = new LlmOptions { AllowOnBenign = true, BenignConfidenceThreshold = 0.85 };
        var local = new FakeLlmProvider { Name = "local", MayAutoAllow = false, Result = FakeLlmProvider.Verdict(LlmDisposition.Benign, 0.99) };
        var source = new LlmVerdictSource(new[] { local }, new DossierBuilder(options), options, NullLogger<LlmVerdictSource>.Instance);

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Unknown, result.Verdict); // a squatted local endpoint cannot clear a block
    }

    [Fact]
    public async Task Given_allow_on_benign_When_a_local_server_answers_benign_Then_the_real_pipeline_still_defers()
    {
        // End to end through the real LocalLlmProvider: a forced tool call saying "benign 0.99".
        var handler = new RecordingHandler(_ => RecordingHandler.Ok(LlmTest.OpenAiToolCall("benign", 0.99, "allow")));
        var options = new LlmOptions
        {
            EnableLocal = true, LocalAllowLoopbackHttp = true, LocalApiKey = "tok",
            AllowOnBenign = true, BenignConfidenceThreshold = 0.5,
        };
        var local = new LocalLlmProvider(new StubHttpClientFactory(handler, LlmTest.LocalBase), options, NullLogger<LocalLlmProvider>.Instance);
        var source = new LlmVerdictSource(new IVerdictLlmProvider[] { local }, new DossierBuilder(options), options,
            NullLogger<LlmVerdictSource>.Instance);

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(Verdict.Unknown, result.Verdict);
    }

    [Fact]
    public void Given_default_options_When_created_Then_every_auto_allow_switch_is_off()
    {
        Assert.False(new LlmOptions().AllowOnBenign);
        Assert.False(new Warden.Ml.MlOptions().AllowOnLowScore);
        Assert.False(new Warden.Reputation.ReputationOptions().AllowKnownClean);
    }

    // ---- Evidence items are capped and cleaned ------------------------------------------------------

    [Fact]
    public void Given_huge_or_control_laden_evidence_When_parsing_Then_each_item_is_clipped_and_cleaned()
    {
        string huge = new('A', 50_000);
        string json = JsonSerializer.Serialize(new
        {
            verdict = "malicious",
            confidence = 0.9,
            evidence = new[] { huge, "line one\nline two", "safe\u202Etxt.exe", "\u200B" },
            mitre_attack = new[] { new string('T', 5_000) },
            suggested_action = "block" + new string('x', 1_000),
        });
        using JsonDocument doc = JsonDocument.Parse(json);

        LlmVerdict verdict = LlmVerdict.FromInput(doc.RootElement, maxListItems: 20)!;

        Assert.Equal(LlmVerdict.MaxItemLength, verdict.Evidence[0].Length);
        Assert.Equal("line one line two", verdict.Evidence[1]);
        Assert.Equal("safetxt.exe", verdict.Evidence[2]);  // bidi override removed
        Assert.Equal(3, verdict.Evidence.Length);          // a zero-width-only item is dropped
        Assert.Equal(LlmVerdict.MaxItemLength, verdict.MitreAttack[0].Length);
        Assert.Equal(LlmVerdict.MaxSuggestedActionLength, verdict.SuggestedAction.Length);
    }
}
