using Microsoft.Extensions.Logging.Abstractions;
using Warden.Core;
using Warden.Llm;

namespace Warden.Tests;

public sealed class LlmVerdictSourceTests
{
    private static LlmVerdictSource Source(LlmOptions options, params IVerdictLlmProvider[] providers) =>
        new(providers, new DossierBuilder(options), options, NullLogger<LlmVerdictSource>.Instance);

    [Fact]
    public async Task Disabled_when_no_provider_is_enabled()
    {
        var options = new LlmOptions();
        var source = Source(options, new FakeLlmProvider { IsEnabled = false });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.Equal(VerdictSourceKind.Llm, result.Source);
    }

    [Fact]
    public async Task Confident_malicious_blocks()
    {
        var options = new LlmOptions { MaliciousConfidenceThreshold = 0.7 };
        var source = Source(options, new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Malicious, 0.9) });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Block, result.Verdict);
        Assert.Equal(VerdictSourceKind.Llm, result.Source);
    }

    [Fact]
    public async Task Low_confidence_malicious_defers()
    {
        var options = new LlmOptions { MaliciousConfidenceThreshold = 0.7 };
        var source = Source(options, new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Malicious, 0.5) });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task Benign_defers_by_default()
    {
        var options = new LlmOptions(); // AllowOnBenign defaults false
        var source = Source(options, new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Benign, 0.99) });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task Benign_allows_when_configured_and_confident()
    {
        var options = new LlmOptions { AllowOnBenign = true, BenignConfidenceThreshold = 0.85 };
        var source = Source(options, new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Benign, 0.9) });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Allow, result.Verdict);
    }

    [Fact]
    public async Task Suspicious_blocks_only_when_configured()
    {
        var deferOptions = new LlmOptions();
        var deferSource = Source(deferOptions, new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Suspicious, 0.8) });
        Assert.Equal(Verdict.Unknown, (await deferSource.EvaluateAsync(LlmTest.Context(), default)).Verdict);

        var blockOptions = new LlmOptions { BlockOnSuspicious = true };
        var blockSource = Source(blockOptions, new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Suspicious, 0.8) });
        Assert.Equal(Verdict.Block, (await blockSource.EvaluateAsync(LlmTest.Context(), default)).Verdict);
    }

    [Fact]
    public async Task Content_fallback_benign_never_auto_allows()
    {
        var options = new LlmOptions { AllowOnBenign = true, BenignConfidenceThreshold = 0.85 };
        // A confident "benign" that did NOT come through the forced tool call (e.g. the local content
        // fallback, which an injected local model could steer) must never clear the block.
        LlmVerdict fromProse = FakeLlmProvider.Verdict(LlmDisposition.Benign, 0.99) with { FromToolCall = false };
        var source = Source(options, new FakeLlmProvider { Result = fromProse });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Unknown, result.Verdict); // defers to prompt despite AllowOnBenign
    }

    [Fact]
    public async Task Null_verdict_is_undecided()
    {
        var options = new LlmOptions();
        var source = Source(options, new FakeLlmProvider { Result = null });

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task Falls_back_to_next_provider_in_priority_order()
    {
        var options = new LlmOptions();
        var primary = new FakeLlmProvider { Name = "primary", Priority = 0, Result = null }; // fails
        var secondary = new FakeLlmProvider { Name = "secondary", Priority = 10, Result = FakeLlmProvider.Verdict(LlmDisposition.Malicious, 0.95) };

        // Register out of order to prove the source sorts by priority.
        var source = Source(options, secondary, primary);

        VerdictResult result = await source.EvaluateAsync(LlmTest.Context(), default);

        Assert.Equal(Verdict.Block, result.Verdict);
        Assert.Equal(1, primary.Calls);   // primary was tried first (priority 0)...
        Assert.Equal(1, secondary.Calls); // ...then fell back to secondary
    }

    [Fact]
    public async Task Internet_origin_requests_escalation()
    {
        var options = new LlmOptions();
        var provider = new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Suspicious, 0.5) };
        var source = Source(options, provider);

        await source.EvaluateAsync(LlmTest.Context(motwZone: 3), default); // MOTW internet

        Assert.True(provider.LastEscalate);
    }

    [Fact]
    public async Task Local_origin_does_not_escalate_by_default()
    {
        var options = new LlmOptions();
        var provider = new FakeLlmProvider { Result = FakeLlmProvider.Verdict(LlmDisposition.Suspicious, 0.5) };
        var source = Source(options, provider);

        await source.EvaluateAsync(LlmTest.Context(motwZone: VerdictContext.NoMotw), default);

        Assert.False(provider.LastEscalate);
    }
}
