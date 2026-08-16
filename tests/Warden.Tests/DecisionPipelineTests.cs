using Warden.Core;

namespace Warden.Tests;

public sealed class DecisionPipelineTests
{
    [Fact]
    public async Task First_decisive_source_wins_and_later_sources_are_not_consulted()
    {
        var rules = StubSource.Deciding(VerdictSourceKind.Rules, Verdict.Allow);
        var laterMl = StubSource.Deciding(VerdictSourceKind.Ml, Verdict.Block);
        var pipeline = new DecisionPipeline(new IVerdictSource[] { rules, laterMl });

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Allow, result.Verdict);
        Assert.Equal(VerdictSourceKind.Rules, result.Source);
        Assert.True(rules.WasEvaluated);
        Assert.False(laterMl.WasEvaluated); // short-circuited
    }

    [Fact]
    public async Task Undecided_sources_are_skipped_until_a_decisive_one()
    {
        var trust = StubSource.Undecided(VerdictSourceKind.TrustGate);
        var whitelist = StubSource.Undecided(VerdictSourceKind.Whitelist);
        var ml = StubSource.Deciding(VerdictSourceKind.Ml, Verdict.Block);
        var pipeline = new DecisionPipeline(new IVerdictSource[] { trust, whitelist, ml });

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Block, result.Verdict);
        Assert.Equal(VerdictSourceKind.Ml, result.Source);
        Assert.True(trust.WasEvaluated);
        Assert.True(whitelist.WasEvaluated);
    }

    [Fact]
    public async Task All_undecided_falls_through_to_prompt()
    {
        var sources = new IVerdictSource[]
        {
            StubSource.Undecided(VerdictSourceKind.Rules),
            StubSource.Undecided(VerdictSourceKind.TrustGate),
            StubSource.Undecided(VerdictSourceKind.Llm),
        };
        var pipeline = new DecisionPipeline(sources);

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Prompt, result.Verdict);
        Assert.Equal(VerdictSourceKind.Fallthrough, result.Source);
    }

    [Fact]
    public async Task Throwing_source_is_isolated_and_reported_then_pipeline_continues()
    {
        var errors = new List<(VerdictSourceKind Kind, Exception Ex)>();
        var throwing = new ThrowingSource(VerdictSourceKind.VirusTotal);
        var ml = StubSource.Deciding(VerdictSourceKind.Ml, Verdict.Block);
        var pipeline = new DecisionPipeline(
            new IVerdictSource[] { throwing, ml },
            onSourceError: (kind, ex) => errors.Add((kind, ex)));

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Block, result.Verdict); // reached the source after the thrower
        var error = Assert.Single(errors);
        Assert.Equal(VerdictSourceKind.VirusTotal, error.Kind);
        Assert.IsType<InvalidOperationException>(error.Ex);
    }

    [Fact]
    public async Task A_broken_final_source_never_produces_a_silent_allow()
    {
        // If the only decisive-capable tier throws, the fail-safe result must be Prompt, not Allow.
        var pipeline = new DecisionPipeline(
            new IVerdictSource[] { new ThrowingSource(VerdictSourceKind.Llm) });

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Prompt, result.Verdict);
        Assert.NotEqual(Verdict.Allow, result.Verdict);
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        var pipeline = new DecisionPipeline(new IVerdictSource[] { new CancelObservingSource() });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pipeline.EvaluateAsync(TestData.Context(), cts.Token));
    }

    [Fact]
    public void Empty_source_list_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new DecisionPipeline(Array.Empty<IVerdictSource>()));
    }

    [Fact]
    public void Null_source_list_is_rejected()
    {
        Assert.Throws<ArgumentNullException>(() => new DecisionPipeline(null!));
    }

    /// <summary>
    /// The composition root orders tiers by <c>(int)Kind</c>. A prior explicit decision (whitelist) must
    /// outrank the automatic fast-allow (trust gate), or a user's "keep blocked" on a validly-signed file
    /// would be re-allowed and overwritten on the next launch.
    /// </summary>
    [Fact]
    public async Task Whitelist_block_outranks_the_trust_gates_allow_in_registration_order()
    {
        Assert.True((int)VerdictSourceKind.Rules < (int)VerdictSourceKind.Whitelist);
        Assert.True((int)VerdictSourceKind.Whitelist < (int)VerdictSourceKind.TrustGate);

        var whitelistBlock = StubSource.Deciding(VerdictSourceKind.Whitelist, Verdict.Block);
        var trustAllow = StubSource.Deciding(VerdictSourceKind.TrustGate, Verdict.Allow);

        // Register in the "wrong" textual order and sort the way Program.cs does.
        var ordered = new IVerdictSource[] { trustAllow, whitelistBlock }.OrderBy(s => (int)s.Kind).ToList();
        var pipeline = new DecisionPipeline(ordered);

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Block, result.Verdict);
        Assert.Equal(VerdictSourceKind.Whitelist, result.Source);
        Assert.False(trustAllow.WasEvaluated);
    }
}
