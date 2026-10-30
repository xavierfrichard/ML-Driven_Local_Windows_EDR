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

    // ---- M7: an Allow needs pinned bytes unless it is hash-keyed ----

    private static VerdictContext Pinned() => TestData.Context() with { SnapshotPath = @"C:\ProgramData\Warden\snapshots\1_x_unknown.exe" };

    [Fact]
    public void Given_no_snapshot_When_context_is_built_Then_it_is_not_byte_pinned()
    {
        Assert.False(TestData.Context().IsBytePinned);
        Assert.True(Pinned().IsBytePinned);
    }

    [Theory]
    [InlineData(VerdictSourceKind.TrustGate)]
    [InlineData(VerdictSourceKind.VirusTotal)]
    [InlineData(VerdictSourceKind.Ml)]
    [InlineData(VerdictSourceKind.Llm)]
    public async Task Given_unpinned_bytes_When_a_content_tier_allows_Then_the_result_is_prompt(VerdictSourceKind kind)
    {
        var pipeline = new DecisionPipeline(new IVerdictSource[] { StubSource.Deciding(kind, Verdict.Allow) });

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Prompt, result.Verdict);
        Assert.Equal(kind, result.Source);
        Assert.Contains("not pinned", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(VerdictSourceKind.Rules)]
    [InlineData(VerdictSourceKind.Whitelist)]
    public async Task Given_unpinned_bytes_When_a_hash_keyed_tier_allows_Then_the_allow_stands(VerdictSourceKind kind)
    {
        var pipeline = new DecisionPipeline(new IVerdictSource[] { StubSource.Deciding(kind, Verdict.Allow) });

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Allow, result.Verdict);
        Assert.Equal(kind, result.Source);
    }

    [Theory]
    [InlineData(VerdictSourceKind.TrustGate)]
    [InlineData(VerdictSourceKind.Ml)]
    [InlineData(VerdictSourceKind.Llm)]
    public async Task Given_pinned_bytes_When_a_content_tier_allows_Then_the_allow_stands(VerdictSourceKind kind)
    {
        var pipeline = new DecisionPipeline(new IVerdictSource[] { StubSource.Deciding(kind, Verdict.Allow) });

        var result = await pipeline.EvaluateAsync(Pinned());

        Assert.Equal(Verdict.Allow, result.Verdict);
    }

    [Fact]
    public async Task Given_unpinned_bytes_When_a_content_tier_blocks_Then_the_block_stands()
    {
        var pipeline = new DecisionPipeline(new IVerdictSource[] { StubSource.Deciding(VerdictSourceKind.Ml, Verdict.Block) });

        var result = await pipeline.EvaluateAsync(TestData.Context());

        Assert.Equal(Verdict.Block, result.Verdict);
    }

    [Fact]
    public void Given_an_unknown_future_tier_When_asked_if_it_may_allow_unpinned_Then_no()
    {
        Assert.False(DecisionPipeline.MayAllowUnpinned(VerdictSourceKind.UserPrompt));
        Assert.False(DecisionPipeline.MayAllowUnpinned((VerdictSourceKind)99));
    }

    // ---- M6: per-tier time budgets ----

    private static DecisionPipelineOptions ShortBudget(TimeSpan budget)
    {
        var options = new DecisionPipelineOptions { DefaultTierTimeout = budget };
        options.TierTimeouts.Clear();
        return options;
    }

    [Fact]
    public async Task Given_a_tier_that_blocks_synchronously_When_it_exceeds_its_budget_Then_it_is_skipped_and_reported()
    {
        var errors = new List<(VerdictSourceKind Kind, Exception Ex)>();
        using var release = new ManualResetEventSlim(false);
        var stuck = new SyncBlockingSource(VerdictSourceKind.Ml, release);
        var llm = StubSource.Deciding(VerdictSourceKind.Llm, Verdict.Block);
        var pipeline = new DecisionPipeline(
            new IVerdictSource[] { stuck, llm },
            (kind, ex) => errors.Add((kind, ex)),
            ShortBudget(TimeSpan.FromMilliseconds(200)));

        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var result = await pipeline.EvaluateAsync(TestData.Context()).AsTask().WaitAsync(TimeSpan.FromSeconds(20));
            sw.Stop();

            Assert.Equal(Verdict.Block, result.Verdict);
            Assert.Equal(VerdictSourceKind.Llm, result.Source);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"pipeline waited {sw.Elapsed}");
            var error = Assert.Single(errors);
            Assert.Equal(VerdictSourceKind.Ml, error.Kind);
            Assert.IsType<VerdictSourceTimeoutException>(error.Ex);
        }
        finally
        {
            release.Set();
        }
    }

    [Fact]
    public async Task Given_an_async_tier_that_hangs_When_it_times_out_Then_its_token_is_cancelled_and_the_result_is_prompt()
    {
        var hanging = new HangingSource(VerdictSourceKind.Llm);
        var pipeline = new DecisionPipeline(
            new IVerdictSource[] { hanging },
            options: ShortBudget(TimeSpan.FromMilliseconds(100)));

        var result = await pipeline.EvaluateAsync(TestData.Context()).AsTask().WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Equal(Verdict.Prompt, result.Verdict);
        Assert.Equal(VerdictSourceKind.Fallthrough, result.Source);
        Assert.True(await hanging.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task Given_a_per_tier_override_When_that_tier_hangs_Then_only_its_budget_applies()
    {
        var options = ShortBudget(TimeSpan.FromSeconds(60));
        options.TierTimeouts[VerdictSourceKind.VirusTotal] = TimeSpan.FromMilliseconds(100);
        var ml = StubSource.Deciding(VerdictSourceKind.Ml, Verdict.Block);
        var pipeline = new DecisionPipeline(new IVerdictSource[] { new HangingSource(VerdictSourceKind.VirusTotal), ml }, options: options);

        var result = await pipeline.EvaluateAsync(TestData.Context()).AsTask().WaitAsync(TimeSpan.FromSeconds(20));

        Assert.Equal(VerdictSourceKind.Ml, result.Source);
    }

    [Fact]
    public void Given_default_options_When_reading_budgets_Then_llm_gets_more_time_than_the_default()
    {
        var options = new DecisionPipelineOptions();

        Assert.Equal(TimeSpan.FromSeconds(15), options.TimeoutFor(VerdictSourceKind.Ml));
        Assert.True(options.TimeoutFor(VerdictSourceKind.Llm) > options.DefaultTierTimeout);
        Assert.True(options.TimeoutFor(VerdictSourceKind.Llm) >= TimeSpan.FromSeconds(90)); // Claude CLI budget
    }

    [Fact]
    public async Task Given_a_hung_tier_When_the_caller_cancels_Then_cancellation_propagates()
    {
        var pipeline = new DecisionPipeline(
            new IVerdictSource[] { new HangingSource(VerdictSourceKind.Ml) },
            options: ShortBudget(TimeSpan.FromSeconds(60)));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await pipeline.EvaluateAsync(TestData.Context(), cts.Token));
    }

    /// <summary>Blocks its thread (like a synchronous PE parse) until released; ignores cancellation.</summary>
    private sealed class SyncBlockingSource : IVerdictSource
    {
        private readonly ManualResetEventSlim _release;

        public SyncBlockingSource(VerdictSourceKind kind, ManualResetEventSlim release)
        {
            Kind = kind;
            _release = release;
        }

        public VerdictSourceKind Kind { get; }

        public ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
        {
            _release.Wait(TimeSpan.FromSeconds(30));
            return ValueTask.FromResult(new VerdictResult(Verdict.Allow, Kind, 1d, "late allow"));
        }
    }

    /// <summary>Never answers; records when its token is cancelled.</summary>
    private sealed class HangingSource : IVerdictSource
    {
        public HangingSource(VerdictSourceKind kind) => Kind = kind;

        public VerdictSourceKind Kind { get; }

        public TaskCompletionSource<bool> Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
        {
            using (cancellationToken.Register(() => Cancelled.TrySetResult(true)))
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            }
            return VerdictResult.Undecided(Kind, "unreached");
        }
    }
}
