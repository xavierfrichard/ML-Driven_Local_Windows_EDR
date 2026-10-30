using Warden.Etw;

namespace Warden.Tests.Windows;

/// <summary>L1: coalescing of pending blocks and the prompt cooldown / rate cap.</summary>
public sealed class BlockFlowControlTests
{
    private static CiBlockEvent Block(string path, string authHash = "") => new(
        EventId: 3077,
        Mode: "Enforce",
        BlockedFilePath: path,
        ProcessName: @"C:\Windows\explorer.exe",
        PolicyName: "Warden",
        PolicyGuid: Guid.Empty.ToString(),
        Sha256Authenticode: authHash,
        ActivityId: string.Empty,
        TimeCreated: DateTimeOffset.UnixEpoch,
        RawProperties: new Dictionary<string, string>());

    /// <summary>A hand-written clock for the throttle.</summary>
    private sealed class FakeTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void Given_a_pending_block_When_the_same_file_is_blocked_again_Then_the_repeat_is_coalesced()
    {
        var pending = new PendingBlockSet();

        Assert.True(pending.TryAdd(Block(@"C:\Users\me\d\x.exe")));
        Assert.False(pending.TryAdd(Block(@"c:\users\ME\d\X.EXE")));
        Assert.Equal(1, pending.Count);
    }

    [Fact]
    public void Given_a_handled_block_When_the_file_is_blocked_again_Then_it_is_queued_again()
    {
        var pending = new PendingBlockSet();
        CiBlockEvent first = Block(@"C:\x.exe");
        Assert.True(pending.TryAdd(first));

        pending.Remove(first);

        Assert.True(pending.TryAdd(Block(@"C:\x.exe")));
    }

    [Fact]
    public void Given_the_same_path_with_a_different_ci_hash_When_queued_Then_both_are_kept()
    {
        var pending = new PendingBlockSet();

        Assert.True(pending.TryAdd(Block(@"C:\x.exe", "AA")));
        Assert.True(pending.TryAdd(Block(@"C:\x.exe", "BB")));
    }

    [Fact]
    public void Given_a_flood_of_one_binary_When_queued_Then_it_takes_one_slot()
    {
        var pending = new PendingBlockSet();
        int accepted = Enumerable.Range(0, 1000).Count(_ => pending.TryAdd(Block(@"C:\spam.exe", "CC")));

        Assert.Equal(1, accepted);
    }

    [Fact]
    public void Given_a_recent_prompt_for_a_hash_When_asked_again_within_the_cooldown_Then_it_is_suppressed()
    {
        var time = new FakeTime();
        var throttle = new PromptThrottle(TimeSpan.FromSeconds(60), timeProvider: time);
        string key = PromptThrottle.KeyOf("abc", @"C:\x.exe");

        Assert.Equal(PromptSuppression.None, throttle.TryAcquire(key));
        time.Now += TimeSpan.FromSeconds(30);
        Assert.Equal(PromptSuppression.Cooldown, throttle.TryAcquire(key));
        time.Now += TimeSpan.FromSeconds(31);
        Assert.Equal(PromptSuppression.None, throttle.TryAcquire(key));
    }

    [Fact]
    public void Given_a_prompt_that_stayed_open_When_it_completes_Then_the_cooldown_runs_from_its_close()
    {
        var time = new FakeTime();
        var throttle = new PromptThrottle(TimeSpan.FromSeconds(60), timeProvider: time);
        string key = PromptThrottle.KeyOf("abc", null);

        Assert.Equal(PromptSuppression.None, throttle.TryAcquire(key));
        time.Now += TimeSpan.FromSeconds(50);
        throttle.MarkCompleted(key);
        time.Now += TimeSpan.FromSeconds(30); // 80 s after open, 30 s after close

        Assert.Equal(PromptSuppression.Cooldown, throttle.TryAcquire(key));
    }

    [Fact]
    public void Given_the_same_hash_at_two_paths_When_prompting_Then_the_key_is_the_hash()
    {
        Assert.Equal(PromptThrottle.KeyOf("abc", @"C:\a.exe"), PromptThrottle.KeyOf("ABC", @"D:\b.exe"));
        Assert.NotEqual(PromptThrottle.KeyOf(null, @"C:\a.exe"), PromptThrottle.KeyOf(null, @"C:\b.exe"));
    }

    [Fact]
    public void Given_many_distinct_files_When_prompting_Then_the_global_cap_suppresses_the_excess()
    {
        var time = new FakeTime();
        var throttle = new PromptThrottle(TimeSpan.FromSeconds(60), maxPromptsPerWindow: 3, window: TimeSpan.FromSeconds(60), timeProvider: time);

        Assert.Equal(PromptSuppression.None, throttle.TryAcquire("a"));
        Assert.Equal(PromptSuppression.None, throttle.TryAcquire("b"));
        Assert.Equal(PromptSuppression.None, throttle.TryAcquire("c"));
        Assert.Equal(PromptSuppression.RateLimited, throttle.TryAcquire("d"));

        time.Now += TimeSpan.FromSeconds(61);
        Assert.Equal(PromptSuppression.None, throttle.TryAcquire("d"));
    }

    [Fact]
    public void Given_a_suppressed_prompt_When_retried_Then_it_did_not_consume_the_cooldown()
    {
        var time = new FakeTime();
        var throttle = new PromptThrottle(TimeSpan.FromSeconds(60), maxPromptsPerWindow: 1, window: TimeSpan.FromSeconds(10), timeProvider: time);

        Assert.Equal(PromptSuppression.None, throttle.TryAcquire("a"));
        Assert.Equal(PromptSuppression.RateLimited, throttle.TryAcquire("b"));
        time.Now += TimeSpan.FromSeconds(11);

        Assert.Equal(PromptSuppression.None, throttle.TryAcquire("b"));
    }
}
