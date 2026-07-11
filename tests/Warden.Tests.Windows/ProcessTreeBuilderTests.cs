using Microsoft.Extensions.Logging.Abstractions;
using Warden.AttackChain;
using Warden.Core;
using Warden.Etw;
using Warden.Storage;

namespace Warden.Tests.Windows;

public sealed class ProcessTreeBuilderTests
{
    [Fact]
    public void BuildChainFor_reconstructs_ancestry_root_first_nearest_parent_last()
    {
        var builder = new ProcessTreeBuilder(new FakeChainRepo(), new ChainSuspicionScorer(), NullLogger<ProcessTreeBuilder>.Instance);

        // explorer(4) -> cmd(100) -> powershell(200)
        builder.RecordStart(Start(pid: 4, parent: 0, @"C:\Windows\explorer.exe"));
        builder.RecordStart(Start(pid: 100, parent: 4, @"C:\Windows\System32\cmd.exe"));
        builder.RecordStart(Start(pid: 200, parent: 100, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));

        AttackChainNode chain = builder.BuildChainFor(200);

        Assert.Equal("powershell.exe", chain.ImageName);
        Assert.Equal(2, chain.Depth);
        Assert.Equal(2, chain.Ancestors.Length);
        Assert.Equal("explorer.exe", chain.Ancestors[0].ImageName);  // root first
        Assert.Equal("cmd.exe", chain.Ancestors[^1].ImageName);      // nearest parent last
    }

    [Fact]
    public void BuildChainFor_unknown_pid_is_none()
    {
        var builder = new ProcessTreeBuilder(new FakeChainRepo(), new ChainSuspicionScorer(), NullLogger<ProcessTreeBuilder>.Instance);
        Assert.Same(AttackChainNode.None, builder.BuildChainFor(9999));
    }

    [Fact]
    public void Suspicion_scorer_flags_office_spawning_a_shell()
    {
        var scorer = new ChainSuspicionScorer();
        var parent = new AttackChainNode(50, 0, @"C:\Office\winword.exe", null, "winword", DateTimeOffset.UtcNow, 0,
            System.Collections.Immutable.ImmutableArray<AttackChainNode>.Empty);
        var node = new AttackChainNode(60, 50, @"C:\Windows\System32\cmd.exe", null, "cmd", DateTimeOffset.UtcNow, 1,
            System.Collections.Immutable.ImmutableArray.Create(parent));

        double score = scorer.Score(node);
        Assert.True(score >= 0.4, $"expected a strong suspicion score, got {score}");
    }

    private static ProcessStartRecord Start(int pid, int parent, string image) =>
        new(pid, parent, image, image, DateTimeOffset.UtcNow, null);

    private sealed class FakeChainRepo : IAttackChainRepository
    {
        public Task<long> AddNodeAsync(AttackChainRecord node, CancellationToken ct = default) => Task.FromResult(1L);
        public Task<IReadOnlyList<AttackChainRecord>> GetRecentAsync(int limit = 500, CancellationToken ct = default) =>
            Task.FromResult((IReadOnlyList<AttackChainRecord>)Array.Empty<AttackChainRecord>());
    }
}
