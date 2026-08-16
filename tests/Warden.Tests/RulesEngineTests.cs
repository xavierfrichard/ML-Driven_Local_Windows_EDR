using Warden.Core;
using Warden.Rules;
using Warden.Storage;

namespace Warden.Tests;

public sealed class RulesEngineTests
{
    private static readonly SignerInfo TrustedSigner =
        new(IsSigned: true, IsValid: true, "CN=Trusted", "CN=CA", "THUMB", IsMicrosoft: false);

    [Fact]
    public async Task Hash_allow_rule_allows_matching_file()
    {
        var rules = new FakeRules(Rule(RuleKind.Hash, "ABC", PolicyAction.Allow));
        var engine = new RulesEngine(rules, new FakeWhitelist());

        var result = await engine.EvaluateAsync(TestData.Context(sha256: "abc"), default);

        Assert.Equal(Verdict.Allow, result.Verdict);
        Assert.Equal(VerdictSourceKind.Rules, result.Source);
    }

    [Fact]
    public async Task Block_rule_wins_over_a_matching_allow_rule()
    {
        var rules = new FakeRules(
            Rule(RuleKind.Extension, ".exe", PolicyAction.Allow),
            Rule(RuleKind.Hash, "ABC", PolicyAction.Block));
        var engine = new RulesEngine(rules, new FakeWhitelist());

        var result = await engine.EvaluateAsync(
            TestData.Context(imagePath: @"C:\x\a.exe", sha256: "ABC"), default);

        Assert.Equal(Verdict.Block, result.Verdict); // deny wins
    }

    [Fact]
    public async Task No_matching_rule_is_undecided()
    {
        var rules = new FakeRules(Rule(RuleKind.Hash, "OTHER", PolicyAction.Allow));
        var engine = new RulesEngine(rules, new FakeWhitelist());

        var result = await engine.EvaluateAsync(TestData.Context(sha256: "ABC"), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.False(result.Decisive);
    }

    [Fact]
    public async Task RequireSignature_allow_declines_for_unsigned_file()
    {
        var rules = new FakeRules(Rule(RuleKind.Extension, ".exe", PolicyAction.Allow, requireSignature: true));
        var engine = new RulesEngine(rules, new FakeWhitelist());

        var result = await engine.EvaluateAsync(
            TestData.Context(imagePath: @"C:\x\a.exe"), default); // unsigned

        Assert.Equal(Verdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task RequireSignature_allow_permits_trusted_signed_file()
    {
        var rules = new FakeRules(Rule(RuleKind.Extension, ".exe", PolicyAction.Allow, requireSignature: true));
        var engine = new RulesEngine(rules, new FakeWhitelist());

        var result = await engine.EvaluateAsync(
            TestData.Context(imagePath: @"C:\x\a.exe", signer: TrustedSigner), default);

        Assert.Equal(Verdict.Allow, result.Verdict);
    }

    [Fact]
    public async Task RequireWhitelist_allow_needs_an_existing_allow_row()
    {
        var rule = Rule(RuleKind.Folder, @"C:\x\", PolicyAction.Allow, requireWhitelist: true);
        var withoutWhitelist = new RulesEngine(new FakeRules(rule), new FakeWhitelist());
        var withWhitelist = new RulesEngine(new FakeRules(rule),
            new FakeWhitelist(new WhitelistEntry
            {
                Timestamp = DateTimeOffset.UtcNow, Action = PolicyAction.Allow,
                ProcessName = "a.exe", ProcessPath = @"C:\x\a.exe", Sha256 = "ABC", Source = "Test",
            }));

        var ctx = TestData.Context(imagePath: @"C:\x\a.exe", sha256: "ABC");

        Assert.Equal(Verdict.Unknown, (await withoutWhitelist.EvaluateAsync(ctx, default)).Verdict);
        Assert.Equal(Verdict.Allow, (await withWhitelist.EvaluateAsync(ctx, default)).Verdict);
    }

    private static RuleEntry Rule(
        RuleKind kind, string value, PolicyAction action,
        bool requireSignature = false, bool requireWhitelist = false) => new()
    {
        Id = 1,
        Kind = kind,
        MatchValue = value,
        Action = action,
        RequireSignature = requireSignature,
        RequireWhitelist = requireWhitelist,
        Enabled = true,
        CreatedTs = DateTimeOffset.UtcNow,
    };

    private sealed class FakeRules : IRulesRepository
    {
        private readonly List<RuleEntry> _rules;
        public FakeRules(params RuleEntry[] rules) => _rules = rules.ToList();
        public Task<long> AddAsync(RuleEntry rule, CancellationToken ct = default) => Task.FromResult(1L);
        public Task<IReadOnlyList<RuleEntry>> GetEnabledAsync(CancellationToken ct = default) =>
            Task.FromResult((IReadOnlyList<RuleEntry>)_rules.Where(r => r.Enabled).ToList());
        public Task<IReadOnlyList<RuleEntry>> GetAllAsync(CancellationToken ct = default) =>
            Task.FromResult((IReadOnlyList<RuleEntry>)_rules);
        public Task DeleteAsync(long id, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class FakeWhitelist : IWhitelistRepository
    {
        private readonly WhitelistEntry? _latest;
        public FakeWhitelist(WhitelistEntry? latest = null) => _latest = latest;
        public Task<long> AddAsync(WhitelistEntry entry, CancellationToken ct = default) => Task.FromResult(1L);
        public Task<WhitelistEntry?> FindLatestBySha256Async(string sha256, CancellationToken ct = default) =>
            Task.FromResult(_latest);
        public Task<IReadOnlyList<WhitelistEntry>> GetAllAsync(int limit = 1000, CancellationToken ct = default) =>
            Task.FromResult((IReadOnlyList<WhitelistEntry>)Array.Empty<WhitelistEntry>());
        public Task SetActionAsync(long id, PolicyAction action, CancellationToken ct = default) => Task.CompletedTask;
        public Task<WhitelistEntry?> GetByIdAsync(long id, CancellationToken ct = default) => Task.FromResult<WhitelistEntry?>(null);
    }
}
