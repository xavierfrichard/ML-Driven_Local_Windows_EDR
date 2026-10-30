using Microsoft.Extensions.Logging.Abstractions;
using Warden.Hardening;
using Warden.Storage;

namespace Warden.Tests.Windows;

/// <summary>Startup audit that disables stored Folder → Allow rules on folders non-admins can change.</summary>
public sealed class FolderRuleAuditTests
{
    [Fact]
    public async Task Only_unsafe_folder_allow_rules_are_disabled_and_each_is_logged()
    {
        var rules = new FakeRules(
            Rule(1, RuleKind.Folder, @"C:\Users\bob\Downloads\", PolicyAction.Allow),   // unsafe
            Rule(2, RuleKind.Folder, @"C:\Program Files\App\", PolicyAction.Allow),     // safe
            Rule(3, RuleKind.Folder, @"C:\Users\bob\Downloads\", PolicyAction.Block),   // blocks are never touched
            Rule(4, RuleKind.Hash, new string('A', 64), PolicyAction.Allow));
        var tamper = new FakeTamperLog();

        int disabled = await FolderRuleAudit.DisableUnsafeFolderAllowsAsync(
            rules, tamper, NullLogger.Instance,
            check: folder => folder.StartsWith(@"C:\Users\", StringComparison.OrdinalIgnoreCase) ? "bob can write to it." : null);

        Assert.Equal(1, disabled);
        Assert.Equal(new long[] { 1 }, rules.Disabled);
        var entry = Assert.Single(tamper.Entries);
        Assert.Equal(FolderRuleAudit.Category, entry.Category);
        Assert.Contains("#1", entry.Detail, StringComparison.Ordinal);
        Assert.Contains("bob can write to it.", entry.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_check_that_throws_disables_the_rule()
    {
        var rules = new FakeRules(Rule(7, RuleKind.Folder, @"C:\Tools\", PolicyAction.Allow));
        var tamper = new FakeTamperLog();

        int disabled = await FolderRuleAudit.DisableUnsafeFolderAllowsAsync(
            rules, tamper, NullLogger.Instance, check: _ => throw new InvalidOperationException("boom"));

        Assert.Equal(1, disabled);
        Assert.Equal(new long[] { 7 }, rules.Disabled);
    }

    [Fact]
    public async Task A_rule_that_cannot_be_disabled_is_logged_as_critical()
    {
        var rules = new FakeRules(Rule(9, RuleKind.Folder, @"C:\Tools\", PolicyAction.Allow)) { FailDisable = true };
        var tamper = new FakeTamperLog();

        int disabled = await FolderRuleAudit.DisableUnsafeFolderAllowsAsync(
            rules, tamper, NullLogger.Instance, check: _ => "Users can write to it.");

        Assert.Equal(0, disabled);
        Assert.Equal("critical", Assert.Single(tamper.Entries).Severity);
    }

    [Fact]
    public async Task The_default_check_disables_a_rule_for_a_missing_folder()
    {
        string missing = Path.Combine(Path.GetTempPath(), "warden-gone-" + Guid.NewGuid().ToString("N")) + @"\";
        var rules = new FakeRules(Rule(5, RuleKind.Folder, missing, PolicyAction.Allow));

        int disabled = await FolderRuleAudit.DisableUnsafeFolderAllowsAsync(rules, new FakeTamperLog(), NullLogger.Instance);

        Assert.Equal(1, disabled);
    }

    private static RuleEntry Rule(long id, RuleKind kind, string value, PolicyAction action) => new()
    {
        Id = id,
        Kind = kind,
        MatchValue = value,
        Action = action,
        Enabled = true,
        CreatedTs = DateTimeOffset.UtcNow,
    };

    private sealed class FakeRules : IRulesRepository
    {
        private readonly List<RuleEntry> _rules;
        public FakeRules(params RuleEntry[] rules) => _rules = rules.ToList();
        public bool FailDisable { get; init; }
        public List<long> Disabled { get; } = new();
        public Task<long> AddAsync(RuleEntry rule, CancellationToken cancellationToken = default) => Task.FromResult(1L);
        public Task<IReadOnlyList<RuleEntry>> GetEnabledAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((IReadOnlyList<RuleEntry>)_rules.Where(r => r.Enabled).ToList());
        public Task<IReadOnlyList<RuleEntry>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((IReadOnlyList<RuleEntry>)_rules);
        public Task DeleteAsync(long id, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task SetEnabledAsync(long id, bool enabled, CancellationToken cancellationToken = default)
        {
            if (FailDisable)
            {
                throw new IOException("database is locked");
            }
            Disabled.Add(id);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTamperLog : ITamperLog
    {
        public List<(string Category, string? Detail, string Severity)> Entries { get; } = new();
        public Task LogAsync(string category, string? detail = null, string severity = "warning", CancellationToken cancellationToken = default)
        {
            Entries.Add((category, detail, severity));
            return Task.CompletedTask;
        }
    }
}
