using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Wdac;

namespace Warden.Tests.Windows;

/// <summary>
/// The allow / revoke transaction of <see cref="WdacAllowlistManager"/> (M1, H4), driven through a fake
/// ConfigCI/CiTool: nothing reaches the live XML or ledger unless the deploy succeeded, revokes work by
/// rule hash and fail when nothing was removed, and planted or tampered policies are never deployed.
/// </summary>
public sealed class WdacAllowlistTransactionTests : IDisposable
{
    private const string BaseGuid = "{A25BED84-7550-4AC9-8E03-6BA6E19C766F}";
    private static readonly XNamespace Ns = SupplementalPolicyXml.Ns;

    private readonly string _root;
    private readonly string _work;
    private readonly string _src;
    private readonly FakeWdacPolicyTools _tools = new();
    private readonly WdacAllowlistManager _manager;

    public WdacAllowlistTransactionTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "warden-wdac-tx-" + Guid.NewGuid().ToString("N"));
        _work = Path.Combine(_root, "wdac");
        _src = Path.Combine(_root, "src");
        Directory.CreateDirectory(_src);
        var options = new WdacOptions { WorkDir = _work, BasePolicyGuid = BaseGuid };
        _manager = new WdacAllowlistManager(options, _tools, NullLogger<WdacAllowlistManager>.Instance);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private string LivePath => Path.Combine(_work, "WardenAllowlist.Supplemental.xml");
    private string LedgerPath => Path.Combine(_work, "WardenAllowlist.Ledger.json");

    private (string Path, string Sha, IReadOnlyList<string> RuleHashes) Pe(string name)
    {
        byte[] bytes = new byte[256];
        RandomNumberGenerator.Fill(bytes);
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        string path = Path.Combine(_src, name);
        File.WriteAllBytes(path, bytes);
        return (path, Convert.ToHexString(SHA256.HashData(bytes)), FakeWdacPolicyTools.RuleHashesFor(bytes));
    }

    private async Task<(string Path, string Sha, IReadOnlyList<string> RuleHashes)> AllowedPe(string name)
    {
        var pe = Pe(name);
        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(pe.Path, pe.Sha) });
        Assert.True(r.Success, r.Error);
        return pe;
    }

    private static IReadOnlySet<string> Hashes(XDocument doc) => SupplementalPolicyXml.AllowRuleHashes(doc);

    private XDocument Live() => XDocument.Load(LivePath);

    // ---- M1a: nothing is promoted unless the deploy succeeded -----------------------------------

    [Theory]
    [InlineData("merge")]
    [InlineData("compile")]
    [InlineData("deploy")]
    public async Task Given_a_failing_ConfigCI_or_CiTool_step_When_allowing_Then_live_xml_and_ledger_are_unchanged(string failingStep)
    {
        await AllowedPe("first.exe");
        byte[] xmlBefore = File.ReadAllBytes(LivePath);
        byte[] ledgerBefore = File.ReadAllBytes(LedgerPath);
        var b = Pe("second.exe");

        _tools.FailMerge = failingStep == "merge";
        _tools.FailCompile = failingStep == "compile";
        _tools.FailDeploy = failingStep == "deploy";
        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(b.Path, b.Sha) });

        Assert.False(r.Success);
        Assert.False(r.Files[0].Success);
        Assert.Equal(xmlBefore, File.ReadAllBytes(LivePath));
        Assert.Equal(ledgerBefore, File.ReadAllBytes(LedgerPath));
        Assert.False(File.Exists(Path.Combine(_work, "_staged.Supplemental.xml")));
    }

    [Fact]
    public async Task Given_an_allow_whose_deploy_failed_When_a_later_allow_deploys_Then_the_failed_file_is_not_in_it()
    {
        await AllowedPe("first.exe");
        var failed = Pe("failed.exe");
        _tools.FailDeploy = true;
        Assert.False((await _manager.AllowManyAsync(new[] { new WdacAllowFile(failed.Path, failed.Sha) })).Success);

        _tools.FailDeploy = false;
        var later = await AllowedPe("later.exe");

        IReadOnlySet<string> deployed = Hashes(_tools.LastDeployed!);
        Assert.All(later.RuleHashes, h => Assert.Contains(h, deployed));
        Assert.All(failed.RuleHashes, h => Assert.DoesNotContain(h, deployed));
        Assert.All(failed.RuleHashes, h => Assert.DoesNotContain(h, Hashes(Live())));
        Assert.False(AllowRuleLedger.Load(LedgerPath).HasEntry(failed.Sha));
    }

    [Fact]
    public async Task Given_the_ledger_cannot_be_replaced_after_deploy_When_allowing_Then_previous_xml_is_restored_and_previous_policy_redeployed()
    {
        await AllowedPe("first.exe");
        byte[] xmlBefore = File.ReadAllBytes(LivePath);
        IReadOnlySet<string> hashesBefore = Hashes(Live());
        var b = Pe("second.exe");

        WdacBatchResult r;
        // Readable, but not replaceable (no FILE_SHARE_DELETE), so only the promotion step fails.
        using (new FileStream(LedgerPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(b.Path, b.Sha) });
        }

        Assert.False(r.Success);
        Assert.Equal(3, _tools.Deployed.Count); // first allow, the failed one, the compensating redeploy
        XDocument failedDeploy = _tools.Deployed[1];
        XDocument rollback = _tools.Deployed[2];
        Assert.All(b.RuleHashes, h => Assert.Contains(h, Hashes(failedDeploy)));
        Assert.All(b.RuleHashes, h => Assert.DoesNotContain(h, Hashes(rollback)));
        Assert.Equal(hashesBefore.OrderBy(h => h), Hashes(rollback).OrderBy(h => h));
        Assert.True(Version.Parse(SupplementalPolicyXml.GetVersion(rollback)!) > Version.Parse(SupplementalPolicyXml.GetVersion(failedDeploy)!));
        // The live XML is the previous content (re-versioned above the failed deploy), and the ledger is untouched.
        Assert.Equal(hashesBefore.OrderBy(h => h), Hashes(Live()).OrderBy(h => h));
        Assert.NotEqual(xmlBefore, File.ReadAllBytes(LivePath));
        Assert.False(AllowRuleLedger.Load(LedgerPath).HasEntry(b.Sha));
    }

    [Fact]
    public async Task Given_deploy_fails_When_revoking_Then_rule_and_ledger_entry_stay_and_a_retry_succeeds()
    {
        var a = await AllowedPe("first.exe");
        byte[] xmlBefore = File.ReadAllBytes(LivePath);
        byte[] ledgerBefore = File.ReadAllBytes(LedgerPath);

        _tools.FailDeploy = true;
        WdacUpdateResult r = await _manager.RevokeAsync(a.Sha, "first.exe");
        Assert.False(r.Success);
        Assert.Equal(xmlBefore, File.ReadAllBytes(LivePath));
        Assert.Equal(ledgerBefore, File.ReadAllBytes(LedgerPath));

        _tools.FailDeploy = false;
        WdacUpdateResult retry = await _manager.RevokeAsync(a.Sha, "first.exe");
        Assert.True(retry.Success, retry.Error);
        Assert.Equal($"revoked:{a.Sha}", retry.RuleAdded);
    }

    // ---- M1b: revoke by hash; fail when nothing was removed ------------------------------------

    [Fact]
    public async Task Given_later_merges_renumbered_the_rule_ids_When_revoking_Then_the_rules_are_removed_by_hash()
    {
        var a = await AllowedPe("first.exe");
        var b = await AllowedPe("second.exe"); // this merge renumbers first.exe's rules

        WdacUpdateResult r = await _manager.RevokeAsync(a.Sha, "first.exe");

        Assert.True(r.Success, r.Error);
        Assert.Equal($"revoked:{a.Sha}", r.RuleAdded);
        IReadOnlySet<string> deployed = Hashes(_tools.LastDeployed!);
        Assert.All(a.RuleHashes, h => Assert.DoesNotContain(h, deployed));
        Assert.All(b.RuleHashes, h => Assert.Contains(h, deployed));
        Assert.False(AllowRuleLedger.Load(LedgerPath).HasEntry(a.Sha));
        Assert.True(AllowRuleLedger.Load(LedgerPath).HasEntry(b.Sha));
    }

    [Fact]
    public async Task Given_the_ledger_records_hashes_that_are_not_in_the_policy_When_revoking_Then_it_fails_without_deploying()
    {
        await AllowedPe("first.exe");
        string ghost = new('A', 64);
        AllowRuleLedger ledger = AllowRuleLedger.Load(LedgerPath);
        ledger.RecordHashes(ghost, new[] { new string('B', 64) });
        ledger.Save(LedgerPath);
        int deploys = _tools.DeployCalls;

        WdacUpdateResult r = await _manager.RevokeAsync(ghost, "ghost.exe");

        Assert.False(r.Success);
        Assert.Equal(deploys, _tools.DeployCalls);
        Assert.True(AllowRuleLedger.Load(LedgerPath).HasEntry(ghost));
    }

    [Fact]
    public async Task Given_a_legacy_ledger_whose_rule_ids_were_renumbered_away_When_revoking_Then_it_fails()
    {
        var a = await AllowedPe("first.exe");
        await AllowedPe("second.exe");
        // A pre-hash ledger entry pointing at IDs the merges have since renumbered.
        File.WriteAllText(LedgerPath, $"{{ \"{a.Sha}\": [\"ID_ALLOW_A_1\", \"ID_ALLOW_A_2\"] }}");
        int deploys = _tools.DeployCalls;

        WdacUpdateResult r = await _manager.RevokeAsync(a.Sha, imageName: null);

        Assert.False(r.Success);
        Assert.Equal(deploys, _tools.DeployCalls);
    }

    [Fact]
    public async Task Given_a_legacy_ledger_whose_rule_ids_are_current_When_revoking_Then_every_rule_with_their_hashes_is_removed()
    {
        var a = await AllowedPe("first.exe");
        IReadOnlySet<string> ids = SupplementalPolicyXml.AllowRuleIdsByHash(Live(), a.RuleHashes);
        File.WriteAllText(LedgerPath, $"{{ \"{a.Sha}\": [{string.Join(",", ids.Select(i => $"\"{i}\""))}] }}");

        WdacUpdateResult r = await _manager.RevokeAsync(a.Sha, imageName: null);

        Assert.True(r.Success, r.Error);
        Assert.All(a.RuleHashes, h => Assert.DoesNotContain(h, Hashes(_tools.LastDeployed!)));
    }

    [Fact]
    public async Task Given_no_ledger_entry_and_no_matching_rule_When_revoking_Then_nothing_to_do()
    {
        await AllowedPe("first.exe");
        int deploys = _tools.DeployCalls;

        WdacUpdateResult r = await _manager.RevokeAsync(new string('C', 64), "unknown.exe");

        Assert.True(r.Success, r.Error);
        Assert.Equal("none", r.RuleAdded);
        Assert.Equal(deploys, _tools.DeployCalls);
    }

    [Fact]
    public async Task Given_an_unreadable_ledger_When_allowing_Then_it_refuses_rather_than_forget_recorded_allows()
    {
        await AllowedPe("first.exe");
        File.WriteAllText(LedgerPath, "{ not json");
        var b = Pe("second.exe");

        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(b.Path, b.Sha) });

        Assert.False(r.Success);
        Assert.Equal("{ not json", File.ReadAllText(LedgerPath));
    }

    // ---- H4: a planted or tampered policy is never deployed --------------------------------------

    [Fact]
    public async Task Given_a_planted_supplemental_with_a_filepath_rule_When_allowing_Then_it_is_refused_before_ConfigCI_runs()
    {
        Directory.CreateDirectory(_work);
        File.WriteAllText(LivePath, SupplementalPolicyValidatorTests.Seed(BaseGuid, rules:
            "<Allow ID=\"ID_ALLOW_EVIL\" FriendlyName=\"evil\" FilePath=\"C:\\Users\\*\" />"));
        var a = Pe("first.exe");

        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(a.Path, a.Sha) });

        Assert.False(r.Success);
        Assert.Contains("FilePath", r.Error);
        Assert.Equal(0, _tools.MergeCalls);
        Assert.Equal(0, _tools.DeployCalls);
    }

    [Fact]
    public async Task Given_a_planted_supplemental_with_a_foreign_policy_id_When_revoking_Then_it_is_refused()
    {
        Directory.CreateDirectory(_work);
        File.WriteAllText(LivePath, SupplementalPolicyValidatorTests.Seed(BaseGuid, policyId: "{11111111-2222-3333-4444-555555555555}",
            rules: $"<Allow ID=\"ID_ALLOW_X\" FriendlyName=\"x Hash Sha256\" Hash=\"{new string('D', 64)}\" />"));

        WdacUpdateResult r = await _manager.RevokeAsync(new string('E', 64), "x.exe");

        Assert.False(r.Success);
        Assert.Contains("PolicyID", r.Error);
        Assert.Equal(0, _tools.DeployCalls);
    }

    [Fact]
    public async Task Given_the_merged_policy_gains_a_signer_When_allowing_Then_nothing_is_compiled_or_promoted()
    {
        var a = Pe("first.exe");
        _tools.MutateMerged = doc => doc.Root!.Element(Ns + "Signers")!.Add(
            new XElement(Ns + "Signer", new XAttribute("ID", "ID_SIGNER_X"), new XAttribute("Name", "Evil CA")));

        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(a.Path, a.Sha) });

        Assert.False(r.Success);
        Assert.Equal(0, _tools.CompileCalls);
        Assert.Equal(0, _tools.DeployCalls);
        Assert.False(File.Exists(LivePath));
    }

    [Fact]
    public async Task Given_the_merged_policy_allows_a_hash_no_requested_file_produced_When_allowing_Then_it_is_refused()
    {
        var a = Pe("first.exe");
        _tools.MutateMerged = doc =>
        {
            doc.Root!.Element(Ns + "FileRules")!.Add(new XElement(Ns + "Allow",
                new XAttribute("ID", "ID_ALLOW_PLANTED"), new XAttribute("FriendlyName", "planted Hash Sha256"), new XAttribute("Hash", new string('F', 64))));
            doc.Descendants(Ns + "FileRulesRef").First().Add(new XElement(Ns + "FileRuleRef", new XAttribute("RuleID", "ID_ALLOW_PLANTED")));
        };

        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(a.Path, a.Sha) });

        Assert.False(r.Success);
        Assert.Equal(0, _tools.DeployCalls);
    }

    [Fact]
    public async Task Given_the_scan_copy_is_swapped_while_ConfigCI_runs_When_allowing_Then_it_is_refused()
    {
        var a = Pe("first.exe");
        _tools.AfterMerge = () =>
        {
            string copy = Directory.EnumerateFiles(Path.Combine(_work, "scan"), "first.exe", SearchOption.AllDirectories).Single();
            File.WriteAllBytes(copy, new byte[] { (byte)'M', (byte)'Z', 1, 2, 3 });
        };

        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(a.Path, a.Sha) });

        Assert.False(r.Success);
        Assert.Equal(0, _tools.DeployCalls);
        Assert.False(File.Exists(LivePath));
    }

    [Fact]
    public async Task Given_no_scanned_file_produces_a_rule_When_allowing_Then_nothing_is_deployed()
    {
        string text = Path.Combine(_src, "notes.txt");
        File.WriteAllText(text, "not a PE");

        WdacBatchResult r = await _manager.AllowManyAsync(new[] { new WdacAllowFile(text, null) });

        Assert.False(r.Success);
        Assert.Equal(0, _tools.DeployCalls);
    }
}
