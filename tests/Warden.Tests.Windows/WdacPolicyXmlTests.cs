using System.Xml.Linq;
using Warden.Etw;
using Warden.Wdac;

namespace Warden.Tests.Windows;

/// <summary>
/// The pure XML/ledger logic behind WDAC allow + revoke: rule enumeration, targeted removal (including
/// the FileRuleRef pointers), version bumping, and the flat-hash → rule-id ledger. No ConfigCI needed.
/// </summary>
public sealed class WdacPolicyXmlTests
{
    private const string Ns = "urn:schemas-microsoft-com:sipolicy";

    private static XDocument Sample() => XDocument.Parse($$"""
        <SiPolicy xmlns="{{Ns}}" PolicyType="Supplemental Policy">
          <VersionEx>1.0.0.7</VersionEx>
          <FileRules>
            <Allow ID="ID_ALLOW_A_1" FriendlyName="C:\ProgramData\Warden\wdac\scan\tool.exe Hash Sha1" Hash="AA" />
            <Allow ID="ID_ALLOW_A_2" FriendlyName="C:\ProgramData\Warden\wdac\scan\tool.exe Hash Sha256" Hash="BB" />
            <Allow ID="ID_ALLOW_A_3" FriendlyName="C:\ProgramData\Warden\wdac\scan\other.exe Hash Sha256" Hash="CC" />
          </FileRules>
          <SigningScenarios>
            <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode">
              <ProductSigners>
                <FileRulesRef>
                  <FileRuleRef RuleID="ID_ALLOW_A_1" />
                  <FileRuleRef RuleID="ID_ALLOW_A_2" />
                  <FileRuleRef RuleID="ID_ALLOW_A_3" />
                </FileRulesRef>
              </ProductSigners>
            </SigningScenario>
          </SigningScenarios>
          <BasePolicyID>{A25BED84-7550-4AC9-8E03-6BA6E19C766F}</BasePolicyID>
          <PolicyID>{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}</PolicyID>
        </SiPolicy>
        """);

    [Fact]
    public void Allow_rule_ids_are_enumerated()
    {
        IReadOnlySet<string> ids = SupplementalPolicyXml.AllowRuleIds(Sample());
        Assert.Equal(new[] { "ID_ALLOW_A_1", "ID_ALLOW_A_2", "ID_ALLOW_A_3" }, ids.OrderBy(s => s));
    }

    [Fact]
    public void Removing_rules_also_removes_their_file_rule_refs()
    {
        XDocument doc = Sample();
        int removed = SupplementalPolicyXml.RemoveAllowRules(doc, new[] { "ID_ALLOW_A_1", "ID_ALLOW_A_2" });

        Assert.Equal(2, removed);
        Assert.Equal(new[] { "ID_ALLOW_A_3" }, SupplementalPolicyXml.AllowRuleIds(doc));
        var refs = doc.Descendants(XName.Get("FileRuleRef", Ns)).Select(r => (string?)r.Attribute("RuleID")).ToList();
        Assert.Equal(new[] { "ID_ALLOW_A_3" }, refs);
    }

    [Fact]
    public void Friendly_name_prefix_finds_the_rules_new_cipolicy_generated_for_a_file()
    {
        IReadOnlySet<string> ids = SupplementalPolicyXml.AllowRuleIdsByFriendlyNamePrefix(
            Sample(), @"C:\ProgramData\Warden\wdac\scan\tool.exe");
        Assert.Equal(new[] { "ID_ALLOW_A_1", "ID_ALLOW_A_2" }, ids.OrderBy(s => s));
    }

    [Fact]
    public void Scanned_file_name_lookup_matches_flat_and_batch_layouts_under_the_scan_root()
    {
        XDocument doc = XDocument.Parse($$"""
            <SiPolicy xmlns="{{Ns}}">
              <FileRules>
                <Allow ID="A" FriendlyName="C:\ProgramData\Warden\wdac\scan\tool.exe Hash Sha256" Hash="1" />
                <Allow ID="B" FriendlyName="C:\ProgramData\Warden\wdac\scan\0007\tool.exe Hash Page Sha1" Hash="2" />
                <Allow ID="C" FriendlyName="C:\ProgramData\Warden\wdac\scan\0008\other.exe Hash Sha256" Hash="3" />
                <Allow ID="D" FriendlyName="C:\Elsewhere\tool.exe Hash Sha256" Hash="4" />
              </FileRules>
            </SiPolicy>
            """);
        IReadOnlySet<string> ids = SupplementalPolicyXml.AllowRuleIdsByScannedFileName(doc, "tool.exe", @"C:\ProgramData\Warden\wdac\scan");
        Assert.Equal(new[] { "A", "B" }, ids.OrderBy(s => s));
    }

    [Fact]
    public void Version_bump_increments_the_revision_and_creates_a_missing_element()
    {
        XDocument doc = Sample();
        Assert.Equal("1.0.0.8", SupplementalPolicyXml.BumpVersion(doc));
        Assert.Equal("1.0.0.9", SupplementalPolicyXml.BumpVersion(doc));

        XDocument bare = XDocument.Parse($"<SiPolicy xmlns=\"{Ns}\"><PolicyID>x</PolicyID></SiPolicy>");
        Assert.Equal("1.0.0.1", SupplementalPolicyXml.BumpVersion(bare));
        Assert.Equal("1.0.0.1", bare.Root!.Element(XName.Get("VersionEx", Ns))!.Value);
    }

    [Fact]
    public void Ledger_round_trips_and_merges()
    {
        var ledger = new AllowRuleLedger();
        ledger.Record("abc", new[] { "ID_1", "ID_2" });
        ledger.Record("ABC", new[] { "ID_3" });     // same hash, different case → merged
        ledger.Record("def", new[] { "ID_9" });

        AllowRuleLedger back = AllowRuleLedger.FromJson(ledger.ToJson());
        Assert.Equal(new[] { "ID_1", "ID_2", "ID_3" }, back.RulesFor("abc").OrderBy(s => s));
        Assert.Equal(new[] { "ID_9" }, back.RulesFor("DEF"));
        Assert.Empty(back.RulesFor("nope"));

        back.Remove("abc");
        Assert.Empty(back.RulesFor("ABC"));
        Assert.Empty(AllowRuleLedger.FromJson("{ not json").RulesFor("abc"));
    }

    [Fact]
    public void Powershell_single_quote_helper_doubles_quotes()
    {
        Assert.Equal("'a'", WdacAllowlistManager.Ps("a"));
        Assert.Equal("'it''s;'' -bad'", WdacAllowlistManager.Ps("it's;' -bad"));
    }

    [Fact]
    public void Wdac_options_pin_citool_to_system32()
    {
        Assert.StartsWith(Environment.SystemDirectory, new WdacOptions().CiToolPath, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith(Environment.SystemDirectory, ProcessRunner.PowerShellPath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Process_runner_refuses_bare_executable_names()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => new ProcessRunner().RunAsync("powershell.exe", "-?", TimeSpan.FromSeconds(1)));
    }
}

/// <summary>Correlation must use full paths only — a same-named decoy must not match.</summary>
public sealed class PathCorrelationTests
{
    [Fact]
    public void Strict_equality_ignores_case_but_not_directory()
    {
        Assert.True(PathUtil.PathsEqualStrict(@"C:\Users\bob\evil.exe", @"c:\users\BOB\evil.exe"));
        Assert.False(PathUtil.PathsEqualStrict(@"C:\Users\bob\chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        Assert.False(PathUtil.PathsEqualStrict(string.Empty, @"C:\x.exe"));
    }

    [Fact]
    public void Lenient_equality_still_matches_by_name_for_display_purposes()
    {
        Assert.True(PathUtil.PathsEqual(@"C:\Users\bob\chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe"));
    }
}
