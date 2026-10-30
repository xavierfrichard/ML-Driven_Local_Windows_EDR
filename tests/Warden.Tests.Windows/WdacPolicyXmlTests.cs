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
        ledger.RecordHashes("abc", new[] { "aa11", "BB22" });
        ledger.RecordHashes("ABC", new[] { "cc33" });     // same flat hash, different case → merged
        ledger.RecordHashes("def", new[] { "DD44" });

        AllowRuleLedger back = AllowRuleLedger.FromJson(ledger.ToJson());
        Assert.Equal(new[] { "AA11", "BB22", "CC33" }, back.HashesFor("abc").OrderBy(s => s));
        Assert.Equal(new[] { "DD44" }, back.HashesFor("DEF"));
        Assert.Empty(back.HashesFor("nope"));
        Assert.False(back.HasEntry("nope"));

        back.Remove("abc");
        Assert.Empty(back.HashesFor("ABC"));
        Assert.Empty(AllowRuleLedger.FromJson("{ not json").HashesFor("abc"));
    }

    [Fact]
    public void Given_a_legacy_id_only_ledger_When_parsing_Then_its_ids_are_kept_as_legacy_entries()
    {
        Assert.True(AllowRuleLedger.TryParse("{ \"ABC\": [\"ID_ALLOW_A_1\", \"ID_ALLOW_A_2\"] }", out AllowRuleLedger ledger, out string? error), error);

        Assert.Equal(new[] { "ID_ALLOW_A_1", "ID_ALLOW_A_2" }, ledger.LegacyRuleIdsFor("abc").OrderBy(s => s));
        Assert.Empty(ledger.HashesFor("abc"));
        Assert.True(ledger.HasEntry("abc"));
        // Rewritten in the current format, the legacy IDs survive.
        Assert.Equal(new[] { "ID_ALLOW_A_1", "ID_ALLOW_A_2" }, AllowRuleLedger.FromJson(ledger.ToJson()).LegacyRuleIdsFor("ABC").OrderBy(s => s));
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("[1, 2]")]
    [InlineData("{ \"ABC\": 42 }")]
    public void Given_text_that_is_not_a_ledger_When_parsing_Then_it_is_reported_not_treated_as_empty(string json)
    {
        Assert.False(AllowRuleLedger.TryParse(json, out _, out string? error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Hash_lookups_find_rules_by_hash_value_not_id()
    {
        XDocument doc = Sample();
        Assert.Equal(new[] { "ID_ALLOW_A_1", "ID_ALLOW_A_2" }, SupplementalPolicyXml.AllowRuleIdsByHash(doc, new[] { "aa", "BB" }).OrderBy(s => s));
        Assert.Equal(new[] { "AA", "BB" }, SupplementalPolicyXml.AllowRuleHashesForScannedFile(doc, @"C:\ProgramData\Warden\wdac\scan\tool.exe").OrderBy(s => s));
        Assert.Equal(new[] { "CC" }, SupplementalPolicyXml.AllowRuleHashesById(doc, new[] { "ID_ALLOW_A_3", "ID_GONE" }));
        Assert.Equal(new[] { "AA", "BB", "CC" }, SupplementalPolicyXml.AllowRuleHashes(doc).OrderBy(s => s));
    }

    [Fact]
    public void Powershell_single_quote_helper_doubles_quotes()
    {
        Assert.Equal("'a'", WdacAllowlistManager.Ps("a"));
        Assert.Equal("'it''s;'' -bad'", WdacAllowlistManager.Ps("it's;' -bad"));
    }

    [Theory]
    [InlineData('\u2018')]
    [InlineData('\u2019')]
    [InlineData('\u201A')]
    [InlineData('\u201B')]
    public void Given_a_typographic_single_quote_When_quoting_for_PowerShell_Then_it_is_doubled_like_an_ascii_quote(char quote)
    {
        // PowerShell ends a single-quoted string at any of these; doubled, each is one literal character.
        Assert.Equal($"'x{quote}{quote}; calc {quote}{quote}'", WdacAllowlistManager.Ps($"x{quote}; calc {quote}"));
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
