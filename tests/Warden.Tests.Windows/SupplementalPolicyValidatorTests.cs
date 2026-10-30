using System.Xml.Linq;
using Warden.Wdac;

namespace Warden.Tests.Windows;

/// <summary>
/// H4: what <see cref="SupplementalPolicyValidator"/> accepts (a Warden hash-only supplemental under the
/// fixed PolicyID, linked to the expected base) and the shapes a planted policy could take that it refuses.
/// </summary>
public sealed class SupplementalPolicyValidatorTests
{
    private const string BaseGuid = "{A25BED84-7550-4AC9-8E03-6BA6E19C766F}";
    private const string Sha256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    private const string Sha1 = "0123456789ABCDEF0123456789ABCDEF01234567";

    /// <summary>A Warden-shaped supplemental with the given pieces swapped in.</summary>
    internal static string Seed(
        string baseGuid,
        string rules = "",
        string policyId = WdacAllowlistManager.SupplementalPolicyId,
        string policyType = "Supplemental Policy",
        string options = "<Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule><Rule><Option>Enabled:Inherit Default Policy</Option></Rule>",
        string signers = "",
        string kernelSigners = "",
        string userSigners = "") => $"""
        <?xml version="1.0" encoding="utf-8"?>
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="{policyType}">
          <VersionEx>1.0.0.3</VersionEx>
          <Rules>{options}</Rules>
          <EKUs />
          <FileRules>{rules}</FileRules>
          <Signers>{signers}</Signers>
          <SigningScenarios>
            <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Kernel Mode">
              <ProductSigners>{kernelSigners}</ProductSigners>
            </SigningScenario>
            <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode">
              <ProductSigners>{userSigners}</ProductSigners>
            </SigningScenario>
          </SigningScenarios>
          <UpdatePolicySigners />
          <CiSigners />
          <HvciOptions>0</HvciOptions>
          <BasePolicyID>{baseGuid}</BasePolicyID>
          <PolicyID>{policyId}</PolicyID>
        </SiPolicy>
        """;

    private const string HashRules = $"""
        <Allow ID="ID_ALLOW_A_1" FriendlyName="C:\scan\0000\a.exe Hash Sha1" Hash="{Sha1}" />
        <Allow ID="ID_ALLOW_A_2" FriendlyName="C:\scan\0000\a.exe Hash Sha256" Hash="{Sha256}" />
        """;

    private const string HashRefs = "<FileRulesRef><FileRuleRef RuleID=\"ID_ALLOW_A_1\" /><FileRuleRef RuleID=\"ID_ALLOW_A_2\" /></FileRulesRef>";

    private static IReadOnlyList<string> Check(string xml, string? expectedBase = BaseGuid, bool allowUnlinked = false) =>
        SupplementalPolicyValidator.Validate(XDocument.Parse(xml), WdacAllowlistManager.SupplementalPolicyId, expectedBase, allowUnlinked);

    [Fact]
    public void Given_a_hash_only_supplemental_linked_to_the_base_When_validating_Then_it_is_accepted()
    {
        Assert.Empty(Check(Seed(BaseGuid, HashRules, userSigners: HashRefs)));
        // Brace-less, lower-case GUIDs (as CiTool prints them) compare equal.
        Assert.Empty(Check(Seed(BaseGuid, HashRules, userSigners: HashRefs), expectedBase: "a25bed84-7550-4ac9-8e03-6ba6e19c766f"));
    }

    [Fact]
    public void Given_the_unlinked_seed_When_validating_as_current_state_Then_it_is_accepted_but_never_for_deploy()
    {
        string seed = Seed("{00000000-0000-0000-0000-000000000000}");
        Assert.Empty(Check(seed, expectedBase: null, allowUnlinked: true));
        Assert.NotEmpty(Check(seed));
    }

    public static IEnumerable<object[]> Rejections()
    {
        yield return new object[] { "foreign PolicyID", Seed(BaseGuid, policyId: "{11111111-2222-3333-4444-555555555555}"), "PolicyID" };
        yield return new object[] { "base policy type", Seed(BaseGuid, policyType: "Base Policy"), "PolicyType" };
        yield return new object[] { "other base", Seed("{BBBBBBBB-7550-4AC9-8E03-6BA6E19C766F}"), "expected base" };
        yield return new object[] { "unlinked", Seed("{00000000-0000-0000-0000-000000000000}"), "all zeros" };
        yield return new object[] { "self-based", Seed(WdacAllowlistManager.SupplementalPolicyId), "equals PolicyID" };
        yield return new object[] { "FilePath allow", Seed(BaseGuid, "<Allow ID=\"ID_ALLOW_P\" FriendlyName=\"p\" FilePath=\"C:\\Users\\*\" />"), "FilePath" };
        yield return new object[] { "FileName allow", Seed(BaseGuid, $"<Allow ID=\"ID_ALLOW_N\" FriendlyName=\"n\" FileName=\"evil.exe\" Hash=\"{Sha256}\" />"), "FileName" };
        yield return new object[] { "version range", Seed(BaseGuid, $"<Allow ID=\"ID_ALLOW_V\" FriendlyName=\"v\" Hash=\"{Sha256}\" MinimumFileVersion=\"0.0.0.0\" />"), "MinimumFileVersion" };
        yield return new object[] { "allow without hash", Seed(BaseGuid, "<Allow ID=\"ID_ALLOW_H\" FriendlyName=\"h\" />"), "Hash" };
        yield return new object[] { "malformed hash", Seed(BaseGuid, "<Allow ID=\"ID_ALLOW_H\" FriendlyName=\"h\" Hash=\"XYZ\" />"), "Hash" };
        yield return new object[] { "FileAttrib rule", Seed(BaseGuid, "<FileAttrib ID=\"ID_FILEATTRIB_1\" FriendlyName=\"a\" FileName=\"x.exe\" />"), "FileAttrib" };
        yield return new object[] { "Deny rule", Seed(BaseGuid, $"<Deny ID=\"ID_DENY_1\" FriendlyName=\"d\" Hash=\"{Sha256}\" />"), "Deny" };
        yield return new object[] { "signer", Seed(BaseGuid, signers: "<Signer ID=\"ID_SIGNER_1\" Name=\"Evil CA\"><CertRoot Type=\"TBS\" Value=\"00\" /></Signer>"), "Signers" };
        yield return new object[] { "allowed signers", Seed(BaseGuid, userSigners: "<AllowedSigners><AllowedSigner SignerId=\"ID_SIGNER_1\" /></AllowedSigners>"), "AllowedSigners" };
        yield return new object[] { "kernel-mode ref", Seed(BaseGuid, HashRules, kernelSigners: HashRefs), "scenario 131" };
        yield return new object[] { "dangling ref", Seed(BaseGuid, userSigners: "<FileRulesRef><FileRuleRef RuleID=\"ID_ALLOW_GONE\" /></FileRulesRef>"), "points at no" };
        yield return new object[] { "managed installer", Seed(BaseGuid, options: "<Rule><Option>Enabled:Managed Installer</Option></Rule>"), "Managed Installer" };
        yield return new object[] { "filepath protection off", Seed(BaseGuid, options: "<Rule><Option>Disabled:Runtime FilePath Rule Protection</Option></Rule>"), "FilePath Rule Protection" };
        yield return new object[] { "ISG", Seed(BaseGuid, options: "<Rule><Option>Enabled:Intelligent Security Graph Authorization</Option></Rule>"), "Intelligent Security Graph" };
    }

    [Theory]
    [MemberData(nameof(Rejections))]
    public void Given_a_policy_that_is_not_a_warden_hash_supplemental_When_validating_Then_it_is_rejected(string label, string xml, string expectedInError)
    {
        IReadOnlyList<string> errors = Check(xml);
        Assert.True(errors.Count > 0, $"'{label}' was accepted.");
        Assert.Contains(errors, e => e.Contains(expectedInError, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Given_a_non_policy_document_When_validating_Then_it_is_rejected()
    {
        Assert.NotEmpty(Check("<Other xmlns=\"urn:x\" />"));
    }
}
