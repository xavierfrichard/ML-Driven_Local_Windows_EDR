using System.Xml.Linq;

namespace Warden.Wdac;

/// <summary>
/// Checks that a supplemental policy XML is one Warden would have produced before it is compiled and
/// deployed. The XML lives on disk between runs, so a file planted or edited there (H4) must never be
/// merged and deployed as-is: anything other than per-file hash allows under Warden's own PolicyID,
/// linked to the expected base, is refused.
/// </summary>
/// <remarks>
/// What is accepted:
/// <list type="bullet">
/// <item><c>PolicyType="Supplemental Policy"</c>, <c>PolicyID</c> = the fixed Warden ID, and a
/// <c>BasePolicyID</c> that is a real GUID other than the policy's own (and equal to the expected base when
/// one is given).</item>
/// <item><c>&lt;FileRules&gt;</c> holding only <c>&lt;Allow ID FriendlyName Hash/&gt;</c> with a SHA-1 or
/// SHA-256 hex hash: no <c>FilePath</c>, <c>FileName</c>, version or package attributes, no Deny/FileAttrib.</item>
/// <item>No signers anywhere (<c>Signers</c>, <c>AllowedSigners</c>, <c>DeniedSigners</c>,
/// <c>UpdatePolicySigners</c>, <c>CiSigners</c>, <c>SupplementalPolicySigners</c> must be empty or absent).</item>
/// <item><c>FileRuleRef</c>s only in the user-mode scenario (12), each pointing at an existing Allow.</item>
/// <item>Rule options limited to <see cref="AllowedOptions"/>. Options such as Managed Installer, ISG
/// authorization or Disabled:Runtime FilePath Rule Protection widen what a supplemental allows.</item>
/// </list>
/// </remarks>
public static class SupplementalPolicyValidator
{
    private static readonly XNamespace Ns = SupplementalPolicyXml.Ns;

    /// <summary>The rule options a Warden supplemental may carry.</summary>
    public static readonly IReadOnlySet<string> AllowedOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Enabled:Unsigned System Integrity Policy",
        "Enabled:Inherit Default Policy",
    };

    private static readonly HashSet<string> AllowedAllowAttributes = new(StringComparer.Ordinal) { "ID", "FriendlyName", "Hash" };

    private static readonly string[] SignerContainers =
    {
        "Signers", "UpdatePolicySigners", "CiSigners", "SupplementalPolicySigners",
    };

    /// <summary>
    /// Returns every problem found (empty when the policy is acceptable).
    /// </summary>
    /// <param name="doc">The supplemental policy.</param>
    /// <param name="expectedPolicyId">Warden's fixed supplemental PolicyID.</param>
    /// <param name="expectedBasePolicyId">
    /// The base the policy must supplement, or null to accept any linked base (a real GUID that is not the
    /// policy's own ID).
    /// </param>
    /// <param name="allowUnlinked">Accept an all-zeros BasePolicyID (the seed template, before linkage).</param>
    public static IReadOnlyList<string> Validate(XDocument doc, string expectedPolicyId, string? expectedBasePolicyId, bool allowUnlinked = false)
    {
        ArgumentNullException.ThrowIfNull(doc);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedPolicyId);
        var errors = new List<string>();

        XElement? root = doc.Root;
        if (root is null || root.Name != Ns + "SiPolicy")
        {
            errors.Add("Root element is not a ConfigCI SiPolicy.");
            return errors;
        }

        string? type = (string?)root.Attribute("PolicyType");
        if (!string.Equals(type, "Supplemental Policy", StringComparison.Ordinal))
        {
            errors.Add($"PolicyType is '{type ?? "(none)"}', expected 'Supplemental Policy'.");
        }

        Guid? policyId = ParseGuid(SupplementalPolicyXml.PolicyId(doc));
        Guid? expectedId = ParseGuid(expectedPolicyId);
        if (policyId is null || expectedId is null || policyId != expectedId)
        {
            errors.Add($"PolicyID is '{SupplementalPolicyXml.PolicyId(doc) ?? "(none)"}', expected {expectedPolicyId}.");
        }

        string? baseText = SupplementalPolicyXml.BasePolicyId(doc);
        Guid? baseId = ParseGuid(baseText);
        if (baseId is null)
        {
            errors.Add($"BasePolicyID '{baseText ?? "(none)"}' is not a GUID.");
        }
        else if (baseId == Guid.Empty)
        {
            if (!allowUnlinked)
            {
                errors.Add("BasePolicyID is all zeros (not linked to a base).");
            }
        }
        else if (baseId == policyId)
        {
            errors.Add("BasePolicyID equals PolicyID (that is a base policy, not a supplemental).");
        }
        else if (expectedBasePolicyId is not null && baseId != ParseGuid(expectedBasePolicyId))
        {
            errors.Add($"BasePolicyID {baseText} is not the expected base {expectedBasePolicyId}.");
        }

        foreach (XElement option in root.Elements(Ns + "Rules").Elements(Ns + "Rule").Elements(Ns + "Option"))
        {
            string value = option.Value.Trim();
            if (!AllowedOptions.Contains(value))
            {
                errors.Add($"Unexpected rule option '{value}'.");
            }
        }

        var allowIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (XElement fileRules in root.Elements(Ns + "FileRules"))
        {
            foreach (XElement rule in fileRules.Elements())
            {
                string id = (string?)rule.Attribute("ID") ?? "(no ID)";
                if (rule.Name != Ns + "Allow")
                {
                    errors.Add($"File rule {id} is a <{rule.Name.LocalName}>; only hash <Allow> rules are accepted.");
                    continue;
                }
                foreach (XAttribute a in rule.Attributes())
                {
                    if (!AllowedAllowAttributes.Contains(a.Name.LocalName) || a.Name.Namespace != XNamespace.None)
                    {
                        errors.Add($"Allow rule {id} has a '{a.Name.LocalName}' attribute; only hash rules are accepted.");
                    }
                }
                if (rule.HasElements)
                {
                    errors.Add($"Allow rule {id} has child elements.");
                }
                if (!IsHashValue((string?)rule.Attribute("Hash")))
                {
                    errors.Add($"Allow rule {id} has no SHA-1/SHA-256 Hash.");
                }
                if (rule.Attribute("ID") is null)
                {
                    errors.Add("An Allow rule has no ID.");
                }
                else if (!allowIds.Add(id))
                {
                    errors.Add($"Allow rule ID {id} is duplicated.");
                }
            }
        }
        if (root.Elements(Ns + "FileRules").Count() > 1)
        {
            errors.Add("More than one <FileRules> element.");
        }

        foreach (string container in SignerContainers)
        {
            foreach (XElement e in root.Elements(Ns + container))
            {
                if (e.HasElements)
                {
                    errors.Add($"<{container}> is not empty; a Warden supplemental carries no signers.");
                }
            }
        }

        foreach (XElement scenario in root.Elements(Ns + "SigningScenarios").Elements(Ns + "SigningScenario"))
        {
            string value = (string?)scenario.Attribute("Value") ?? "?";
            foreach (XElement e in scenario.Descendants())
            {
                string local = e.Name.LocalName;
                // An empty container grants nothing; any signer entry does.
                if ((local is "AllowedSigners" or "DeniedSigners" && e.HasElements)
                    || local is "AllowedSigner" or "DeniedSigner" or "ExceptDenyRule" or "ExceptAllowRule")
                {
                    errors.Add($"Signing scenario {value} contains <{local}>; signer rules are not accepted.");
                }
                else if (local == "FileRuleRef")
                {
                    string rid = (string?)e.Attribute("RuleID") ?? string.Empty;
                    if (value != "12")
                    {
                        errors.Add($"FileRuleRef {rid} is in signing scenario {value}; only user mode (12) is accepted.");
                    }
                    else if (!allowIds.Contains(rid))
                    {
                        errors.Add($"FileRuleRef {rid} points at no hash Allow rule.");
                    }
                }
            }
        }

        return errors;
    }

    /// <summary>True when <paramref name="value"/> is a hex SHA-1 (40) or SHA-256 (64) digest.</summary>
    public static bool IsHashValue(string? value) =>
        value is { Length: 40 or 64 } && value.All(Uri.IsHexDigit);

    private static Guid? ParseGuid(string? text) =>
        text is not null && Guid.TryParse(text.Trim().Trim('{', '}'), out Guid g) ? g : null;
}
