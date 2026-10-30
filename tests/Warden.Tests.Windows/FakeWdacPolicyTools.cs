using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Warden.Wdac;

namespace Warden.Tests.Windows;

/// <summary>
/// Stand-in for ConfigCI + CiTool. "New-CIPolicy" emits a SHA-1 and a SHA-256 rule per scanned file whose
/// bytes start with "MZ" (the hashes are of a salted copy of the bytes, so they differ from the flat
/// SHA-256 the way Authenticode hashes do); "Merge-CIPolicy" appends them, de-duplicates by hash and
/// <b>renumbers every rule ID</b>, which is what makes rule IDs useless as revoke keys. Compile copies the
/// XML to the .cip path; deploy records the XML it was given.
/// </summary>
internal sealed class FakeWdacPolicyTools : IWdacPolicyTools
{
    private static readonly XNamespace Ns = SupplementalPolicyXml.Ns;
    private int _mergeCount;

    public bool FailMerge { get; set; }
    public bool FailCompile { get; set; }
    public bool FailDeploy { get; set; }

    /// <summary>Runs after the merged XML is written (e.g. to swap a scan copy).</summary>
    public Action? AfterMerge { get; set; }

    /// <summary>Edits the merged policy before it is written (e.g. to smuggle in a signer).</summary>
    public Action<XDocument>? MutateMerged { get; set; }

    public int MergeCalls { get; private set; }
    public int CompileCalls { get; private set; }
    public int DeployCalls { get; private set; }

    /// <summary>The XML of every policy that was successfully deployed, in order.</summary>
    public List<XDocument> Deployed { get; } = new();

    public XDocument? LastDeployed => Deployed.Count > 0 ? Deployed[^1] : null;

    /// <summary>The "Authenticode" hashes this fake generates for a file's bytes.</summary>
    public static IReadOnlyList<string> RuleHashesFor(byte[] bytes)
    {
        byte[] salted = Encoding.ASCII.GetBytes("authenticode:").Concat(bytes).ToArray();
        return new[] { Convert.ToHexString(SHA1.HashData(salted)), Convert.ToHexString(SHA256.HashData(salted)) };
    }

    public Task<ProcessResult> BuildMergedAsync(string currentXml, string scanDir, string hashPolicyXml, string mergedXml, string baseGuid, CancellationToken cancellationToken)
    {
        MergeCalls++;
        if (FailMerge)
        {
            return Task.FromResult(new ProcessResult(1, string.Empty, "Merge-CIPolicy: boom"));
        }

        var rules = new XElement(Ns + "FileRules");
        int n = 0;
        foreach (string file in Directory.EnumerateFiles(scanDir, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
        {
            byte[] bytes = File.ReadAllBytes(file);
            if (bytes.Length < 2 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
            {
                continue; // not a PE: New-CIPolicy generates nothing
            }
            IReadOnlyList<string> h = RuleHashesFor(bytes);
            rules.Add(new XElement(Ns + "Allow", new XAttribute("ID", $"ID_ALLOW_A_{++n}"), new XAttribute("FriendlyName", $"{file} Hash Sha1"), new XAttribute("Hash", h[0])));
            rules.Add(new XElement(Ns + "Allow", new XAttribute("ID", $"ID_ALLOW_A_{++n}"), new XAttribute("FriendlyName", $"{file} Hash Sha256"), new XAttribute("Hash", h[1])));
        }
        new XDocument(new XElement(Ns + "SiPolicy", new XAttribute("PolicyType", "Base Policy"), rules)).Save(hashPolicyXml);

        XDocument merged = XDocument.Load(currentXml);
        XElement fileRules = merged.Root!.Element(Ns + "FileRules")!;
        var seen = new HashSet<string>(fileRules.Elements(Ns + "Allow").Select(a => (string)a.Attribute("Hash")!), StringComparer.OrdinalIgnoreCase);
        foreach (XElement allow in rules.Elements())
        {
            if (seen.Add((string)allow.Attribute("Hash")!))
            {
                fileRules.Add(new XElement(allow));
            }
        }

        // Renumber every rule and rebuild the user-mode refs, as a merge may.
        _mergeCount++;
        XElement userMode = merged.Root!.Element(Ns + "SigningScenarios")!.Elements(Ns + "SigningScenario")
            .Single(s => (string?)s.Attribute("Value") == "12").Element(Ns + "ProductSigners")!;
        userMode.RemoveNodes();
        var refs = new XElement(Ns + "FileRulesRef");
        int k = 0;
        foreach (XElement allow in fileRules.Elements(Ns + "Allow"))
        {
            string id = $"ID_ALLOW_M{_mergeCount}_{k++}";
            allow.SetAttributeValue("ID", id);
            refs.Add(new XElement(Ns + "FileRuleRef", new XAttribute("RuleID", id)));
        }
        if (k > 0)
        {
            userMode.Add(refs);
        }

        SupplementalPolicyXml.SetBasePolicyId(merged, baseGuid);
        MutateMerged?.Invoke(merged);
        merged.Save(mergedXml);
        AfterMerge?.Invoke();
        return Task.FromResult(new ProcessResult(0, string.Empty, string.Empty));
    }

    public Task<ProcessResult> CompileAsync(string xmlPath, string cipPath, CancellationToken cancellationToken)
    {
        CompileCalls++;
        if (FailCompile)
        {
            return Task.FromResult(new ProcessResult(1, string.Empty, "ConvertFrom-CIPolicy: boom"));
        }
        File.Copy(xmlPath, cipPath, overwrite: true);
        return Task.FromResult(new ProcessResult(0, string.Empty, string.Empty));
    }

    public Task<ProcessResult> DeployAsync(string cipPath, CancellationToken cancellationToken)
    {
        DeployCalls++;
        if (FailDeploy)
        {
            return Task.FromResult(new ProcessResult(5, string.Empty, "CiTool: boom"));
        }
        Deployed.Add(XDocument.Load(cipPath));
        return Task.FromResult(new ProcessResult(0, string.Empty, string.Empty));
    }

    public Task<ProcessResult> ListPoliciesAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new ProcessResult(0, "{\"Policies\":[]}", string.Empty));
}
