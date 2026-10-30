using System.Xml.Linq;

namespace Warden.Wdac;

/// <summary>
/// Pure helpers over the supplemental policy XML (the ConfigCI schema, namespace
/// <c>urn:schemas-microsoft-com:sipolicy</c>): enumerate <c>&lt;Allow&gt;</c> rule IDs, remove a set of
/// rules (and every <c>&lt;FileRuleRef&gt;</c> that points at them), and bump <c>VersionEx</c>. Kept free
/// of I/O so the logic is unit-testable without ConfigCI or admin rights.
/// </summary>
public static class SupplementalPolicyXml
{
    /// <summary>The ConfigCI policy namespace.</summary>
    public static readonly XNamespace Ns = "urn:schemas-microsoft-com:sipolicy";

    /// <summary>IDs of every <c>&lt;Allow&gt;</c> file rule in the document.</summary>
    public static IReadOnlySet<string> AllowRuleIds(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (XElement allow in doc.Descendants(Ns + "FileRules").Elements(Ns + "Allow"))
        {
            string? id = (string?)allow.Attribute("ID");
            if (!string.IsNullOrEmpty(id))
            {
                ids.Add(id);
            }
        }
        return ids;
    }

    /// <summary>
    /// IDs of <c>&lt;Allow&gt;</c> rules whose <c>FriendlyName</c> starts with <paramref name="friendlyNamePrefix"/>
    /// (New-CIPolicy names hash rules "&lt;scanned path&gt; Hash Sha1|Sha256|Page Sha1|Page Sha256").
    /// </summary>
    public static IReadOnlySet<string> AllowRuleIdsByFriendlyNamePrefix(XDocument doc, string friendlyNamePrefix)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(friendlyNamePrefix))
        {
            return ids;
        }

        foreach (XElement allow in doc.Descendants(Ns + "FileRules").Elements(Ns + "Allow"))
        {
            string? id = (string?)allow.Attribute("ID");
            string? name = (string?)allow.Attribute("FriendlyName");
            if (!string.IsNullOrEmpty(id) && name is not null
                && name.StartsWith(friendlyNamePrefix, StringComparison.OrdinalIgnoreCase))
            {
                ids.Add(id);
            }
        }
        return ids;
    }

    /// <summary>
    /// IDs of <c>&lt;Allow&gt;</c> rules generated from a scanned copy named <paramref name="fileName"/> under
    /// <paramref name="scanRoot"/> (any layout: <c>scan\name</c> or <c>scan\NNNN\name</c>). Legacy fallback for
    /// rules recorded before the ledger existed; over-matching only ever removes allows.
    /// </summary>
    public static IReadOnlySet<string> AllowRuleIdsByScannedFileName(XDocument doc, string fileName, string scanRoot)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(fileName) || string.IsNullOrWhiteSpace(scanRoot))
        {
            return ids;
        }

        string root = scanRoot.TrimEnd('\\') + "\\";
        string tail = "\\" + fileName + " Hash";
        foreach (XElement allow in doc.Descendants(Ns + "FileRules").Elements(Ns + "Allow"))
        {
            string? id = (string?)allow.Attribute("ID");
            string? name = (string?)allow.Attribute("FriendlyName");
            if (!string.IsNullOrEmpty(id) && name is not null
                && name.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                && name.Contains(tail, StringComparison.OrdinalIgnoreCase))
            {
                ids.Add(id);
            }
        }
        return ids;
    }

    /// <summary>
    /// Removes the given <c>&lt;Allow&gt;</c> rules and every <c>&lt;FileRuleRef RuleID=…&gt;</c> that
    /// references them (under any signing scenario). Returns how many rule elements were removed.
    /// </summary>
    public static int RemoveAllowRules(XDocument doc, IReadOnlyCollection<string> ruleIds)
    {
        ArgumentNullException.ThrowIfNull(doc);
        ArgumentNullException.ThrowIfNull(ruleIds);
        if (ruleIds.Count == 0)
        {
            return 0;
        }

        var wanted = new HashSet<string>(ruleIds, StringComparer.OrdinalIgnoreCase);

        List<XElement> refs = doc.Descendants(Ns + "FileRuleRef")
            .Where(r => (string?)r.Attribute("RuleID") is { } rid && wanted.Contains(rid))
            .ToList();
        foreach (XElement r in refs)
        {
            r.Remove();
        }

        List<XElement> rules = doc.Descendants(Ns + "FileRules").Elements(Ns + "Allow")
            .Where(a => (string?)a.Attribute("ID") is { } id && wanted.Contains(id))
            .ToList();
        foreach (XElement a in rules)
        {
            a.Remove();
        }

        return rules.Count;
    }

    /// <summary>
    /// Increments the last component of <c>&lt;VersionEx&gt;</c> ("a.b.c.d" → "a.b.c.d+1"). WDAC only
    /// applies an update to an already-deployed PolicyID when the version increases; a missing or
    /// malformed element is replaced by "1.0.0.1". Returns the new version string.
    /// </summary>
    public static string BumpVersion(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        XElement root = doc.Root ?? throw new InvalidOperationException("Policy XML has no root element.");
        XElement? version = root.Element(Ns + "VersionEx");

        string next = "1.0.0.1";
        if (version is not null && Version.TryParse(version.Value.Trim(), out Version? v) && v.Revision >= 0)
        {
            next = new Version(v.Major, v.Minor, Math.Max(0, v.Build), v.Revision + 1).ToString();
        }
        else if (version is not null && Version.TryParse(version.Value.Trim(), out Version? v3))
        {
            next = new Version(v3.Major, v3.Minor, Math.Max(0, v3.Build), 1).ToString();
        }

        if (version is null)
        {
            root.AddFirst(new XElement(Ns + "VersionEx", next));
        }
        else
        {
            version.Value = next;
        }
        return next;
    }

    /// <summary>
    /// <c>Hash</c> values of the <c>&lt;Allow&gt;</c> rules whose <c>FriendlyName</c> starts with
    /// "<paramref name="scannedPath"/> Hash": the rules New-CIPolicy generated for that one scanned file.
    /// </summary>
    public static IReadOnlySet<string> AllowRuleHashesForScannedFile(XDocument doc, string scannedPath)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(scannedPath))
        {
            return hashes;
        }

        string prefix = scannedPath + " Hash";
        foreach (XElement allow in AllowRules(doc))
        {
            string? name = (string?)allow.Attribute("FriendlyName");
            string? hash = (string?)allow.Attribute("Hash");
            if (name is not null && !string.IsNullOrEmpty(hash) && name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                hashes.Add(hash.ToUpperInvariant());
            }
        }
        return hashes;
    }

    /// <summary>Every <c>Hash</c> value carried by an <c>&lt;Allow&gt;</c> rule (upper-case hex).</summary>
    public static IReadOnlySet<string> AllowRuleHashes(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (XElement allow in AllowRules(doc))
        {
            if ((string?)allow.Attribute("Hash") is { Length: > 0 } hash)
            {
                hashes.Add(hash.ToUpperInvariant());
            }
        }
        return hashes;
    }

    /// <summary>IDs of the <c>&lt;Allow&gt;</c> rules whose <c>Hash</c> is one of <paramref name="hashes"/>.</summary>
    public static IReadOnlySet<string> AllowRuleIdsByHash(XDocument doc, IEnumerable<string> hashes)
    {
        ArgumentNullException.ThrowIfNull(doc);
        ArgumentNullException.ThrowIfNull(hashes);
        var wanted = new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (XElement allow in AllowRules(doc))
        {
            if ((string?)allow.Attribute("ID") is { Length: > 0 } id
                && (string?)allow.Attribute("Hash") is { Length: > 0 } hash
                && wanted.Contains(hash))
            {
                ids.Add(id);
            }
        }
        return ids;
    }

    /// <summary><c>Hash</c> values of the <c>&lt;Allow&gt;</c> rules with the given IDs (resolves legacy ID-only ledger entries).</summary>
    public static IReadOnlySet<string> AllowRuleHashesById(XDocument doc, IEnumerable<string> ruleIds)
    {
        ArgumentNullException.ThrowIfNull(doc);
        ArgumentNullException.ThrowIfNull(ruleIds);
        var wanted = new HashSet<string>(ruleIds, StringComparer.OrdinalIgnoreCase);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (XElement allow in AllowRules(doc))
        {
            if ((string?)allow.Attribute("ID") is { Length: > 0 } id && wanted.Contains(id)
                && (string?)allow.Attribute("Hash") is { Length: > 0 } hash)
            {
                hashes.Add(hash.ToUpperInvariant());
            }
        }
        return hashes;
    }

    /// <summary>The <c>&lt;VersionEx&gt;</c> value, or null.</summary>
    public static string? GetVersion(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return doc.Root?.Element(Ns + "VersionEx")?.Value.Trim();
    }

    /// <summary>Sets <c>&lt;VersionEx&gt;</c> (orders a compensating redeploy after a newer deploy).</summary>
    public static void SetVersion(XDocument doc, string version) => SetElement(doc, "VersionEx", version, first: true);

    /// <summary>Sets <c>&lt;BasePolicyID&gt;</c> in memory (the real linkage is done by Set-CIPolicyIdInfo).</summary>
    public static void SetBasePolicyId(XDocument doc, string baseGuid) => SetElement(doc, "BasePolicyID", baseGuid, first: false);

    private static void SetElement(XDocument doc, string name, string value, bool first)
    {
        ArgumentNullException.ThrowIfNull(doc);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        XElement root = doc.Root ?? throw new InvalidOperationException("Policy XML has no root element.");
        XElement? element = root.Element(Ns + name);
        if (element is not null)
        {
            element.Value = value;
        }
        else if (first)
        {
            root.AddFirst(new XElement(Ns + name, value));
        }
        else
        {
            root.Add(new XElement(Ns + name, value));
        }
    }

    private static IEnumerable<XElement> AllowRules(XDocument doc) =>
        doc.Descendants(Ns + "FileRules").Elements(Ns + "Allow");

    /// <summary>The policy's own ID (the <c>&lt;PolicyID&gt;</c> element), or null.</summary>
    public static string? PolicyId(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return doc.Root?.Element(Ns + "PolicyID")?.Value.Trim();
    }

    /// <summary>The <c>&lt;BasePolicyID&gt;</c> element, or null.</summary>
    public static string? BasePolicyId(XDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        return doc.Root?.Element(Ns + "BasePolicyID")?.Value.Trim();
    }
}
