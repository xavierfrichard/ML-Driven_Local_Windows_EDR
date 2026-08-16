using System.Globalization;
using System.Text.Json;
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

/// <summary>
/// Maps a flat SHA-256 (what the pipeline and whitelist track) to the ConfigCI rule IDs that
/// <c>New-CIPolicy</c> generated for that file, so a revoke can remove exactly those rules. Persisted as
/// JSON next to the supplemental. Without this, the Authenticode/page hashes in the policy could not be
/// tied back to the flat hash.
/// </summary>
public sealed class AllowRuleLedger
{
    private readonly Dictionary<string, HashSet<string>> _map = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Rule IDs recorded for the hash (empty when unknown).</summary>
    public IReadOnlyCollection<string> RulesFor(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        return _map.TryGetValue(sha256, out HashSet<string>? ids) ? ids : Array.Empty<string>();
    }

    /// <summary>Associates rule IDs with a hash (merged with any existing entry).</summary>
    public void Record(string sha256, IEnumerable<string> ruleIds)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(ruleIds);
        if (!_map.TryGetValue(sha256, out HashSet<string>? ids))
        {
            ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _map[sha256] = ids;
        }
        foreach (string id in ruleIds)
        {
            ids.Add(id);
        }
    }

    /// <summary>Forgets a hash.</summary>
    public void Remove(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        _map.Remove(sha256);
    }

    /// <summary>Number of hashes tracked.</summary>
    public int Count => _map.Count;

    /// <summary>Serializes to JSON.</summary>
    public string ToJson() =>
        JsonSerializer.Serialize(_map.ToDictionary(kv => kv.Key, kv => kv.Value.OrderBy(s => s, StringComparer.Ordinal).ToArray(), StringComparer.OrdinalIgnoreCase),
            new JsonSerializerOptions { WriteIndented = true });

    /// <summary>Parses JSON produced by <see cref="ToJson"/>; malformed input yields an empty ledger.</summary>
    public static AllowRuleLedger FromJson(string? json)
    {
        var ledger = new AllowRuleLedger();
        if (string.IsNullOrWhiteSpace(json))
        {
            return ledger;
        }

        try
        {
            Dictionary<string, string[]>? raw = JsonSerializer.Deserialize<Dictionary<string, string[]>>(json);
            if (raw is not null)
            {
                foreach ((string sha, string[] ids) in raw)
                {
                    ledger.Record(sha, ids ?? Array.Empty<string>());
                }
            }
        }
        catch (JsonException)
        {
            // Corrupt ledger: start empty; revoke falls back to friendly-name matching.
        }
        return ledger;
    }

    /// <summary>Loads from a file (empty when missing).</summary>
    public static AllowRuleLedger Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return File.Exists(path) ? FromJson(File.ReadAllText(path)) : new AllowRuleLedger();
    }

    /// <summary>Saves to a file.</summary>
    public void Save(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        File.WriteAllText(path, ToJson());
    }

    /// <summary>Formats a version for the ledger's own use.</summary>
    internal static string Stamp() => DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss_fff", CultureInfo.InvariantCulture);
}
