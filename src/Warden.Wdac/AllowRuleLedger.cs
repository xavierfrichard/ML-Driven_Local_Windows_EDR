using System.Text.Json;

namespace Warden.Wdac;

/// <summary>
/// Maps a flat SHA-256 (what the pipeline and whitelist track) to the ConfigCI rules that <c>New-CIPolicy</c>
/// generated for that file, so a revoke can remove exactly those rules. Persisted as JSON next to the
/// supplemental.
/// </summary>
/// <remarks>
/// Entries record the rules' <c>Hash=</c> values (Authenticode and page hashes). Rule <c>ID</c>s are not
/// stable: <c>Merge-CIPolicy</c> may renumber them on every allow, so an ID recorded today can point at
/// nothing, or at another file's rule, tomorrow. Ledgers written before this change
/// (<c>{"SHA": ["ID_…", …]}</c>) are still read; their IDs are kept as <see cref="LegacyRuleIdsFor"/> and
/// resolved to hashes against the current policy at revoke time.
/// </remarks>
public sealed class AllowRuleLedger
{
    private sealed class Entry
    {
        public HashSet<string> Hashes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> RuleIds { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private readonly Dictionary<string, Entry> _map = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Rule <c>Hash=</c> values recorded for the flat hash (empty when unknown).</summary>
    public IReadOnlyCollection<string> HashesFor(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        return _map.TryGetValue(sha256, out Entry? e) ? e.Hashes : Array.Empty<string>();
    }

    /// <summary>Rule IDs from a pre-hash ledger (empty when none). They may be stale; resolve them against the current policy.</summary>
    public IReadOnlyCollection<string> LegacyRuleIdsFor(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        return _map.TryGetValue(sha256, out Entry? e) ? e.RuleIds : Array.Empty<string>();
    }

    /// <summary>True when anything is recorded for the flat hash.</summary>
    public bool HasEntry(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        return _map.TryGetValue(sha256, out Entry? e) && (e.Hashes.Count > 0 || e.RuleIds.Count > 0);
    }

    /// <summary>Associates rule <c>Hash=</c> values with a flat hash (merged with any existing entry).</summary>
    public void RecordHashes(string sha256, IEnumerable<string> ruleHashes)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(ruleHashes);
        Entry e = GetOrAdd(sha256);
        foreach (string h in ruleHashes)
        {
            if (!string.IsNullOrWhiteSpace(h))
            {
                e.Hashes.Add(h.ToUpperInvariant());
            }
        }
    }

    /// <summary>Associates legacy rule IDs with a flat hash (reading old ledgers, and tests).</summary>
    public void RecordLegacyRuleIds(string sha256, IEnumerable<string> ruleIds)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentNullException.ThrowIfNull(ruleIds);
        Entry e = GetOrAdd(sha256);
        foreach (string id in ruleIds)
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                e.RuleIds.Add(id);
            }
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

    /// <summary>Serializes to JSON: <c>{"SHA": {"hashes": [...], "ruleIds": [...]}}</c>.</summary>
    public string ToJson()
    {
        var o = new SortedDictionary<string, Dictionary<string, string[]>>(StringComparer.OrdinalIgnoreCase);
        foreach ((string sha, Entry e) in _map)
        {
            o[sha] = new Dictionary<string, string[]>
            {
                ["hashes"] = e.Hashes.OrderBy(s => s, StringComparer.Ordinal).ToArray(),
                ["ruleIds"] = e.RuleIds.OrderBy(s => s, StringComparer.Ordinal).ToArray(),
            };
        }
        return JsonSerializer.Serialize(o, Indented);
    }

    /// <summary>Parses the current or the legacy format; malformed input yields an empty ledger (see <see cref="TryParse"/>).</summary>
    public static AllowRuleLedger FromJson(string? json) =>
        TryParse(json, out AllowRuleLedger ledger, out _) ? ledger : new AllowRuleLedger();

    /// <summary>
    /// Parses a ledger. Returns false (with a reason) when the text is not a ledger, so a caller that changes
    /// the policy can refuse instead of silently forgetting what was allowed. Empty text is an empty ledger.
    /// </summary>
    public static bool TryParse(string? json, out AllowRuleLedger ledger, out string? error)
    {
        ledger = new AllowRuleLedger();
        error = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            return true;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                error = "Ledger root is not a JSON object.";
                ledger = new AllowRuleLedger();
                return false;
            }

            foreach (JsonProperty p in doc.RootElement.EnumerateObject())
            {
                switch (p.Value.ValueKind)
                {
                    case JsonValueKind.Array: // legacy: "SHA": ["ID_ALLOW_…", …]
                        ledger.RecordLegacyRuleIds(p.Name, Strings(p.Value));
                        break;
                    case JsonValueKind.Object:
                        if (p.Value.TryGetProperty("hashes", out JsonElement h) && h.ValueKind == JsonValueKind.Array)
                        {
                            ledger.RecordHashes(p.Name, Strings(h));
                        }
                        if (p.Value.TryGetProperty("ruleIds", out JsonElement r) && r.ValueKind == JsonValueKind.Array)
                        {
                            ledger.RecordLegacyRuleIds(p.Name, Strings(r));
                        }
                        break;
                    default:
                        error = $"Ledger entry '{p.Name}' has an unexpected shape.";
                        ledger = new AllowRuleLedger();
                        return false;
                }
            }
            return true;
        }
        catch (JsonException ex)
        {
            error = "Ledger is not valid JSON: " + ex.Message;
            ledger = new AllowRuleLedger();
            return false;
        }

        static IEnumerable<string> Strings(JsonElement array) =>
            array.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!);
    }

    /// <summary>Loads from a file (empty when missing or malformed; use <see cref="TryLoad"/> to tell those apart).</summary>
    public static AllowRuleLedger Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return File.Exists(path) ? FromJson(File.ReadAllText(path)) : new AllowRuleLedger();
    }

    /// <summary>Loads from a file; false when the file exists but is not a ledger.</summary>
    public static bool TryLoad(string path, out AllowRuleLedger ledger, out string? error)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (!File.Exists(path))
        {
            ledger = new AllowRuleLedger();
            error = null;
            return true;
        }
        return TryParse(File.ReadAllText(path), out ledger, out error);
    }

    /// <summary>Saves to a file.</summary>
    public void Save(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        File.WriteAllText(path, ToJson());
    }

    private Entry GetOrAdd(string sha256)
    {
        if (!_map.TryGetValue(sha256, out Entry? e))
        {
            e = new Entry();
            _map[sha256] = e;
        }
        return e;
    }
}
