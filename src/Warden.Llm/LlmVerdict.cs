using System.Collections.Immutable;
using System.Text;
using System.Text.Json;

namespace Warden.Llm;

/// <summary>The analyst's disposition for a sample. Maps to a pipeline verdict in <see cref="LlmVerdictSource"/>.</summary>
public enum LlmDisposition
{
    /// <summary>The model believes the sample is safe.</summary>
    Benign,

    /// <summary>The model is unsure but sees risk indicators.</summary>
    Suspicious,

    /// <summary>The model believes the sample is malicious.</summary>
    Malicious,
}

/// <summary>
/// The structured verdict returned by an <see cref="IVerdictLlmProvider"/> — the parsed output of the
/// forced <c>submit_verdict</c> tool call. The enforcement action is derived from these typed fields,
/// never from free-form model prose, which is the prompt-injection defense on the output side.
/// </summary>
/// <param name="Disposition">Benign / suspicious / malicious.</param>
/// <param name="Confidence">Model confidence in [0,1].</param>
/// <param name="Evidence">Short human-readable justifications (capped).</param>
/// <param name="MitreAttack">MITRE ATT&amp;CK technique IDs (capped).</param>
/// <param name="SuggestedAction">The model's non-binding suggested action ("allow"/"prompt"/"block"/"quarantine").</param>
public sealed record LlmVerdict(
    LlmDisposition Disposition,
    double Confidence,
    ImmutableArray<string> Evidence,
    ImmutableArray<string> MitreAttack,
    string SuggestedAction)
{
    /// <summary>The model that produced this verdict, recorded for the rationale/telemetry (set by the provider).</summary>
    public string Model { get; init; } = string.Empty;

    /// <summary>
    /// True when the verdict came from a forced tool/function call (the structured output boundary).
    /// A verdict scraped from free-form model <i>content</i> (the local content fallback) sets this
    /// false, and must never be trusted to auto-allow — see <see cref="LlmVerdictSource"/>.
    /// </summary>
    public bool FromToolCall { get; init; } = true;

    /// <summary>
    /// Parse the tool input object (Anthropic <c>tool_use.input</c> or an OpenAI
    /// <c>tool_calls[].function.arguments</c> object). Returns null if the object has no usable
    /// verdict, which the source maps to "undecided" (fail-safe: no verdict → prompt).
    /// </summary>
    public static LlmVerdict? FromInput(JsonElement input, int maxListItems)
    {
        if (input.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!input.TryGetProperty("verdict", out JsonElement v) || v.ValueKind != JsonValueKind.String)
        {
            return null; // no disposition → not a usable verdict
        }

        LlmDisposition disposition = v.GetString()?.Trim().ToLowerInvariant() switch
        {
            "benign" => LlmDisposition.Benign,
            "malicious" => LlmDisposition.Malicious,
            "suspicious" => LlmDisposition.Suspicious,
            // Any unexpected label is treated conservatively as "suspicious" (never silently benign).
            _ => LlmDisposition.Suspicious,
        };

        double confidence = 0.5;
        if (input.TryGetProperty("confidence", out JsonElement c) && c.ValueKind == JsonValueKind.Number
            && c.TryGetDouble(out double parsed))
        {
            confidence = Math.Clamp(parsed, 0d, 1d);
        }

        string action = input.TryGetProperty("suggested_action", out JsonElement a) && a.ValueKind == JsonValueKind.String
            ? a.GetString() ?? string.Empty
            : string.Empty;

        return new LlmVerdict(
            disposition,
            confidence,
            ReadStringArray(input, "evidence", maxListItems),
            ReadStringArray(input, "mitre_attack", maxListItems),
            action);
    }

    /// <summary>A compact one-line rationale for the UI / logs (bounded length).</summary>
    public string Describe(string providerName)
    {
        var sb = new StringBuilder();
        sb.Append('[').Append(providerName);
        if (!string.IsNullOrEmpty(Model))
        {
            sb.Append(':').Append(Model);
        }
        sb.Append("] ").Append(Disposition.ToString().ToLowerInvariant())
          .Append(" (").Append(Confidence.ToString("F2", System.Globalization.CultureInfo.InvariantCulture)).Append(')');
        if (!Evidence.IsDefaultOrEmpty)
        {
            sb.Append(". Evidence: ").Append(string.Join("; ", Evidence));
        }
        if (!MitreAttack.IsDefaultOrEmpty)
        {
            sb.Append(". MITRE: ").Append(string.Join(", ", MitreAttack));
        }
        return sb.ToString();
    }

    private static ImmutableArray<string> ReadStringArray(JsonElement obj, string name, int cap)
    {
        if (!obj.TryGetProperty(name, out JsonElement arr) || arr.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<string>.Empty;
        }

        ImmutableArray<string>.Builder builder = ImmutableArray.CreateBuilder<string>();
        foreach (JsonElement e in arr.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.String)
            {
                continue;
            }
            string? s = e.GetString();
            if (!string.IsNullOrWhiteSpace(s))
            {
                builder.Add(s);
            }
            if (builder.Count >= cap)
            {
                break;
            }
        }
        return builder.ToImmutable();
    }
}
