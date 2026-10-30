using System.Text;
using Serilog.Core;
using Serilog.Events;

namespace Warden.Hardening;

/// <summary>
/// Log-injection guard: escapes control characters (CR, LF, TAB, ESC, NUL…), the Unicode line and
/// paragraph separators (U+2028, U+2029) and bidirectional overrides (U+202A–U+202E, U+2066–U+2069, plus
/// the LRM/RLM/ALM marks) in every string property, including strings nested in sequences, structures and
/// dictionaries. An attacker-controlled value (a file name, a command line, a signer subject) therefore
/// cannot forge extra lines, terminal escapes, or a reversed-looking file name in the security audit log.
/// Applied once at Serilog configuration; the file sink itself does not escape property text. Exception text
/// is handled by <see cref="ExceptionSanitizingSink"/>, because a Serilog 3 enricher cannot replace it.
/// </summary>
public sealed class ControlCharacterSanitizingEnricher : ILogEventEnricher
{
    /// <summary>Longest string property kept; longer values are truncated (with a marker) to bound log growth.</summary>
    public const int MaxPropertyLength = 4096;

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(propertyFactory);

        List<LogEventProperty>? replacements = null;
        foreach (KeyValuePair<string, LogEventPropertyValue> kv in logEvent.Properties)
        {
            LogEventPropertyValue sanitized = SanitizeValue(kv.Value);
            if (!ReferenceEquals(sanitized, kv.Value))
            {
                replacements ??= new List<LogEventProperty>();
                replacements.Add(new LogEventProperty(kv.Key, sanitized));
            }
        }

        if (replacements is null)
        {
            return;
        }

        foreach (LogEventProperty property in replacements)
        {
            logEvent.AddOrUpdateProperty(property);
        }
    }

    /// <summary>
    /// Returns <paramref name="value"/> itself when nothing in it needs escaping, otherwise a sanitized copy.
    /// Recurses into sequences, structures (including the type tag) and dictionaries (keys and values).
    /// </summary>
    public static LogEventPropertyValue SanitizeValue(LogEventPropertyValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        switch (value)
        {
            case ScalarValue { Value: string s }:
                return NeedsSanitizing(s) ? new ScalarValue(Sanitize(s)) : value;

            case ScalarValue { Value: char c }:
                return IsUnsafe(c) ? new ScalarValue(Sanitize(c.ToString())) : value;

            case SequenceValue sequence:
            {
                bool changed = false;
                var elements = new List<LogEventPropertyValue>(sequence.Elements.Count);
                foreach (LogEventPropertyValue element in sequence.Elements)
                {
                    LogEventPropertyValue clean = SanitizeValue(element);
                    changed |= !ReferenceEquals(clean, element);
                    elements.Add(clean);
                }
                return changed ? new SequenceValue(elements) : value;
            }

            case StructureValue structure:
            {
                bool changed = false;
                var properties = new List<LogEventProperty>(structure.Properties.Count);
                foreach (LogEventProperty property in structure.Properties)
                {
                    LogEventPropertyValue clean = SanitizeValue(property.Value);
                    bool same = ReferenceEquals(clean, property.Value);
                    changed |= !same;
                    properties.Add(same ? property : new LogEventProperty(property.Name, clean));
                }
                string? typeTag = structure.TypeTag;
                if (typeTag is not null && NeedsSanitizing(typeTag))
                {
                    typeTag = Sanitize(typeTag);
                    changed = true;
                }
                return changed ? new StructureValue(properties, typeTag) : value;
            }

            case DictionaryValue dictionary:
            {
                bool changed = false;
                var elements = new List<KeyValuePair<ScalarValue, LogEventPropertyValue>>(dictionary.Elements.Count);
                foreach (KeyValuePair<ScalarValue, LogEventPropertyValue> kv in dictionary.Elements)
                {
                    var key = (ScalarValue)SanitizeValue(kv.Key);
                    LogEventPropertyValue clean = SanitizeValue(kv.Value);
                    changed |= !ReferenceEquals(key, kv.Key) || !ReferenceEquals(clean, kv.Value);
                    elements.Add(new KeyValuePair<ScalarValue, LogEventPropertyValue>(key, clean));
                }
                return changed ? new DictionaryValue(elements) : value;
            }

            default:
                return value;
        }
    }

    /// <summary>True when the value contains a character <see cref="Sanitize(string)"/> escapes, or exceeds the length cap.</summary>
    public static bool NeedsSanitizing(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > MaxPropertyLength)
        {
            return true;
        }
        foreach (char c in value)
        {
            if (IsUnsafe(c))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Control characters, U+2028/U+2029 (line/paragraph separators some viewers break on), and the bidi
    /// embedding/override/isolate controls and marks that reorder how the text is displayed.
    /// </summary>
    public static bool IsUnsafe(char c) =>
        char.IsControl(c)
        || (int)c is 0x2028 or 0x2029                       // line / paragraph separator
        || (int)c is >= 0x202A and <= 0x202E                // LRE, RLE, PDF, LRO, RLO
        || (int)c is >= 0x2066 and <= 0x2069                // LRI, RLI, FSI, PDI
        || (int)c is 0x200E or 0x200F or 0x061C;            // LRM, RLM, ALM

    /// <summary>
    /// Escapes unsafe characters as <c>\uXXXX</c> (CR/LF/TAB as <c>\r</c>/<c>\n</c>/<c>\t</c>) and truncates
    /// to <see cref="MaxPropertyLength"/>.
    /// </summary>
    public static string Sanitize(string value) => Sanitize(value, MaxPropertyLength);

    /// <summary>As <see cref="Sanitize(string)"/>, with an explicit length cap.</summary>
    public static string Sanitize(string value, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(value);
        int limit = Math.Min(value.Length, maxLength);
        var sb = new StringBuilder(limit + 16);
        for (int i = 0; i < limit; i++)
        {
            AppendEscaped(sb, value[i]);
        }
        if (value.Length > maxLength)
        {
            sb.Append("…[truncated ").Append(value.Length - maxLength).Append(" chars]");
        }
        return sb.ToString();
    }

    internal static void AppendEscaped(StringBuilder sb, char c)
    {
        switch (c)
        {
            case '\r': sb.Append("\\r"); break;
            case '\n': sb.Append("\\n"); break;
            case '\t': sb.Append("\\t"); break;
            default:
                if (IsUnsafe(c))
                {
                    sb.Append("\\u").Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
                }
                else
                {
                    sb.Append(c);
                }
                break;
        }
    }
}
