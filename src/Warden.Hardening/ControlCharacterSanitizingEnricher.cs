using System.Text;
using Serilog.Core;
using Serilog.Events;

namespace Warden.Hardening;

/// <summary>
/// Log-injection guard: escapes control characters (CR, LF, TAB, ESC, NUL…) in every string property so
/// an attacker-controlled value — a file name, a command line, a signer subject — cannot forge extra
/// lines or terminal escapes in the security audit log. Applied once at Serilog configuration; the file
/// sink itself does not escape property text.
/// </summary>
public sealed class ControlCharacterSanitizingEnricher : ILogEventEnricher
{
    /// <summary>Longest string property kept; longer values are truncated (with a marker) to bound log growth.</summary>
    public const int MaxPropertyLength = 4096;

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(propertyFactory);

        List<(string Name, string Value)>? replacements = null;
        foreach (KeyValuePair<string, LogEventPropertyValue> kv in logEvent.Properties)
        {
            if (kv.Value is ScalarValue { Value: string s } && NeedsSanitizing(s))
            {
                replacements ??= new List<(string, string)>();
                replacements.Add((kv.Key, Sanitize(s)));
            }
        }

        if (replacements is null)
        {
            return;
        }

        foreach ((string name, string value) in replacements)
        {
            logEvent.AddOrUpdateProperty(propertyFactory.CreateProperty(name, value));
        }
    }

    /// <summary>True when the value contains a control character or exceeds the length cap.</summary>
    public static bool NeedsSanitizing(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > MaxPropertyLength)
        {
            return true;
        }
        foreach (char c in value)
        {
            if (char.IsControl(c))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Escapes control characters as <c>\uXXXX</c> (CR/LF/TAB as <c>\r</c>/<c>\n</c>/<c>\t</c>) and truncates.</summary>
    public static string Sanitize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sb = new StringBuilder(Math.Min(value.Length, MaxPropertyLength) + 16);
        int limit = Math.Min(value.Length, MaxPropertyLength);
        for (int i = 0; i < limit; i++)
        {
            char c = value[i];
            switch (c)
            {
                case '\r': sb.Append("\\r"); break;
                case '\n': sb.Append("\\n"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (char.IsControl(c))
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
        if (value.Length > MaxPropertyLength)
        {
            sb.Append("…[truncated ").Append(value.Length - MaxPropertyLength).Append(" chars]");
        }
        return sb.ToString();
    }
}
