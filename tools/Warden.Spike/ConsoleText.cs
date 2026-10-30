using System.Globalization;
using System.Text;

namespace Warden.Spike;

/// <summary>
/// Makes attacker-controlled text safe to write to an (often elevated) console. Command lines, file
/// paths, signer subjects and exception messages all come from the blocked binary or its launcher, so
/// they can carry ESC (ANSI/VT sequences that move the cursor, rewrite earlier lines or retitle the
/// window), CR/BS (overwrite what was printed), or bidi overrides (reorder what is shown).
/// </summary>
internal static class ConsoleText
{
    /// <summary>
    /// Returns <paramref name="value"/> with every C0/C1 control character, DEL, line/paragraph
    /// separator and bidi/zero-width formatting character replaced by a visible <c>\uXXXX</c> escape.
    /// Replacing ESC itself neutralises any ANSI sequence: what follows it is printed as plain text.
    /// </summary>
    public static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        StringBuilder? sb = null;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!IsUnsafe(c))
            {
                sb?.Append(c);
                continue;
            }

            sb ??= new StringBuilder(value.Length + 16).Append(value, 0, i);
            sb.Append("\\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
        }

        return sb?.ToString() ?? value;
    }

    private static bool IsUnsafe(char c) =>
        c < 0x20                         // C0 controls, including ESC, CR, LF, BS, TAB
        || c is >= '\u007F' and <= '\u009F' // DEL + C1 controls (U+009B is an 8-bit CSI)
        || c is '\u2028' or '\u2029'     // line / paragraph separators
        || c is >= '\u200B' and <= '\u200F' // zero-width chars, LRM/RLM
        || c is >= '\u202A' and <= '\u202E' // bidi embeddings / overrides
        || c is >= '\u2066' and <= '\u2069' // bidi isolates
        || c == '\uFEFF';                // zero-width no-break space / BOM
}
