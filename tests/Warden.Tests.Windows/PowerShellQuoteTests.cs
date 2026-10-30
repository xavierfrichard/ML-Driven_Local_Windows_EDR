using Warden.AntiExploit;

namespace Warden.Tests.Windows;

/// <summary>
/// <see cref="PowerShellRunner.PsQuote"/> must produce a single-quoted literal that PowerShell reads back
/// as exactly the input, with nothing after it. PowerShell treats U+0027 and the typographic quotes
/// U+2018–U+201B all as single quotes, so each must be escaped. No PowerShell is started: the tests use a
/// model of PowerShell's single-quoted-string scanner (a quote ends the literal unless the next character
/// is also a quote, in which case the second one is kept as text).
/// </summary>
public sealed class PowerShellQuoteTests
{
    public static TheoryData<char> PowerShellSingleQuotes() => new()
    {
        '\'', '\u2018', '\u2019', '\u201A', '\u201B',
    };

    [Theory]
    [MemberData(nameof(PowerShellSingleQuotes))]
    public void Given_a_value_with_a_PowerShell_quote_When_quoted_Then_PowerShell_reads_back_the_whole_value_and_nothing_runs(char quote)
    {
        string value = $"C:\\x{quote}; Remove-Item C:\\important -Recurse; {quote}y.xml";

        string literal = PowerShellRunner.PsQuote(value);
        (string parsed, int consumed) = ScanSingleQuotedLiteral(literal);

        Assert.Equal(value, parsed);
        Assert.Equal(literal.Length, consumed); // the literal ends at the last char: no trailing code
    }

    [Theory]
    [MemberData(nameof(PowerShellSingleQuotes))]
    public void Given_a_PowerShell_quote_When_quoted_Then_it_is_doubled(char quote)
    {
        Assert.Equal($"'a{quote}{quote}b'", PowerShellRunner.PsQuote($"a{quote}b"));
    }

    [Fact]
    public void Given_a_value_without_quotes_When_quoted_Then_it_is_only_wrapped()
    {
        Assert.Equal("'C:\\Program Files\\App\\app.exe'", PowerShellRunner.PsQuote("C:\\Program Files\\App\\app.exe"));
    }

    [Fact]
    public void Given_double_quotes_When_quoted_Then_they_are_left_alone_because_they_are_literal_inside_single_quotes()
    {
        Assert.Equal("'a\"b\u201Cc\u201Dd'", PowerShellRunner.PsQuote("a\"b\u201Cc\u201Dd"));
    }

    /// <summary>
    /// Model of PowerShell's tokenizer for a verbatim (single-quoted) string starting at index 0.
    /// Returns the string's value and the number of characters consumed, including both quotes.
    /// </summary>
    private static (string Value, int Consumed) ScanSingleQuotedLiteral(string s)
    {
        Assert.True(s.Length >= 2 && IsQuote(s[0]), "literal must open with a quote");
        var sb = new System.Text.StringBuilder();
        int i = 1;
        while (i < s.Length)
        {
            char c = s[i];
            if (IsQuote(c))
            {
                if (i + 1 < s.Length && IsQuote(s[i + 1]))
                {
                    sb.Append(s[i + 1]); // doubled quote: keep the second one as text
                    i += 2;
                    continue;
                }
                return (sb.ToString(), i + 1); // closing quote
            }
            sb.Append(c);
            i++;
        }
        throw new Xunit.Sdk.XunitException("unterminated literal");
    }

    // Independent of the code under test, so a bug in IsPsSingleQuote cannot hide here.
    private static bool IsQuote(char c) => c is '\'' or '\u2018' or '\u2019' or '\u201A' or '\u201B';
}
