using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Display;
using Warden.Hardening;
using Warden.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace Warden.Tests.Windows;

/// <summary>
/// Log-injection guard: nested property values, exception text, U+2028/U+2029 and bidi controls, and the
/// tamper_log rows.
/// </summary>
public sealed class LogSanitizerTests
{
    private const string Forged = "2026-10-30 12:00:00.000 +00:00 [INF] forged entry";

    private sealed class CaptureSink : ILogEventSink
    {
        public List<LogEvent> Events { get; } = new();

        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }

    private sealed class RecordingTamperRepository : ITamperLogRepository
    {
        public List<TamperEventRecord> Rows { get; } = new();

        public Task<long> AddAsync(TamperEventRecord record, CancellationToken cancellationToken = default)
        {
            Rows.Add(record);
            return Task.FromResult((long)Rows.Count);
        }

        public Task<IReadOnlyList<TamperEventRecord>> GetRecentAsync(int limit = 500, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<TamperEventRecord>>(Rows);
    }

    /// <summary>Logs through the same enricher + exception wrapper as production and renders as the file sink does.</summary>
    private static string Render(Action<Serilog.ILogger> log)
    {
        var capture = new CaptureSink();
        using (Logger logger = new LoggerConfiguration()
                   .Enrich.With<ControlCharacterSanitizingEnricher>()
                   .WriteTo.Sink(new ExceptionSanitizingSink(capture))
                   .CreateLogger())
        {
            log(logger);
        }

        var formatter = new MessageTemplateTextFormatter(
            "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}", null);
        using var writer = new StringWriter();
        foreach (LogEvent e in capture.Events)
        {
            formatter.Format(e, writer);
        }
        return writer.ToString();
    }

    private static IEnumerable<string> Lines(string text) =>
        text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);

    [Fact]
    public void Given_bidi_and_line_separator_characters_When_sanitized_Then_they_are_escaped()
    {
        string spoofed = "invoice\u202Egpj.exe\u2028" + Forged + "\u2066x\u2069\u200F";

        Assert.True(ControlCharacterSanitizingEnricher.NeedsSanitizing(spoofed));
        string clean = ControlCharacterSanitizingEnricher.Sanitize(spoofed);

        Assert.Equal(@"invoice\u202Egpj.exe\u2028" + Forged + @"\u2066x\u2069\u200F", clean);
        Assert.False(ControlCharacterSanitizingEnricher.NeedsSanitizing(clean));
    }

    [Fact]
    public void Given_attacker_strings_nested_in_sequences_structures_and_dictionaries_When_logged_Then_no_line_is_forged()
    {
        var command = new { Path = "a.exe\r\n" + Forged, Args = new[] { "x\n" + Forged } };
        var env = new Dictionary<string, string> { ["K\n" + Forged] = "v\u2028" };

        string output = Render(l => l.Information("Launch {@Command} {Paths} {@Env}", command, new[] { "p\r\n" + Forged }, env));

        Assert.DoesNotContain(Lines(output), line => line.StartsWith(Forged, StringComparison.Ordinal));
        Assert.DoesNotContain("\u2028", output, StringComparison.Ordinal);
        Assert.Contains(@"\n" + Forged, output, StringComparison.Ordinal);
    }

    [Fact]
    public void Given_an_exception_whose_message_holds_a_forged_line_When_logged_Then_every_exception_line_is_indented_and_escaped()
    {
        Exception ex;
        try
        {
            throw new IOException("Cannot open C:\\x\r\n" + Forged + "\u202E");
        }
        catch (IOException caught)
        {
            ex = caught;
        }

        string output = Render(l => l.Error(ex, "Scan failed"));

        string[] lines = Lines(output).Where(s => s.Length > 0).ToArray();
        Assert.Equal(1, lines.Count(s => !s.StartsWith(' ') && s.Contains("[ERR]", StringComparison.Ordinal)));
        Assert.DoesNotContain(lines, line => line.StartsWith(Forged, StringComparison.Ordinal));
        Assert.Contains(lines, line => line.StartsWith("System.IO.IOException", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.StartsWith("    " + Forged, StringComparison.Ordinal));
        Assert.DoesNotContain("\u202E", output, StringComparison.Ordinal);
        // The stack trace keeps its own lines (still indented).
        Assert.Contains(lines, line => line.StartsWith("   at ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Given_a_tamper_detail_with_control_characters_When_persisted_Then_the_row_is_escaped()
    {
        var repo = new RecordingTamperRepository();
        var tamper = new TamperLog(repo, NullLogger<TamperLog>.Instance);

        await tamper.LogAsync("cat\n", "path\r\n" + Forged + "\u202E", "critical");

        TamperEventRecord row = Assert.Single(repo.Rows);
        Assert.Equal(@"cat\n", row.Category);
        Assert.Equal(@"path\r\n" + Forged + @"\u202E", row.Detail);
    }
}
