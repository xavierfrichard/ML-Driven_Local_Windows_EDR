using System.Text;
using Serilog.Core;
using Serilog.Events;

namespace Warden.Hardening;

/// <summary>
/// Wraps the real sinks and replaces each event's exception with a <see cref="SanitizedException"/> before
/// it is written. Exception messages routinely carry attacker-controlled text (a path in an
/// <see cref="IOException"/>, a parser error quoting file content), and the text sinks write
/// <c>Exception.ToString()</c> verbatim, so a CR/LF in it would otherwise forge log lines.
/// </summary>
public sealed class ExceptionSanitizingSink : ILogEventSink, IDisposable
{
    private readonly ILogEventSink _inner;

    public ExceptionSanitizingSink(ILogEventSink inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
    }

    public void Emit(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (logEvent.Exception is null || logEvent.Exception is SanitizedException)
        {
            _inner.Emit(logEvent);
            return;
        }

        var copy = new LogEvent(
            logEvent.Timestamp,
            logEvent.Level,
            new SanitizedException(logEvent.Exception),
            logEvent.MessageTemplate,
            logEvent.Properties.Select(kv => new LogEventProperty(kv.Key, kv.Value)));
        _inner.Emit(copy);
    }

    public void Dispose() => (_inner as IDisposable)?.Dispose();
}

/// <summary>
/// Stand-in for a logged exception whose <see cref="ToString"/> is the original's text made safe: unsafe
/// characters inside each line are escaped, the original line breaks are kept (stack traces stay
/// readable), and every line after the first is indented, so no line of exception text can start in
/// column 0 and pass for a new log entry. The text is capped at <see cref="MaxLength"/> characters.
/// </summary>
public sealed class SanitizedException : Exception
{
    /// <summary>Longest exception text kept.</summary>
    public const int MaxLength = 32 * 1024;

    private readonly string _text;

    public SanitizedException(Exception original)
        : base(ControlCharacterSanitizingEnricher.Sanitize((original ?? throw new ArgumentNullException(nameof(original))).Message))
    {
        OriginalType = original.GetType().FullName ?? original.GetType().Name;
        _text = SanitizeMultiline(original.ToString());
    }

    public SanitizedException()
        : this(new InvalidOperationException())
    {
    }

    public SanitizedException(string message)
        : this(new InvalidOperationException(message))
    {
    }

    public SanitizedException(string message, Exception innerException)
        : this(new InvalidOperationException(message, innerException))
    {
    }

    /// <summary>Full name of the exception type that was logged.</summary>
    public string OriginalType { get; } = "";

    public override string? StackTrace => null;

    public override string ToString() => _text;

    /// <summary>Escapes unsafe characters per line, keeps line breaks, and indents continuation lines.</summary>
    public static string SanitizeMultiline(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        int limit = Math.Min(text.Length, MaxLength);
        var sb = new StringBuilder(limit + 64);
        bool lineStart = false;
        for (int i = 0; i < limit; i++)
        {
            char c = text[i];
            if (c is '\r' or '\n')
            {
                if (c == '\r' && i + 1 < limit && text[i + 1] == '\n')
                {
                    i++;
                }
                sb.Append(Environment.NewLine);
                lineStart = true;
                continue;
            }
            if (lineStart)
            {
                // Real stack-trace lines already start with spaces; anything else gets indented.
                if (c != ' ')
                {
                    sb.Append("    ");
                }
                lineStart = false;
            }
            ControlCharacterSanitizingEnricher.AppendEscaped(sb, c);
        }
        if (text.Length > MaxLength)
        {
            sb.Append("…[truncated ").Append(text.Length - MaxLength).Append(" chars]");
        }
        return sb.ToString();
    }
}
