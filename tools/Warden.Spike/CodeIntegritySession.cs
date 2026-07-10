using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace Warden.Spike;

/// <summary>
/// A parsed WDAC/App Control block event (3076 audit, 3077 enforce) from the
/// <c>Microsoft-Windows-CodeIntegrity/Operational</c> channel.
/// </summary>
/// <param name="EventId">3076 = audit (would-block), 3077 = enforce (blocked).</param>
/// <param name="Mode">"audit" or "enforce".</param>
/// <param name="BlockedFilePath">Blocked image path, converted from the raw device path to DOS form.</param>
/// <param name="ProcessName">The requesting/loader process that tried to launch the blocked image.</param>
/// <param name="PolicyName">Friendly name of the blocking policy (if present).</param>
/// <param name="PolicyGuid">GUID of the blocking policy â€” the correlation key back to the deployed .cip.</param>
/// <param name="Sha256Authenticode">Authenticode SHA-256 from the event (NOT a flat hash).</param>
/// <param name="ActivityId">Correlation ActivityID joining this event to its 3089 signer companions.</param>
/// <param name="TimeCreated">When the block was logged.</param>
/// <param name="RawProperties">All named EventData fields, for display/debugging.</param>
internal sealed record CiBlockEvent(
    int EventId,
    string Mode,
    string BlockedFilePath,
    string ProcessName,
    string PolicyName,
    string PolicyGuid,
    string Sha256Authenticode,
    string ActivityId,
    DateTimeOffset TimeCreated,
    IReadOnlyDictionary<string, string> RawProperties);

/// <summary>
/// Subscribes to WDAC block events (3076/3077) on the CodeIntegrity Operational channel via
/// <see cref="EventLogWatcher"/>. Chosen over a raw ETW session per the research: in-box, fully
/// rendered/named data, survives restarts, and supports replay of existing log entries â€” all the
/// latency ETW would buy is irrelevant at Phase-0 block rates. Requires elevation (or Event Log
/// Readers membership).
/// </summary>
internal sealed class CodeIntegritySession : IDisposable
{
    private const string Channel = "Microsoft-Windows-CodeIntegrity/Operational";
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    private readonly EventLogWatcher _watcher;
    private bool _disposed;

    /// <summary>Raised (on a watcher thread) for each parsed 3076/3077 block event.</summary>
    public event Action<CiBlockEvent>? BlockObserved;

    /// <param name="replayExisting">
    /// When true, blocks already present in the log at startup are replayed â€” handy for the spike so a
    /// block produced just before launch is still seen.
    /// </param>
    public CodeIntegritySession(bool replayExisting = true)
    {
        EnsureChannelEnabled();

        var query = new EventLogQuery(
            Channel,
            PathType.LogName,
            "*[System[(EventID=3076 or EventID=3077)]]");

        _watcher = new EventLogWatcher(query, bookmark: null, readExistingEvents: replayExisting);
        _watcher.EventRecordWritten += OnEventWritten;
    }

    /// <summary>Enables delivery. Throws <see cref="EventLogException"/> if not elevated.</summary>
    public void Start() => _watcher.Enabled = true;

    /// <summary>
    /// Best-effort self-heal: if the CodeIntegrity/Operational channel is disabled, enabling the
    /// watcher would throw. Turn it back on. Failures here (access denied, etc.) are non-fatal â€”
    /// if the channel truly cannot be enabled, <see cref="Start"/> surfaces the error instead.
    /// </summary>
    private static void EnsureChannelEnabled()
    {
        try
        {
            using var cfg = new EventLogConfiguration(Channel);
            if (!cfg.IsEnabled)
            {
                cfg.IsEnabled = true;
                cfg.SaveChanges();
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[CI] could not verify/enable channel '{Channel}': {ex.Message}");
        }
    }

    private void OnEventWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            Console.Error.WriteLine($"[CI] watcher error: {e.EventException.Message}");
            return;
        }

        EventRecord? rec = e.EventRecord;
        if (rec is null)
        {
            return;
        }

        using (rec)
        {
            try
            {
                BlockObserved?.Invoke(Parse(rec));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[CI] parse error: {ex.Message}");
            }
        }
    }

    /// <summary>Parses a rendered 3076/3077 record into a <see cref="CiBlockEvent"/>.</summary>
    private static CiBlockEvent Parse(EventRecord rec)
    {
        XDocument xml = XDocument.Parse(rec.ToXml());

        var named = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (XElement d in xml.Descendants(Ns + "Data"))
        {
            string? name = (string?)d.Attribute("Name");
            if (!string.IsNullOrEmpty(name))
            {
                named[name] = d.Value;
            }
        }

        string Named(string key) => named.TryGetValue(key, out string? v) ? v : string.Empty;

        // "File Name" is a device path when named data is present; fall back to positional Properties[1].
        string devicePath = Named("File Name");
        if (string.IsNullOrEmpty(devicePath) && rec.Properties.Count > 1)
        {
            devicePath = rec.Properties[1].Value?.ToString() ?? string.Empty;
        }

        string activityId = (string?)xml.Descendants(Ns + "Correlation")
            .FirstOrDefault()?.Attribute("ActivityID") ?? string.Empty;

        int eventId = rec.Id;

        return new CiBlockEvent(
            EventId: eventId,
            Mode: eventId == 3076 ? "audit" : "enforce",
            BlockedFilePath: PathUtil.DevicePathToDosPath(devicePath),
            ProcessName: Named("Process Name"),
            PolicyName: Named("PolicyName"),
            PolicyGuid: Named("PolicyGUID"),
            Sha256Authenticode: Named("SHA256 Hash"),
            ActivityId: activityId,
            TimeCreated: new DateTimeOffset(rec.TimeCreated ?? DateTime.Now),
            RawProperties: named);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _watcher.Enabled = false;
        _watcher.Dispose();
    }
}
