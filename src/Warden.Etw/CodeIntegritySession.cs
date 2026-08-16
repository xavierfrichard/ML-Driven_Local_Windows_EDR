using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace Warden.Etw;

/// <summary>
/// Subscribes to WDAC / App Control block events (3076 audit, 3077 enforce) on the
/// <c>Microsoft-Windows-CodeIntegrity/Operational</c> channel via <see cref="EventLogWatcher"/>. The
/// watcher is created in <see cref="Start"/> so a rights-restricted host does not fault at DI time.
/// </summary>
public sealed class CodeIntegritySession : ICodeIntegrityBlockSource
{
    private const string Channel = "Microsoft-Windows-CodeIntegrity/Operational";
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    private readonly bool _replayExisting;
    private EventLogWatcher? _watcher;
    private bool _disposed;

    public event Action<CiBlockEvent>? BlockObserved;

    /// <summary>Raised when a CodeIntegrity event could not be parsed (event id, exception). Nothing is adjudicated for it.</summary>
    public event Action<int, Exception>? ParseFailed;

    /// <param name="replayExisting">When true, blocks already in the log at startup are replayed.</param>
    public CodeIntegritySession(bool replayExisting = false) => _replayExisting = replayExisting;

    public void Start()
    {
        if (_disposed || _watcher is not null)
        {
            return;
        }

        EnsureChannelEnabled();

        var query = new EventLogQuery(Channel, PathType.LogName, "*[System[(EventID=3076 or EventID=3077)]]");
        _watcher = new EventLogWatcher(query, bookmark: null, readExistingEvents: _replayExisting);
        _watcher.EventRecordWritten += OnEventWritten;
        _watcher.Enabled = true;
    }

    public void Stop()
    {
        if (_watcher is not null)
        {
            _watcher.Enabled = false;
        }
    }

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
        catch
        {
            // If it truly cannot be enabled, Start() surfaces the error via _watcher.Enabled = true.
        }
    }

    private void OnEventWritten(object? sender, EventRecordWrittenEventArgs e)
    {
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
                // A block Warden cannot parse is a block it never adjudicates: the OS block stands, but say so.
                ParseFailed?.Invoke(rec.Id, ex);
            }
        }
    }

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
        if (_watcher is not null)
        {
            _watcher.Enabled = false;
            _watcher.Dispose();
            _watcher = null;
        }
    }
}
