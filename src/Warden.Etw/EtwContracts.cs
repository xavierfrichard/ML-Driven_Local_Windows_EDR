namespace Warden.Etw;

/// <summary>
/// A single process-start event, normalized for correlation. Sourced from the NT Kernel Logger, which
/// (unlike the manifest provider) carries the command line and parent id together.
/// </summary>
public sealed record ProcessStartRecord(
    int Pid,
    int ParentPid,
    string ImagePath,
    string CommandLine,
    DateTimeOffset Timestamp,
    bool? Elevated);

/// <summary>
/// A parsed WDAC / App Control block event (3076 audit, 3077 enforce) from the
/// <c>Microsoft-Windows-CodeIntegrity/Operational</c> channel.
/// </summary>
public sealed record CiBlockEvent(
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

/// <summary>A real-time source of process-start events (implemented by the NT Kernel Logger session).</summary>
public interface IProcessStartSource : IDisposable
{
    event Action<ProcessStartRecord>? ProcessStarted;

    /// <summary>Begins pumping events on a background thread. Non-blocking.</summary>
    void Start();

    /// <summary>Stops pumping and tears down the underlying ETW session.</summary>
    void Stop();
}

/// <summary>A source of WDAC block events (implemented by the CodeIntegrity/Operational watcher).</summary>
public interface ICodeIntegrityBlockSource : IDisposable
{
    event Action<CiBlockEvent>? BlockObserved;

    /// <summary>Begins delivering block events. Requires elevation.</summary>
    void Start();

    /// <summary>Stops delivering block events.</summary>
    void Stop();
}
