namespace Warden.Reputation;

/// <summary>Configuration for the VirusTotal reputation tier.</summary>
public sealed class ReputationOptions
{
    /// <summary>VirusTotal API key. When null/empty the tier is disabled (always undecided).</summary>
    public string? ApiKey { get; set; }

    /// <summary>Base address of the VirusTotal v3 API.</summary>
    public Uri BaseAddress { get; set; } = new("https://www.virustotal.com/api/v3/");

    /// <summary>Cache time-to-live for a hash verdict.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Cache time-to-live for a "not in VirusTotal" (404) answer. Short: a new sample is often uploaded and
    /// scanned within the hour, and a day-long "unknown" would hide its detections.
    /// </summary>
    public TimeSpan NotFoundCacheTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Engine count at or above which a file is decisively blocked. Engines that report "malicious" and
    /// engines that report "suspicious" both count (the cache stores one "flagged" number).
    /// </summary>
    public int BlockThreshold { get; set; } = 5;

    /// <summary>
    /// When true, a well-known clean file (no engine reporting "malicious" <b>or</b> "suspicious", across at
    /// least <see cref="CleanMinEngines"/> engines) is decisively allowed. Off by default: a 0/N result is
    /// weak evidence (new malware is undetected), so unknown files fall through to ML/LLM/prompt.
    /// </summary>
    public bool AllowKnownClean { get; set; }

    /// <summary>Minimum reporting engines required before a zero-detection file may be auto-allowed.</summary>
    public int CleanMinEngines { get; set; } = 40;

    /// <summary>Per-day request budget (VirusTotal free tier is limited). 0 = unlimited.</summary>
    public int DailyRequestBudget { get; set; } = 480;

    /// <summary>
    /// Per-request timeout. The enforcement loop is serial, so a hung lookup would stall every later
    /// decision — this must stay short (the HttpClient default of 100 s is far too long).
    /// </summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Oldest cached record that may still drive an <b>allow</b> while offline. Stale records are always
    /// good enough to <i>block</i> on (a detection does not age out), but a months-old "0/70 clean" must not
    /// keep auto-allowing a file forever.
    /// </summary>
    public TimeSpan MaxAllowStaleness { get; set; } = TimeSpan.FromDays(7);
}
