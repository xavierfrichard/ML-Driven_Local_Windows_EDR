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

    /// <summary>Engine-detection count at or above which a file is decisively blocked.</summary>
    public int BlockThreshold { get; set; } = 5;

    /// <summary>
    /// When true, a well-known clean file (zero detections across at least
    /// <see cref="CleanMinEngines"/> engines) is decisively allowed. Off by default: a 0/N result is
    /// weak evidence (new malware is undetected), so unknown files fall through to ML/LLM/prompt.
    /// </summary>
    public bool AllowKnownClean { get; set; }

    /// <summary>Minimum reporting engines required before a zero-detection file may be auto-allowed.</summary>
    public int CleanMinEngines { get; set; } = 40;

    /// <summary>Per-day request budget (VirusTotal free tier is limited). 0 = unlimited.</summary>
    public int DailyRequestBudget { get; set; } = 480;
}
