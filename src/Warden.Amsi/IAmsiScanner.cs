namespace Warden.Amsi;

/// <summary>Result of an AMSI content scan.</summary>
public enum AmsiVerdict
{
    /// <summary>AMSI was not consulted (unavailable / not initialized).</summary>
    NotChecked = 0,

    /// <summary>Content is clean (result below the detection threshold).</summary>
    Clean,

    /// <summary>Content was flagged as malicious.</summary>
    Detected,
}

/// <summary>An AMSI scan outcome plus the raw AMSI_RESULT value.</summary>
public sealed record AmsiScanOutcome(AmsiVerdict Verdict, int RawResult)
{
    public static readonly AmsiScanOutcome NotChecked = new(AmsiVerdict.NotChecked, 0);
}

/// <summary>
/// Scans script/content buffers through the Antimalware Scan Interface (amsi.dll). Used to inspect the
/// content behind script-host launches (PowerShell/JS/VBA). Degrades to
/// <see cref="AmsiScanOutcome.NotChecked"/> when AMSI is unavailable.
/// </summary>
public interface IAmsiScanner
{
    AmsiScanOutcome Scan(ReadOnlySpan<byte> content, string contentName);
    AmsiScanOutcome Scan(string content, string contentName);
}
