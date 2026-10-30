namespace Warden.Ml;

/// <summary>Configuration for the ML (ONNX) verdict tier.</summary>
public sealed class MlOptions
{
    /// <summary>Path to the ONNX model. When the file is absent the tier is disabled (always undecided).</summary>
    public string ModelPath { get; set; } = Warden.Core.WardenPaths.Under("ml", "model.onnx");

    /// <summary>
    /// SHA-256 (hex) the model file must match to be loaded. <b>Required</b> whenever a model file exists:
    /// whoever can write <c>model.onnx</c> owns the ML verdict, so a model with no pin (or a malformed one) is
    /// refused and the tier stays undecided. The service reads it from the protected secret store
    /// (<c>installer\Set-WardenSecret.ps1 -Name MlModelSha256</c>).
    /// </summary>
    public string? ModelSha256 { get; set; }

    /// <summary>
    /// File-system trust check for <see cref="ModelPath"/>: null when the file and its folders are owned by
    /// SYSTEM, Administrators or TrustedInstaller and nobody else can change them; otherwise a reason. The
    /// service injects one built on <c>Warden.Hardening.FolderWriteAccess</c>. When null, no model is loaded
    /// (fail closed).
    /// </summary>
    public Func<string, string?>? ModelFileTrustCheck { get; set; }

    /// <summary>Largest model file loaded (read once into memory, hashed, then handed to ONNX Runtime).</summary>
    public long MaxModelBytes { get; set; } = 512L * 1024 * 1024;

    /// <summary>Model score at/above which the file is decisively blocked (tuned ~1% FPR).</summary>
    public double HighThreshold { get; set; } = 0.90;

    /// <summary>Model score at/below which a benign auto-allow is permitted (only if <see cref="AllowOnLowScore"/>).</summary>
    public double LowThreshold { get; set; } = 0.05;

    /// <summary>
    /// When false (default), the ML tier only ever blocks (high score) and defers everything else to the
    /// LLM/prompt — a 0/low ML score is weak evidence of benignity. Enable to let a very low score auto-allow.
    /// </summary>
    public bool AllowOnLowScore { get; set; }

    /// <summary>Model version string, recorded alongside scores.</summary>
    public string ModelVersion { get; set; } = "unknown";

    /// <summary>
    /// Largest image the ML tier / PE reader will load into memory (the EMBER extractor copies the buffer,
    /// so the real cost is ~2×). Bigger files are simply not scored — an attacker-controlled file must not be
    /// able to make the SYSTEM service allocate gigabytes.
    /// </summary>
    public long MaxImageBytes { get; set; } = 64L * 1024 * 1024;
}
