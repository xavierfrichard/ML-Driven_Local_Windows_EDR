namespace Warden.Ml;

/// <summary>Configuration for the ML (ONNX) verdict tier.</summary>
public sealed class MlOptions
{
    /// <summary>Path to the ONNX model. When the file is absent the tier is disabled (always undecided).</summary>
    public string ModelPath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden", "ml", "model.onnx");

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
}
