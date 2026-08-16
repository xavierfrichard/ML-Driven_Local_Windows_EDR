namespace Warden.Core;

/// <summary>
/// Identifies which tier of the decision pipeline produced a verdict. Ordered cheap-to-expensive;
/// the numeric values reflect evaluation order but the pipeline order is defined by registration,
/// not by this enum.
/// </summary>
/// <remarks>
/// <b>Whitelist runs before TrustGate on purpose.</b> The whitelist holds explicit prior decisions —
/// including a user's or administrator's "keep blocked" — and an explicit prior decision must outrank
/// any automatic fast-allow. With the reverse order a validly-signed file the user had blocked would be
/// re-allowed by the trust gate and the Block overwritten.
/// </remarks>
public enum VerdictSourceKind
{
    /// <summary>User-defined allow/block rules (hash, signature, folder, extension).</summary>
    Rules = 0,

    /// <summary>Prior allow/block already recorded for this file or publisher.</summary>
    Whitelist,

    /// <summary>Authenticode trust gate: known-good signer from a trusted path.</summary>
    TrustGate,

    /// <summary>VirusTotal hash reputation (cached, offline-tolerant).</summary>
    VirusTotal,

    /// <summary>Local machine-learning score (EMBER features over an ONNX model).</summary>
    Ml,

    /// <summary>LLM analyst verdict from a structured dossier.</summary>
    Llm,

    /// <summary>A decision the user made at a prompt.</summary>
    UserPrompt,

    /// <summary>The pipeline fell through with no decisive source.</summary>
    Fallthrough,
}
