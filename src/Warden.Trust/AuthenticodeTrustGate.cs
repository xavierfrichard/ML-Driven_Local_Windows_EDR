using Warden.Core;

namespace Warden.Trust;

/// <summary>
/// The Authenticode trust gate: a cheap, deterministic fast-allow tier. It decisively allows a launch
/// only when the image carries a trusted signature from a trusted publisher <b>and</b> lives under a
/// trusted path prefix. It never blocks — a file that fails any check is left
/// <see cref="VerdictResult.Undecided"/> so later, more discerning tiers (reputation, ML, LLM) get to
/// weigh in. This asymmetry is deliberate: the gate can only shortcut known-good launches, never
/// condemn, which keeps the pipeline fail-safe.
/// </summary>
public sealed class AuthenticodeTrustGate : IVerdictSource
{
    private readonly TrustGateOptions _options;

    /// <summary>Creates the gate with the supplied trust policy.</summary>
    /// <param name="options">Trusted publishers, path prefixes, and the Microsoft-trust toggle.</param>
    public AuthenticodeTrustGate(TrustGateOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public VerdictSourceKind Kind => VerdictSourceKind.TrustGate;

    /// <inheritdoc />
    public ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        return new ValueTask<VerdictResult>(Evaluate(context));
    }

    private VerdictResult Evaluate(VerdictContext context)
    {
        SignerInfo signer = context.Signer;

        // A trusted signature (signed + verified chain) is the precondition for any fast-allow.
        if (!signer.IsTrustedSignature)
        {
            return VerdictResult.Undecided(Kind, "Image is unsigned or its signature did not verify.");
        }

        // The publisher must be one we trust: Microsoft (when enabled), or a configured publisher substring.
        if (!IsTrustedPublisher(signer))
        {
            return VerdictResult.Undecided(Kind, "Signature is valid but the publisher is not on the trust list.");
        }

        // Defence-in-depth: a validly-signed binary dropped in a user-writable folder still gets scrutinized.
        if (!IsUnderTrustedPath(context.ImagePath))
        {
            return VerdictResult.Undecided(Kind, "Trusted publisher, but the image is not under a trusted path prefix.");
        }

        string reason = signer.IsMicrosoft && _options.TrustMicrosoft
            ? "Validly-signed Microsoft binary from a trusted path."
            : $"Validly-signed binary from trusted publisher '{signer.SubjectName}' at a trusted path.";

        return new VerdictResult(Verdict.Allow, Kind, 1.0d, reason);
    }

    private bool IsTrustedPublisher(SignerInfo signer)
    {
        if (signer.IsMicrosoft && _options.TrustMicrosoft)
        {
            return true;
        }

        string? subject = signer.SubjectName;
        if (string.IsNullOrEmpty(subject))
        {
            return false;
        }

        foreach (string publisher in _options.TrustedPublishers)
        {
            if (!string.IsNullOrEmpty(publisher) &&
                subject.Contains(publisher, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private bool IsUnderTrustedPath(string imagePath)
    {
        if (string.IsNullOrEmpty(imagePath))
        {
            return false;
        }

        foreach (string prefix in _options.TrustedPathPrefixes)
        {
            if (!string.IsNullOrEmpty(prefix) &&
                imagePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
