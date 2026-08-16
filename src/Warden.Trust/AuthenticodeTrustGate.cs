using Warden.Core;

namespace Warden.Trust;

/// <summary>
/// The Authenticode trust gate: a cheap, deterministic fast-allow tier. It decisively allows a launch
/// only when the image carries a <b>verified</b> signature from a trusted publisher, lives under a
/// trusted path prefix (and not in a user-writable pocket of it), and is owned by a privileged account.
/// It never blocks — a file that fails any check is left <see cref="VerdictResult.Undecided"/> so
/// later, more discerning tiers (reputation, ML, LLM) get to weigh in. This asymmetry is deliberate:
/// the gate can only shortcut known-good launches, never condemn, which keeps the pipeline fail-safe.
/// </summary>
public sealed class AuthenticodeTrustGate : IVerdictSource
{
    private readonly TrustGateOptions _options;
    private readonly IFileInspector? _inspector;

    /// <summary>Creates the gate with the supplied trust policy.</summary>
    /// <param name="options">Trusted publishers, path prefixes, and the Microsoft-trust toggle.</param>
    /// <param name="inspector">
    /// Used for the image-owner check. When null and <see cref="TrustGateOptions.RequireAdminOwnedImage"/>
    /// is set, the gate declines (fail-safe) rather than skipping the check.
    /// </param>
    public AuthenticodeTrustGate(TrustGateOptions options, IFileInspector? inspector = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _inspector = inspector;
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
        if (context is null)
        {
            return VerdictResult.Undecided(Kind, "No context.");
        }

        SignerInfo signer = context.Signer;

        // A verified signature (digest matches the file + trusted chain) is the precondition for any fast-allow.
        if (!signer.IsTrustedSignature)
        {
            return VerdictResult.Undecided(Kind, "Image is unsigned or its signature did not verify.");
        }

        // The publisher must be one we trust: Microsoft (when enabled), or a configured publisher.
        if (!IsTrustedPublisher(signer))
        {
            return VerdictResult.Undecided(Kind, "Signature is valid but the publisher is not on the trust list.");
        }

        // Defence-in-depth: a validly-signed binary dropped in a user-writable folder still gets scrutinized.
        if (!IsUnderTrustedPath(context.ImagePath, out string pathReason))
        {
            return VerdictResult.Undecided(Kind, pathReason);
        }

        if (_options.RequireAdminOwnedImage)
        {
            if (_inspector is null)
            {
                return VerdictResult.Undecided(Kind, "Owner check required but no file inspector is available.");
            }

            if (!_inspector.IsOwnedByPrivilegedAccount(context.ImagePath))
            {
                return VerdictResult.Undecided(Kind, "Trusted publisher and path, but the image is not owned by SYSTEM/Administrators/TrustedInstaller.");
            }
        }

        string reason = signer.IsMicrosoft && _options.TrustMicrosoft
            ? "Verified Microsoft signature from a trusted, privileged-owned path."
            : $"Verified signature from trusted publisher '{signer.SubjectCommonName ?? signer.SubjectName}' at a trusted, privileged-owned path.";

        return new VerdictResult(Verdict.Allow, Kind, 1.0d, reason);
    }

    private bool IsTrustedPublisher(SignerInfo signer)
    {
        if (signer.IsMicrosoft && _options.TrustMicrosoft)
        {
            return true;
        }

        if (!string.IsNullOrEmpty(signer.Thumbprint))
        {
            foreach (string pinned in _options.TrustedPublisherThumbprints)
            {
                if (!string.IsNullOrWhiteSpace(pinned) &&
                    string.Equals(NormalizeThumbprint(pinned), NormalizeThumbprint(signer.Thumbprint), StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        // Exact Common-Name match only. A substring over the whole DN would let "O=Not Contoso" match "Contoso".
        string? cn = signer.SubjectCommonName ?? ExtractCommonName(signer.SubjectName);
        if (string.IsNullOrEmpty(cn))
        {
            return false;
        }

        foreach (string publisher in _options.TrustedPublishers)
        {
            if (!string.IsNullOrWhiteSpace(publisher) &&
                string.Equals(cn.Trim(), publisher.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// A path is trusted when its canonical form starts with a trusted prefix and does <b>not</b> start
    /// with any user-writable carve-out. Canonicalization resolves <c>..</c> segments and relative forms;
    /// unusual forms that cannot be canonicalized are simply not trusted (fail-safe).
    /// </summary>
    private bool IsUnderTrustedPath(string imagePath, out string reason)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            reason = "No image path.";
            return false;
        }

        string canonical;
        try
        {
            canonical = Path.GetFullPath(imagePath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or System.Security.SecurityException)
        {
            reason = "Image path could not be canonicalized.";
            return false;
        }

        // Device / UNC / extended-prefix forms are never fast-allowed: they bypass the prefix semantics.
        if (canonical.StartsWith(@"\\", StringComparison.Ordinal))
        {
            reason = "Image path is a UNC or device path; not fast-allowed.";
            return false;
        }

        foreach (string carveOut in _options.UntrustedPathPrefixes)
        {
            if (!string.IsNullOrWhiteSpace(carveOut) && StartsWithDirectory(canonical, carveOut))
            {
                reason = "Trusted publisher, but the image lives in a user-writable location under a trusted root.";
                return false;
            }
        }

        foreach (string prefix in _options.TrustedPathPrefixes)
        {
            if (!string.IsNullOrWhiteSpace(prefix) && StartsWithDirectory(canonical, prefix))
            {
                reason = string.Empty;
                return true;
            }
        }

        reason = "Trusted publisher, but the image is not under a trusted path prefix.";
        return false;
    }

    /// <summary>Prefix match that treats the prefix as a directory (so "C:\Windows" cannot match "C:\Windows2\x").</summary>
    private static bool StartsWithDirectory(string canonicalPath, string prefix)
    {
        string dir = prefix.EndsWith(Path.DirectorySeparatorChar) || prefix.EndsWith(Path.AltDirectorySeparatorChar)
            ? prefix
            : prefix + Path.DirectorySeparatorChar;
        return canonicalPath.StartsWith(dir, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeThumbprint(string value) =>
        value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

    /// <summary>Best-effort CN extraction from a DN string (used only when the inspector did not supply one).</summary>
    internal static string? ExtractCommonName(string? distinguishedName)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return null;
        }

        foreach (string part in SplitDn(distinguishedName))
        {
            string p = part.Trim();
            if (p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                string value = p[3..].Trim();
                if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
                {
                    value = value[1..^1].Replace("\"\"", "\"", StringComparison.Ordinal);
                }
                return value.Length == 0 ? null : value;
            }
        }
        return null;
    }

    // Splits on commas that are not inside a quoted value.
    private static IEnumerable<string> SplitDn(string dn)
    {
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (char c in dn)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            if (c == ',' && !inQuotes)
            {
                yield return current.ToString();
                current.Clear();
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0)
        {
            yield return current.ToString();
        }
    }
}
