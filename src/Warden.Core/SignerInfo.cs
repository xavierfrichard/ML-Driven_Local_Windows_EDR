using System.Diagnostics.CodeAnalysis;

namespace Warden.Core;

/// <summary>
/// Authenticode signature facts about an image, as extracted by the trust tier. All fields describe
/// the signature as validated at decision time; a file with no signature is represented by
/// <see cref="Unsigned"/>.
/// </summary>
/// <param name="IsSigned">True if the image carries an embedded Authenticode signature blob.</param>
/// <param name="IsValid">
/// True only if the signature <b>cryptographically verified for this file's bytes</b> (WinVerifyTrust)
/// and the certificate chained to a trusted root with the code-signing usage. A certificate that was
/// merely copied into the file's certificate table (a "borrowed" signature) is <b>not</b> valid.
/// </param>
/// <param name="SubjectName">Certificate subject DN (the publisher), e.g. "CN=Microsoft Corporation, O=…".</param>
/// <param name="IssuerName">Certificate issuer DN.</param>
/// <param name="Thumbprint">SHA-1 thumbprint of the signing (leaf) certificate, uppercase hex.</param>
/// <param name="IsMicrosoft">
/// True if the signature is valid and its chain terminates in one of Microsoft's own product code-signing
/// roots (pinned by thumbprint) — never a subject-string heuristic.
/// </param>
public sealed record SignerInfo(
    bool IsSigned,
    bool IsValid,
    string? SubjectName,
    string? IssuerName,
    string? Thumbprint,
    bool IsMicrosoft)
{
    /// <summary>Represents an image with no Authenticode signature.</summary>
    [SuppressMessage("Naming", "CA1720:Identifier contains type name",
        Justification = "'Unsigned' is the correct security-domain term for an image without an Authenticode signature.")]
    public static readonly SignerInfo Unsigned = new(
        IsSigned: false,
        IsValid: false,
        SubjectName: null,
        IssuerName: null,
        Thumbprint: null,
        IsMicrosoft: false);

    /// <summary>The leaf certificate's Common Name (the publisher's display name), when available.</summary>
    public string? SubjectCommonName { get; init; }

    /// <summary>SHA-1 thumbprint of the chain's root certificate, uppercase hex, when the chain built.</summary>
    public string? RootThumbprint { get; init; }

    /// <summary>
    /// Raw verifier status (HRESULT) for diagnostics: 0 = verified; non-zero explains why <see cref="IsValid"/>
    /// is false (e.g. TRUST_E_BAD_DIGEST for a signature that does not match the file).
    /// </summary>
    public int VerificationStatus { get; init; }

    /// <summary>True when the image is signed, the signature verified for these bytes, and the chain is trusted.</summary>
    public bool IsTrustedSignature => IsSigned && IsValid;
}
