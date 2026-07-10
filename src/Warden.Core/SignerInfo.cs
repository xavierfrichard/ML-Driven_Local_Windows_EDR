using System.Diagnostics.CodeAnalysis;

namespace Warden.Core;

/// <summary>
/// Authenticode signature facts about an image, as extracted by the trust gate. All fields describe
/// the signature as validated at decision time; a file with no signature is represented by
/// <see cref="Unsigned"/>.
/// </summary>
/// <param name="IsSigned">True if the image carries an Authenticode signature.</param>
/// <param name="IsValid">True if the signature chained to a trusted root and verified.</param>
/// <param name="SubjectName">Certificate subject (the publisher), e.g. "CN=Microsoft Corporation".</param>
/// <param name="IssuerName">Certificate issuer.</param>
/// <param name="Thumbprint">SHA-1 thumbprint of the signing certificate, uppercase hex.</param>
/// <param name="IsMicrosoft">True if the signer is a Microsoft root/publisher.</param>
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

    /// <summary>True when the image is signed, the signature verified, and the chain is trusted.</summary>
    public bool IsTrustedSignature => IsSigned && IsValid;
}
