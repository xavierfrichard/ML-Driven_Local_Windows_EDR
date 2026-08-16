using Warden.Core;

namespace Warden.Trust;

/// <summary>
/// On-disk provenance extraction for an image: flat SHA-256, size, Authenticode signer, and
/// Mark-of-the-Web zone. Implementations must degrade gracefully (never throw) when a file is missing,
/// unsigned, on a non-NTFS volume, or otherwise unreadable — the enforcement controller calls this on
/// every block and must never fault.
/// </summary>
public interface IFileInspector
{
    /// <summary>Flat-file SHA-256 (uppercase hex), or null if unreadable. NOT the Authenticode hash.</summary>
    string? ComputeSha256(string path);

    /// <summary>File length in bytes, or -1 if missing/unreadable.</summary>
    long GetFileSize(string path);

    /// <summary>Embedded Authenticode signer facts, or <see cref="SignerInfo.Unsigned"/>.</summary>
    SignerInfo ReadSigner(string path);

    /// <summary>Mark-of-the-Web zone from the Zone.Identifier ADS, or <see cref="VerdictContext.NoMotw"/>.</summary>
    int ReadMotwZone(string path);

    /// <summary>
    /// True only when the file's NTFS owner is SYSTEM, BUILTIN\Administrators or TrustedInstaller — i.e.
    /// a standard user could not have placed it there. Any failure to read the owner returns false.
    /// </summary>
    bool IsOwnedByPrivilegedAccount(string path);
}

/// <summary>Configuration for the Authenticode trust gate.</summary>
public sealed class TrustGateOptions
{
    /// <summary>Allow validly-signed Microsoft binaries from a trusted path without further checks.</summary>
    public bool TrustMicrosoft { get; set; } = true;

    /// <summary>
    /// Additional trusted publishers, matched <b>exactly</b> (case-insensitive) against the signing
    /// certificate's Common Name — not a substring of the whole DN.
    /// </summary>
    public IList<string> TrustedPublishers { get; } = new List<string>();

    /// <summary>Additional trusted publishers pinned by leaf-certificate SHA-1 thumbprint (uppercase hex).</summary>
    public IList<string> TrustedPublisherThumbprints { get; } = new List<string>();

    /// <summary>
    /// SHA-1 thumbprints of the root certificates that make a chain "Microsoft". Only Microsoft's own
    /// product code-signing roots belong here — <i>not</i> the Microsoft Identity Verification root that
    /// anchors third-party Trusted Signing, and not the time-stamping roots.
    /// </summary>
    public IList<string> MicrosoftRootThumbprints { get; } = new List<string>
    {
        "A43489159A520F0D93D032CCAF37E7FE20A8B419", // Microsoft Root Authority (1997)
        "CDD4EEAE6000AC7F40C3802C171E30148030C072", // Microsoft Root Certificate Authority (2001)
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5", // Microsoft Root Certificate Authority 2010
        "8F43288AD272F3103B6FB1428485EA3014C0BCFE", // Microsoft Root Certificate Authority 2011
        "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74", // Microsoft RSA Root Certificate Authority 2017
        "999A64C37FF47D9FAB95F14769891460EEC4C3C5", // Microsoft ECC Root Certificate Authority 2017
        "06F1AA330B927B753A40E68CDF22E34BCBEF3352", // Microsoft ECC Product Root Certificate Authority 2018
    };

    /// <summary>
    /// Trusted path prefixes (case-insensitive, canonicalized). A signed file must also live under one of
    /// these to be auto-allowed, so a validly-signed binary dropped in a user-writable folder still gets
    /// scrutinized. See <see cref="UntrustedPathPrefixes"/> for the carve-outs.
    /// </summary>
    public IList<string> TrustedPathPrefixes { get; } = new List<string>
    {
        @"C:\Windows\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
    };

    /// <summary>
    /// Subtrees under a trusted prefix that standard users can write to (the classic UAC-bypass drop
    /// locations). Anything under these is never fast-allowed, whatever its signature.
    /// </summary>
    public IList<string> UntrustedPathPrefixes { get; } = new List<string>
    {
        @"C:\Windows\Temp\",
        @"C:\Windows\Tasks\",
        @"C:\Windows\tracing\",
        @"C:\Windows\Registration\CRMLog\",
        @"C:\Windows\debug\WIA\",
        @"C:\Windows\PLA\",
        @"C:\Windows\System32\Tasks\",
        @"C:\Windows\System32\spool\drivers\color\",
        @"C:\Windows\System32\spool\PRINTERS\",
        @"C:\Windows\System32\spool\SERVERS\",
        @"C:\Windows\System32\FxsTmp\",
        @"C:\Windows\System32\com\dmp\",
        @"C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\",
        @"C:\Windows\SysWOW64\Tasks\",
        @"C:\Windows\SysWOW64\FxsTmp\",
        @"C:\Windows\SysWOW64\com\dmp\",
        @"C:\Windows\ServiceProfiles\",
    };

    /// <summary>
    /// Require the image file to be owned by SYSTEM / Administrators / TrustedInstaller before a
    /// fast-allow (defence in depth against a user-writable pocket under a trusted prefix that is not in
    /// <see cref="UntrustedPathPrefixes"/>). When true and no <see cref="IFileInspector"/> is available to
    /// the gate, it declines rather than allows.
    /// </summary>
    public bool RequireAdminOwnedImage { get; set; } = true;
}
