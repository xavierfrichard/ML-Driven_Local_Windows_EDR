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
}

/// <summary>Configuration for the Authenticode trust gate.</summary>
public sealed class TrustGateOptions
{
    /// <summary>Allow validly-signed Microsoft binaries from a trusted path without further checks.</summary>
    public bool TrustMicrosoft { get; set; } = true;

    /// <summary>Additional trusted publisher subject substrings (case-insensitive).</summary>
    public IList<string> TrustedPublishers { get; } = new List<string>();

    /// <summary>
    /// Trusted path prefixes (case-insensitive). A signed file must also live under one of these to be
    /// auto-allowed, so a validly-signed binary dropped in a user-writable folder still gets scrutinized.
    /// </summary>
    public IList<string> TrustedPathPrefixes { get; } = new List<string>
    {
        @"C:\Windows\",
        @"C:\Program Files\",
        @"C:\Program Files (x86)\",
    };
}
