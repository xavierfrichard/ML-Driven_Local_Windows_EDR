using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Warden.Core;

namespace Warden.Spike;

/// <summary>
/// On-disk provenance extraction for a blocked image: flat SHA-256, Authenticode signer, and
/// Mark-of-the-Web zone. Every method degrades gracefully when the file is missing, unsigned, on a
/// non-NTFS volume, or otherwise unreadable — the spike must never throw out of the correlator.
/// </summary>
internal static class FileInspector
{
    /// <summary>
    /// Computes the <b>flat file</b> SHA-256 (digest of every byte). This is deliberately NOT the
    /// Authenticode hash WDAC reports in <c>SHA256 Hash</c>: for a signed PE the two differ because
    /// Authenticode excludes the checksum, the certificate table directory entry, and the embedded
    /// signature blob. Label it as "flat file" wherever it is shown.
    /// </summary>
    /// <returns>Uppercase hex digest, or <c>null</c> if the file cannot be read.</returns>
    public static string? Sha256FlatHex(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(fs)); // uppercase, matches Warden.Core convention
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>File length in bytes, or -1 if the file is missing/unreadable.</summary>
    public static long FileSize(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (IOException) { return -1; }
        catch (UnauthorizedAccessException) { return -1; }
    }

    /// <summary>
    /// Reads the embedded Authenticode leaf certificate and builds a chain to decide validity and
    /// whether it chains to Microsoft. Returns <see cref="SignerInfo.Unsigned"/> for unsigned files
    /// and — a known spike limitation — for catalog-signed files (most in-box Windows binaries), which
    /// <see cref="X509Certificate.CreateFromSignedFile"/> cannot see. Phase 1 should use WinVerifyTrust.
    /// </summary>
    public static SignerInfo ReadSigner(string path)
    {
        try
        {
            using var leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));

            bool valid;
            bool chainsToMicrosoft;
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // offline VM friendly
                valid = chain.Build(leaf);
                chainsToMicrosoft = chain.ChainElements
                    .Cast<X509ChainElement>()
                    .Any(el => el.Certificate.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));
            }

            // Fall back to a subject-string heuristic if the chain could not be built offline.
            if (!chainsToMicrosoft)
            {
                chainsToMicrosoft =
                    leaf.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                    leaf.Issuer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
            }

            return new SignerInfo(
                IsSigned: true,
                IsValid: valid,
                SubjectName: leaf.Subject,
                IssuerName: leaf.Issuer,
                Thumbprint: leaf.Thumbprint, // uppercase hex per X509Certificate2
                IsMicrosoft: chainsToMicrosoft);
        }
        catch (CryptographicException) { return SignerInfo.Unsigned; }  // unsigned or catalog-only
        catch (IOException) { return SignerInfo.Unsigned; }
    }

    /// <summary>
    /// Reads the Mark-of-the-Web zone from the NTFS <c>Zone.Identifier</c> alternate data stream.
    /// </summary>
    /// <returns>
    /// The <c>ZoneId</c> (3 = Internet, 4 = Restricted, etc.), or <see cref="VerdictContext.NoMotw"/>
    /// (-1) when the file carries no MOTW stream.
    /// </returns>
    public static int ReadMotwZone(string path)
    {
        string adsPath = path + ":Zone.Identifier";
        try
        {
            using var fs = new FileStream(adsPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new StreamReader(fs);
            bool inZoneTransfer = false;
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                line = line.Trim();
                if (line.StartsWith('['))
                {
                    inZoneTransfer = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase);
                }
                else if (inZoneTransfer && line.StartsWith("ZoneId", StringComparison.OrdinalIgnoreCase))
                {
                    int eq = line.IndexOf('=');
                    if (eq > 0 && int.TryParse(line[(eq + 1)..].Trim(), out int zone))
                    {
                        return zone;
                    }
                }
            }
            return VerdictContext.NoMotw; // stream present but no ZoneId key
        }
        catch (FileNotFoundException) { return VerdictContext.NoMotw; }      // no ADS -> no MOTW
        catch (DirectoryNotFoundException) { return VerdictContext.NoMotw; }
        catch (IOException) { return VerdictContext.NoMotw; }                // e.g. non-NTFS volume
        catch (UnauthorizedAccessException) { return VerdictContext.NoMotw; }
    }
}
