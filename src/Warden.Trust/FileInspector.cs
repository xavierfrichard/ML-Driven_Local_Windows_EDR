using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Warden.Core;

namespace Warden.Trust;

/// <summary>
/// On-disk provenance extraction for an image: flat SHA-256, size, embedded Authenticode signer, and
/// Mark-of-the-Web zone. Every method degrades gracefully when the file is missing, unsigned, on a
/// non-NTFS volume, or otherwise unreadable — the enforcement controller calls this on every block and
/// must never fault.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FileInspector : IFileInspector
{
    /// <summary>Extended-key-usage OID for code signing (id-kp-codeSigning).</summary>
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";

    /// <summary>NT SERVICE\TrustedInstaller — owner of most in-box Windows binaries.</summary>
    private static readonly SecurityIdentifier TrustedInstallerSid =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    private readonly HashSet<string> _microsoftRoots;

    /// <summary>Creates an inspector; the options supply the pinned Microsoft root thumbprints.</summary>
    public FileInspector(TrustGateOptions? options = null)
    {
        IEnumerable<string> roots = options?.MicrosoftRootThumbprints ?? new TrustGateOptions().MicrosoftRootThumbprints;
        _microsoftRoots = new HashSet<string>(roots.Select(Normalize), StringComparer.Ordinal);
    }

    /// <summary>
    /// Computes the <b>flat file</b> SHA-256 (digest of every byte). This is deliberately NOT the
    /// Authenticode hash WDAC reports in <c>SHA256 Hash</c>: for a signed PE the two differ because
    /// Authenticode excludes the checksum, the certificate table directory entry, and the embedded
    /// signature blob. Label it as "flat file" wherever it is shown.
    /// </summary>
    /// <returns>Uppercase hex digest, or <c>null</c> if the file cannot be read.</returns>
    public string? ComputeSha256(string path)
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
    public long GetFileSize(string path)
    {
        try { return new FileInfo(path).Length; }
        catch (IOException) { return -1; }
        catch (UnauthorizedAccessException) { return -1; }
    }

    /// <summary>
    /// Reads and <b>verifies</b> the embedded Authenticode signature. Three independent checks feed
    /// <see cref="SignerInfo.IsValid"/>: (1) <see cref="AuthenticodeVerifier"/> (WinVerifyTrust) confirms
    /// the signature digest matches this file's bytes and the chain is trusted; (2) an <see cref="X509Chain"/>
    /// built with the code-signing usage confirms the leaf is a code-signing certificate; (3) the chain's
    /// root thumbprint is compared against the pinned Microsoft roots for <see cref="SignerInfo.IsMicrosoft"/>.
    /// A certificate that was merely copied into the file (a "borrowed" signature) fails (1) with
    /// TRUST_E_BAD_DIGEST and is reported as signed-but-invalid — never trusted.
    /// </summary>
    /// <remarks>
    /// Returns <see cref="SignerInfo.Unsigned"/> for unsigned files and — a known limitation — for
    /// catalog-signed files (most in-box Windows binaries), which have no embedded signature.
    /// </remarks>
    public SignerInfo ReadSigner(string path)
    {
        X509Certificate2 leaf;
        try
        {
            leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
        }
        catch (CryptographicException) { return SignerInfo.Unsigned; }  // unsigned or catalog-only
        catch (IOException) { return SignerInfo.Unsigned; }
        catch (UnauthorizedAccessException) { return SignerInfo.Unsigned; }

        using (leaf)
        {
            // (1) Does the signature actually cover this file? This is the check the old code lacked.
            AuthenticodeVerification verification;
            try
            {
                verification = AuthenticodeVerifier.VerifyEmbeddedSignature(path);
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or IOException)
            {
                verification = new AuthenticodeVerification(false, unchecked((int)0x80004005)); // E_FAIL
            }

            // (2) Chain with the code-signing usage. Revocation is handled (best-effort, cache-only) by
            // WinVerifyTrust above; here we only need the chain shape and its root.
            bool chainOk;
            string? rootThumbprint = null;
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CodeSigningEku));
                // Signing certificates routinely expire after the file was signed; WinVerifyTrust honours the
                // timestamp for that. Mirror it here so an expired-but-timestamped signature is not rejected
                // by this secondary chain check.
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                try
                {
                    chainOk = chain.Build(leaf);
                    if (chain.ChainElements.Count > 0)
                    {
                        rootThumbprint = Normalize(chain.ChainElements[^1].Certificate.Thumbprint);
                    }
                }
                catch (CryptographicException)
                {
                    chainOk = false;
                }
            }

            bool valid = verification.Verified && chainOk;

            // (3) "Microsoft" means the verified chain ends in one of Microsoft's own product roots. No
            // subject-string heuristics: a self-signed "CN=Microsoft Corporation" is not Microsoft.
            bool isMicrosoft = valid && rootThumbprint is not null && _microsoftRoots.Contains(rootThumbprint);

            string? cn;
            try { cn = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false); }
            catch (CryptographicException) { cn = null; }

            return new SignerInfo(
                IsSigned: true,
                IsValid: valid,
                SubjectName: leaf.Subject,
                IssuerName: leaf.Issuer,
                Thumbprint: Normalize(leaf.Thumbprint),
                IsMicrosoft: isMicrosoft)
            {
                SubjectCommonName = string.IsNullOrWhiteSpace(cn) ? null : cn,
                RootThumbprint = rootThumbprint,
                VerificationStatus = verification.Status,
            };
        }
    }

    /// <summary>
    /// Reads the Mark-of-the-Web zone from the NTFS <c>Zone.Identifier</c> alternate data stream.
    /// </summary>
    /// <returns>
    /// The <c>ZoneId</c> (3 = Internet, 4 = Restricted, etc.), or <see cref="VerdictContext.NoMotw"/>
    /// (-1) when the file carries no MOTW stream.
    /// </returns>
    public int ReadMotwZone(string path)
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

    /// <inheritdoc />
    public bool IsOwnedByPrivilegedAccount(string path)
    {
        try
        {
            FileSecurity acl = new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
            if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner)
            {
                return false;
            }

            return owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
                || owner.Equals(TrustedInstallerSid);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or System.Security.SecurityException or IdentityNotMappedException)
        {
            return false;
        }
    }

    private static string Normalize(string thumbprint) =>
        thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
}
