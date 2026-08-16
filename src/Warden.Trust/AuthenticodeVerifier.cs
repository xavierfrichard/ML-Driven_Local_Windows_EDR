using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Warden.Trust;

/// <summary>Outcome of a <see cref="AuthenticodeVerifier.VerifyEmbeddedSignature"/> call.</summary>
/// <param name="Verified">True only when WinVerifyTrust returned S_OK: the embedded signature is
/// cryptographically valid <b>for these file bytes</b> and chains to a trusted root.</param>
/// <param name="Status">The raw HRESULT (0 on success). Common failures: <c>TRUST_E_NOSIGNATURE</c>
/// (0x800B0100), <c>TRUST_E_BAD_DIGEST</c> (0x80096010 — a signature copied from another file),
/// <c>CERT_E_UNTRUSTEDROOT</c> (0x800B0109), <c>TRUST_E_EXPLICIT_DISTRUST</c> (0x800B0111).</param>
public readonly record struct AuthenticodeVerification(bool Verified, int Status)
{
    /// <summary>The file carries no embedded Authenticode signature at all.</summary>
    public bool NoSignature => Status == AuthenticodeVerifier.TRUST_E_NOSIGNATURE;

    /// <summary>The signature does not match the file's bytes (grafted / tampered).</summary>
    public bool BadDigest => Status == AuthenticodeVerifier.TRUST_E_BAD_DIGEST;
}

/// <summary>
/// Verifies an image's <b>embedded</b> Authenticode signature with <c>WinVerifyTrust</c>
/// (<c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c>). Unlike <c>X509Certificate.CreateFromSignedFile</c>,
/// which merely extracts the certificate blob, this checks that the signature's digest matches the
/// file, that the chain builds to a trusted root, and honours explicit distrust. Revocation is checked
/// best-effort from the local cache only, so an offline machine still verifies.
/// </summary>
/// <remarks>
/// Catalog-signed files (most in-box Windows binaries) have no embedded signature and report
/// <see cref="AuthenticodeVerification.NoSignature"/>; a catalog lookup is a possible later addition.
/// This type is intentionally free of policy — it answers "is the embedded signature valid for this
/// file?", and <see cref="FileInspector"/> decides what that means.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class AuthenticodeVerifier
{
    // HRESULTs surfaced to callers.
    internal const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    internal const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    internal const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    // Best-effort revocation on the chain (excluding the root) using only the local CRL/OCSP cache —
    // never a network fetch — so a disconnected VM still verifies. WTD_SAFER_FLAG is deliberately NOT
    // set: it collapses "bad digest" into TRUST_E_NOSIGNATURE, and we want the distinct status for
    // diagnostics (a grafted signature is a much stronger malicious indicator than no signature).
    private const uint WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000040;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    /// <summary>
    /// Verifies the embedded signature of <paramref name="path"/>. Never throws for an ordinary
    /// verification failure — the HRESULT is returned in <see cref="AuthenticodeVerification.Status"/>.
    /// </summary>
    public static AuthenticodeVerification VerifyEmbeddedSignature(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr pathPtr = IntPtr.Zero;
        IntPtr trustDataPtr = IntPtr.Zero;
        try
        {
            pathPtr = Marshal.StringToHGlobalUni(path);

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero,
            };
            trustDataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(trustData, trustDataPtr, fDeleteOld: false);

            Guid action = WintrustActionGenericVerifyV2;
            int status = WinVerifyTrust(IntPtr.Zero, ref action, trustDataPtr);

            // Release the verifier's state handle regardless of outcome.
            trustData = Marshal.PtrToStructure<WINTRUST_DATA>(trustDataPtr);
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(trustData, trustDataPtr, fDeleteOld: false);
            _ = WinVerifyTrust(IntPtr.Zero, ref action, trustDataPtr);

            return new AuthenticodeVerification(status == 0, status);
        }
        finally
        {
            if (trustDataPtr != IntPtr.Zero) { Marshal.FreeHGlobal(trustDataPtr); }
            if (fileInfoPtr != IntPtr.Zero) { Marshal.FreeHGlobal(fileInfoPtr); }
            if (pathPtr != IntPtr.Zero) { Marshal.FreeHGlobal(pathPtr); }
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
