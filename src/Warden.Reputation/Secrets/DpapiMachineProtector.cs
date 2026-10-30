using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Warden.Secrets;

/// <summary>Decrypts a stored secret blob. Abstracted so tests can use a fake.</summary>
public interface ISecretUnprotector
{
    /// <summary>Returns the plaintext, or throws when the blob is corrupt or bound to other entropy.</summary>
    byte[] Unprotect(byte[] blob, byte[] entropy);
}

/// <summary>
/// DPAPI with <b>machine</b> scope (<c>CryptProtectData</c> + <c>CRYPTPROTECT_LOCAL_MACHINE</c>), the same scheme
/// as <c>[System.Security.Cryptography.ProtectedData]::Protect(..., 'LocalMachine')</c> in
/// <c>installer\Set-WardenSecret.ps1</c>. Called through crypt32 directly so no package is added.
/// </summary>
/// <remarks>
/// Machine scope means any process on this machine could decrypt the blob <i>if it can read the file</i>, so the
/// file's access list (SYSTEM + Administrators only, checked by <see cref="WardenSecretStore"/>) is the real
/// control. DPAPI adds protection at rest: the blob is useless on another machine, in a backup, or on a disk
/// image read offline.
/// </remarks>
public sealed class DpapiMachineProtector : ISecretUnprotector
{
    private const int CryptProtectUiForbidden = 0x1;
    private const int CryptProtectLocalMachine = 0x4;

    /// <inheritdoc />
    public byte[] Unprotect(byte[] blob, byte[] entropy)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentNullException.ThrowIfNull(entropy);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI is only available on Windows.");
        }
        return Transform(blob, entropy, protect: false);
    }

    /// <summary>Encrypts <paramref name="plaintext"/> for this machine (used by tests; the script does the same).</summary>
    public static byte[] Protect(byte[] plaintext, byte[] entropy)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(entropy);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI is only available on Windows.");
        }
        return Transform(plaintext, entropy, protect: true);
    }

    private static byte[] Transform(byte[] input, byte[] entropy, bool protect)
    {
        GCHandle inHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
        GCHandle entropyHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
        var output = default(DataBlob);
        try
        {
            var inBlob = new DataBlob { cbData = input.Length, pbData = inHandle.AddrOfPinnedObject() };
            var entropyBlob = new DataBlob { cbData = entropy.Length, pbData = entropyHandle.AddrOfPinnedObject() };
            bool ok = protect
                ? NativeMethods.CryptProtectData(ref inBlob, null, ref entropyBlob, IntPtr.Zero, IntPtr.Zero,
                    CryptProtectUiForbidden | CryptProtectLocalMachine, out output)
                : NativeMethods.CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero,
                    CryptProtectUiForbidden, out output);
            if (!ok)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            byte[] result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, output.cbData);
            return result;
        }
        finally
        {
            if (output.pbData != IntPtr.Zero)
            {
                NativeMethods.LocalFree(output.pbData);
            }
            inHandle.Free();
            entropyHandle.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    private static class NativeMethods
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptProtectData(
            ref DataBlob pDataIn, string? szDataDescr, ref DataBlob pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DataBlob pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptUnprotectData(
            ref DataBlob pDataIn, IntPtr ppszDataDescr, ref DataBlob pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DataBlob pDataOut);

        [DllImport("kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern IntPtr LocalFree(IntPtr hMem);
    }
}
