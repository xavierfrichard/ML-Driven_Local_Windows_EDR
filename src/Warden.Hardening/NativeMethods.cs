using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Warden.Hardening;

/// <summary>Win32 calls used by the data-directory hardener.</summary>
[SupportedOSPlatform("windows")]
internal static class NativeMethods
{
    private const int SecurityImpersonation = 2;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const uint FileReadAttributes = 0x0080;
    private const uint FileShareAll = 0x1 | 0x2 | 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateSelf(int impersonationLevel);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(IntPtr thread, uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool openAsSelf, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TokenPrivileges newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    /// <summary>
    /// Number of hard links to a file, read without following a reparse point. Throws
    /// <see cref="Win32Exception"/> when the file cannot be opened.
    /// </summary>
    public static uint HardLinkCount(string path)
    {
        using SafeFileHandle handle = CreateFile(
            path, FileReadAttributes, FileShareAll, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation info))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return info.NumberOfLinks;
    }

    /// <summary>
    /// Enables privileges on a private copy of the process token for the calling thread only
    /// (<c>ImpersonateSelf</c>); disposing reverts the thread. Privileges the account does not hold are
    /// simply not enabled, so an unprivileged caller gets a no-op scope. Use only around synchronous code.
    /// </summary>
    public sealed class PrivilegeScope : IDisposable
    {
        private bool _impersonating;

        private PrivilegeScope(bool impersonating) => _impersonating = impersonating;

        public static PrivilegeScope Enable(params string[] privileges)
        {
            if (!ImpersonateSelf(SecurityImpersonation))
            {
                return new PrivilegeScope(false);
            }

            var scope = new PrivilegeScope(true);
            try
            {
                if (OpenThreadToken(GetCurrentThread(), TokenAdjustPrivileges | TokenQuery, openAsSelf: true, out SafeAccessTokenHandle token))
                {
                    using (token)
                    {
                        foreach (string name in privileges)
                        {
                            if (!LookupPrivilegeValue(null, name, out Luid luid))
                            {
                                continue;
                            }
                            var tp = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
                            // Returns true with ERROR_NOT_ALL_ASSIGNED when the account lacks the privilege: fine.
                            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                        }
                    }
                }
            }
            catch
            {
                scope.Dispose();
                throw;
            }
            return scope;
        }

        public void Dispose()
        {
            if (_impersonating)
            {
                _impersonating = false;
                if (!RevertToSelf())
                {
                    // A thread that cannot drop its impersonation token must not keep running with extra
                    // privileges enabled.
                    Environment.FailFast("Warden: RevertToSelf failed after enabling hardening privileges.");
                }
            }
        }
    }
}
