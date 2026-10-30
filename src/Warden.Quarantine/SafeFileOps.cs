using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Warden.Quarantine;

/// <summary>
/// Handle-based file primitives for moving files as SYSTEM without being redirected by junctions,
/// symbolic links, mount points or hard links. The pattern is: refuse reparse points on every ancestor,
/// open the object itself (never following a final reparse point) with a share mode that denies writers,
/// confirm through the handle where it really lives and what bytes it holds, then rename that same handle.
/// A swap of any path component after the open cannot change which file object is moved.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SafeFileOps
{
    private const uint DELETE = 0x00010000;
    private const uint READ_CONTROL = 0x00020000;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint FILE_READ_DATA = 0x0001;
    private const uint FILE_ADD_FILE = 0x0002;
    private const uint FILE_TRAVERSE = 0x0020;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;

    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;
    private const uint FILE_SHARE_DELETE = 0x4;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;

    private const uint FILE_NAME_NORMALIZED = 0x0;
    private const uint VOLUME_NAME_DOS = 0x0;

    private const int FileRenameInformation = 10;
    private const int FileDispositionInfo = 4; // FILE_INFO_BY_HANDLE_CLASS
    private const uint DACL_SECURITY_INFORMATION = 0x4;

    private static readonly char[] LeafSeparators = { '\\', '/', ':' };

    /// <summary>STATUS_NOT_SAME_DEVICE: a rename cannot cross volumes.</summary>
    internal const int StatusNotSameDevice = unchecked((int)0xC00000D4);

    /// <summary>
    /// Canonicalizes <paramref name="path"/> to a rooted, local, drive-letter path. Returns null for UNC,
    /// device (<c>\\?\</c>, <c>\\.\</c>) or otherwise unusable input.
    /// </summary>
    internal static string? CanonicalLocalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return null;
        }
        try
        {
            if (!Path.IsPathFullyQualified(path))
            {
                return null;
            }
            string full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal) || full.Length < 3 || full[1] != ':')
            {
                return null;
            }
            return ExpandShortNames(full);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    /// <summary>
    /// Expands 8.3 short names (<c>XAVIER~1</c>) so the path can be compared with what
    /// <see cref="FinalPath"/> reports. Only the longest existing prefix is expanded; the rest is kept as
    /// given. This never resolves junctions or links (GetLongPathName only renames components), so it
    /// cannot hide a redirection from the checks that follow.
    /// </summary>
    internal static string ExpandShortNames(string fullPath)
    {
        if (!fullPath.Contains('~', StringComparison.Ordinal))
        {
            return fullPath;
        }

        string existing = fullPath;
        string tail = string.Empty;
        while (!string.IsNullOrEmpty(existing) && !Path.Exists(existing))
        {
            string? parent = Path.GetDirectoryName(existing);
            if (parent is null)
            {
                return fullPath;
            }
            tail = tail.Length == 0 ? Path.GetFileName(existing) : Path.Combine(Path.GetFileName(existing), tail);
            existing = parent;
        }

        var buffer = new char[1024];
        uint n = GetLongPathNameW(existing, buffer, (uint)buffer.Length);
        if (n >= buffer.Length)
        {
            buffer = new char[n + 1];
            n = GetLongPathNameW(existing, buffer, (uint)buffer.Length);
        }
        if (n == 0 || n >= buffer.Length)
        {
            return fullPath;
        }
        string longExisting = new(buffer, 0, (int)n);
        return tail.Length == 0 ? longExisting : Path.Combine(longExisting, tail);
    }

    /// <summary>
    /// Returns the first ancestor directory of <paramref name="canonicalPath"/> (excluding the path itself)
    /// that is a reparse point or cannot be inspected, or null when every ancestor is a plain directory.
    /// </summary>
    internal static string? FindUnsafeAncestor(string canonicalPath)
    {
        string? dir = Path.GetDirectoryName(canonicalPath);
        while (!string.IsNullOrEmpty(dir))
        {
            string? parent = Path.GetDirectoryName(dir);
            if (parent is null)
            {
                break; // drive root ("C:\") — not a reparse point we can act on
            }

            uint attrs = GetFileAttributesW(LongPath(dir));
            if (attrs == INVALID_FILE_ATTRIBUTES
                || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                return dir;
            }
            dir = parent;
        }
        return null;
    }

    /// <summary>
    /// Opens a regular file for a move: DELETE + read, no final reparse-point traversal, and a share mode
    /// that admits readers only (no writer, no deleter/renamer) for as long as the handle is held.
    /// </summary>
    internal static SafeFileHandle OpenFileForMove(string canonicalPath)
    {
        SafeFileHandle h = CreateFileW(
            LongPath(canonicalPath),
            DELETE | FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        if (h.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            h.Dispose();
            throw new IOException($"Could not open {canonicalPath}: {new Win32Exception(err).Message}", HResultFromWin32(err));
        }
        return h;
    }

    /// <summary>Opens a directory (never through a final reparse point) as a rename target root.</summary>
    internal static SafeFileHandle OpenDirectory(string canonicalPath)
    {
        SafeFileHandle h = CreateFileW(
            LongPath(canonicalPath),
            FILE_TRAVERSE | FILE_ADD_FILE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        if (h.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            h.Dispose();
            throw new IOException($"Could not open directory {canonicalPath}: {new Win32Exception(err).Message}", HResultFromWin32(err));
        }
        return h;
    }

    /// <summary>Attributes and hard-link count of the open object.</summary>
    internal static (uint Attributes, uint LinkCount, long Size) Describe(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out BY_HANDLE_FILE_INFORMATION info))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        long size = ((long)info.nFileSizeHigh << 32) | info.nFileSizeLow;
        return (info.dwFileAttributes, info.nNumberOfLinks, size);
    }

    internal static bool IsReparsePoint(uint attributes) => (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

    internal static bool IsDirectory(uint attributes) => (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    /// <summary>
    /// The path the open handle really refers to (junctions, symlinks and mount points resolved), in
    /// drive-letter form without the <c>\\?\</c> prefix; null if it has no drive-letter form.
    /// </summary>
    internal static string? FinalPath(SafeFileHandle handle)
    {
        var buffer = new char[1024];
        while (true)
        {
            uint n = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (n == 0)
            {
                return null;
            }
            if (n < buffer.Length)
            {
                string p = new(buffer, 0, (int)n);
                if (p.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
                {
                    return null;
                }
                if (p.StartsWith(@"\\?\", StringComparison.Ordinal))
                {
                    p = p[4..];
                }
                return p.Length >= 3 && p[1] == ':' ? p : null;
            }
            buffer = new char[n + 1];
        }
    }

    /// <summary>True when the two canonical paths name the same location (case-insensitive, trailing separators ignored).</summary>
    internal static bool SamePath(string a, string b) =>
        string.Equals(
            a.TrimEnd(Path.DirectorySeparatorChar),
            b.TrimEnd(Path.DirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

    /// <summary>True when <paramref name="path"/> equals <paramref name="root"/> or lies beneath it, on a directory boundary.</summary>
    internal static bool IsAtOrUnder(string path, string root)
    {
        string r = root.TrimEnd(Path.DirectorySeparatorChar);
        string p = path.TrimEnd(Path.DirectorySeparatorChar);
        return string.Equals(p, r, StringComparison.OrdinalIgnoreCase)
            || p.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>SHA-256 (uppercase hex) of the bytes behind the handle, read without moving any file pointer.</summary>
    internal static string HashHandle(SafeFileHandle handle, Stream? copyTo = null)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        long offset = 0;
        int read;
        while ((read = RandomAccess.Read(handle, buffer, offset)) > 0)
        {
            sha.AppendData(buffer, 0, read);
            copyTo?.Write(buffer, 0, read);
            offset += read;
        }
        return Convert.ToHexString(sha.GetHashAndReset());
    }

    /// <summary>The DACL of the open object as SDDL, or null if it cannot be read.</summary>
    internal static string? ReadDaclSddl(SafeFileHandle handle)
    {
        GetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, null, 0, out uint needed);
        if (needed == 0)
        {
            return null;
        }
        var sd = new byte[needed];
        if (!GetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd, needed, out _))
        {
            return null;
        }
        return new RawSecurityDescriptor(sd, 0).GetSddlForm(AccessControlSections.Access);
    }

    /// <summary>
    /// Renames the file behind <paramref name="file"/> to <paramref name="leafName"/> inside the directory
    /// behind <paramref name="directory"/>. Both ends are handles, so no path is re-resolved. Never replaces
    /// an existing file. Returns the NTSTATUS (0 = success).
    /// </summary>
    internal static int RenameInto(SafeFileHandle file, SafeFileHandle directory, string leafName)
    {
        if (string.IsNullOrEmpty(leafName) || leafName.IndexOfAny(LeafSeparators) >= 0)
        {
            throw new ArgumentException("A rename target must be a plain file name.", nameof(leafName));
        }

        // FILE_RENAME_INFORMATION: { BOOLEAN ReplaceIfExists (padded to pointer size); HANDLE RootDirectory;
        //                            ULONG FileNameLength; WCHAR FileName[] }
        int nameOffset = IntPtr.Size * 2 + 4;
        int nameBytes = leafName.Length * 2;
        int size = nameOffset + nameBytes + 2;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        bool addedRef = false;
        try
        {
            directory.DangerousAddRef(ref addedRef);
            for (int i = 0; i < size; i++)
            {
                Marshal.WriteByte(buffer, i, 0);
            }
            Marshal.WriteByte(buffer, 0, 0); // ReplaceIfExists = FALSE
            Marshal.WriteIntPtr(buffer, IntPtr.Size, directory.DangerousGetHandle());
            Marshal.WriteInt32(buffer, IntPtr.Size * 2, nameBytes);
            Marshal.Copy(leafName.ToCharArray(), 0, buffer + nameOffset, leafName.Length);

            return NtSetInformationFile(file, out _, buffer, (uint)size, FileRenameInformation);
        }
        finally
        {
            if (addedRef)
            {
                directory.DangerousRelease();
            }
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Marks the file behind the handle for deletion when the handle closes.</summary>
    internal static void DeleteOnClose(SafeFileHandle handle)
    {
        byte delete = 1;
        if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref delete, 1))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    private static string LongPath(string canonical) =>
        canonical.StartsWith(@"\\", StringComparison.Ordinal) ? canonical : @"\\?\" + canonical;

    private static int HResultFromWin32(int err) => err <= 0 ? err : unchecked((int)(0x80070000 | (uint)err));

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetFileAttributesW(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetLongPathNameW(string lpszShortPath, [Out] char[] lpszLongPath, uint cchBuffer);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle hFile, [Out] char[] lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle hFile, int fileInformationClass, ref byte lpFileInformation, uint dwBufferSize);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetKernelObjectSecurity(
        SafeFileHandle handle, uint requestedInformation, byte[]? pSecurityDescriptor, uint nLength, out uint lpnLengthNeeded);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int NtSetInformationFile(
        SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock, IntPtr fileInformation, uint length, int fileInformationClass);
}
