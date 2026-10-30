using System.Security.AccessControl;

namespace Warden.Secrets;

/// <summary>Where an object sits relative to the file being checked.</summary>
public enum ChainRole
{
    /// <summary>The file itself.</summary>
    File,

    /// <summary>The folder that directly holds the file (a writer here can replace the file or plant DLLs beside it).</summary>
    Container,

    /// <summary>A folder further up (a writer here can move the container aside and recreate it).</summary>
    Ancestor,
}

/// <summary>
/// Walks a file and every folder above it, reading each one's owner and access list, and asks a policy
/// delegate whether that object is safe. Used before the SYSTEM service runs or trusts a file that sits
/// outside its own install folder: the <c>claude</c> CLI, the ML model and the secrets store.
/// </summary>
/// <remarks>
/// The walk itself refuses links and junctions anywhere in the chain, a missing file, and a security
/// descriptor that cannot be read. The policy (which accounts count as trusted, which rights matter) is the
/// caller's: the service passes <c>Warden.Hardening.FolderWriteAccess.Describe</c>.
/// </remarks>
public static class TrustedFileChain
{
    /// <summary>Owner + DACL of one path as SDDL, or null when it cannot be read.</summary>
    public delegate string? SddlReader(string path, bool isDirectory);

    /// <summary>
    /// Returns null when every object from <paramref name="filePath"/> up to the volume root (or up to and
    /// including <paramref name="stopAt"/>) passes <paramref name="describe"/>; otherwise the first reason.
    /// </summary>
    /// <param name="filePath">A fully-qualified local file path.</param>
    /// <param name="describe">Policy: given (path, SDDL or null, role), null when safe, else a reason.</param>
    /// <param name="stopAt">Optional top folder of the walk; the file must be under it.</param>
    /// <param name="readSddl">SDDL reader (tests inject one); defaults to the file system.</param>
    public static string? FindProblem(
        string filePath,
        Func<string, string?, ChainRole, string?> describe,
        string? stopAt = null,
        SddlReader? readSddl = null)
    {
        ArgumentNullException.ThrowIfNull(describe);
        if (!OperatingSystem.IsWindows())
        {
            return "File ownership can only be verified on Windows.";
        }
        if (string.IsNullOrWhiteSpace(filePath) || !Path.IsPathFullyQualified(filePath)
            || filePath.StartsWith(@"\\", StringComparison.Ordinal) || filePath.StartsWith("//", StringComparison.Ordinal))
        {
            return $"'{filePath}' is not a fully-qualified local path.";
        }

        readSddl ??= ReadSddl;
        string full = Path.GetFullPath(filePath);
        string? top = stopAt is null ? null : Path.TrimEndingDirectorySeparator(Path.GetFullPath(stopAt));
        if (top is not null && !full.StartsWith(top + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            return $"{full} is not under {top}.";
        }

        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"{full} does not exist or cannot be inspected ({ex.GetType().Name}).";
        }
        if ((attributes & FileAttributes.Directory) != 0)
        {
            return $"{full} is a folder, not a file.";
        }

        string current = full;
        ChainRole role = ChainRole.File;
        while (true)
        {
            bool isDirectory = role != ChainRole.File;
            if (role != ChainRole.File)
            {
                try
                {
                    attributes = File.GetAttributes(current);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    return $"{current} cannot be inspected ({ex.GetType().Name}).";
                }
            }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                return $"{current} is a symbolic link or junction.";
            }

            if (describe(current, readSddl(current, isDirectory), role) is { } problem)
            {
                return problem;
            }

            if (top is not null && string.Equals(Path.TrimEndingDirectorySeparator(current), top, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            string? parent = Path.GetDirectoryName(current);
            if (parent is null)
            {
                return null; // reached the volume root
            }
            current = parent;
            role = role == ChainRole.File ? ChainRole.Container : ChainRole.Ancestor;
        }
    }

    /// <summary>Reads owner + DACL from the file system as SDDL; null when unreadable.</summary>
    public static string? ReadSddl(string path, bool isDirectory)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }
        try
        {
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
            FileSystemSecurity security = isDirectory
                ? new DirectoryInfo(path).GetAccessControl(sections)
                : new FileInfo(path).GetAccessControl(sections);
            return security.GetSecurityDescriptorSddlForm(sections);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or PlatformNotSupportedException or ArgumentException)
        {
            return null;
        }
    }
}
