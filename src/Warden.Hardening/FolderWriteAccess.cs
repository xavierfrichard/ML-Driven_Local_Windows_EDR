using System.Security.AccessControl;
using System.Security.Principal;

namespace Warden.Hardening;

/// <summary>
/// Decides whether a folder is safe to put behind a "Folder → Allow" rule: nobody but SYSTEM,
/// Administrators or TrustedInstaller may be able to put code into it, replace what is there, or move it
/// aside and recreate it. Otherwise a standard user could drop a binary into the folder and have it
/// auto-allowed (and permanently hash-allowed in WDAC) on its first launch.
/// </summary>
/// <remarks>
/// <para>Three things are checked:</para>
/// <list type="bullet">
/// <item>the folder itself, and every file and subfolder under it: no untrusted owner and no untrusted
/// allow ACE with a right that writes, deletes, or rewrites permissions;</item>
/// <item>every ancestor up to the volume root: no untrusted owner and no untrusted right that would let
/// someone delete or rename the folder (or an ancestor) and recreate it with their own content;</item>
/// <item>the walk is capped: a tree too large to verify is reported as not verifiable, never as safe.</item>
/// </list>
/// <para>Deny ACEs are ignored and inherit-only ACEs are skipped (they do not apply to the object itself;
/// they reach its children, which are checked on their own). Both choices can only produce a refusal, never
/// a false "safe".</para>
/// </remarks>
public static class FolderWriteAccess
{
    // Generic rights as they can appear in a stored ACE.
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    /// <summary>Rights on the folder or anything inside it that let the holder change what code is there.</summary>
    private const int ContentWriteMask =
        (int)(FileSystemRights.WriteData            // create files / write file data
            | FileSystemRights.AppendData           // create subfolders / append
            | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.Delete
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership)
        | GenericAll | GenericWrite;

    /// <summary>Rights on an ancestor that let the holder move the folder (or the ancestor) aside and recreate it.</summary>
    private const int AncestorReplaceMask =
        (int)(FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.Delete
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership)
        | GenericAll;

    /// <summary>Default cap on the number of files and folders inspected under the folder.</summary>
    public const int DefaultMaxEntries = 5000;

    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>Which rights a security descriptor is checked for.</summary>
    public enum Scope
    {
        /// <summary>The folder itself or an object inside it.</summary>
        Content,

        /// <summary>A parent folder of the rule's folder.</summary>
        Ancestor,
    }

    /// <summary>
    /// Checks a folder for a Folder → Allow rule. Returns null when only privileged accounts can change its
    /// contents; otherwise a short, human-readable reason (naming the first offending path and principal).
    /// </summary>
    /// <param name="folder">A canonical, existing local folder path.</param>
    /// <param name="maxEntries">Cap on files + subfolders inspected; exceeding it is a refusal.</param>
    public static string? FindProblem(string folder, int maxEntries = DefaultMaxEntries)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);

        var root = new DirectoryInfo(folder);
        if (!root.Exists)
        {
            return "The folder does not exist, so its permissions cannot be checked.";
        }

        // Ancestors: could someone move the folder (or a parent) aside and put their own in its place?
        for (DirectoryInfo? parent = root.Parent; parent is not null; parent = parent.Parent)
        {
            if (Describe(parent.FullName, Read(parent), Scope.Ancestor) is { } problem)
            {
                return problem;
            }
        }

        // The folder itself, then everything under it.
        if ((root.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return $"{root.FullName} is a symbolic link or junction.";
        }
        if (Describe(root.FullName, Read(root), Scope.Content) is { } rootProblem)
        {
            return rootProblem;
        }

        int seen = 0;
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = 0,            // include hidden/system entries
            IgnoreInaccessible = false,      // an unreadable entry is a refusal, not a skip
            ReturnSpecialDirectories = false,
        };

        try
        {
            foreach (FileSystemInfo entry in root.EnumerateFileSystemInfos("*", options))
            {
                if (++seen > maxEntries)
                {
                    return $"The folder holds more than {maxEntries} files and folders; too many to verify.";
                }
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return $"{entry.FullName} is a symbolic link or junction.";
                }
                if (Describe(entry.FullName, Read(entry), Scope.Content) is { } problem)
                {
                    return problem;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "The folder could not be fully inspected (" + ex.GetType().Name + ").";
        }

        return null;
    }

    /// <summary>
    /// Pure check of one security descriptor (owner + DACL, as SDDL). Returns null when only trusted
    /// principals hold the relevant rights, otherwise a reason. Exposed for tests.
    /// </summary>
    public static string? Describe(string path, string? sddl, Scope scope)
    {
        if (string.IsNullOrEmpty(sddl))
        {
            return $"The permissions of {path} could not be read.";
        }

        RawSecurityDescriptor sd;
        try
        {
            sd = new RawSecurityDescriptor(sddl);
        }
        catch (ArgumentException)
        {
            return $"The permissions of {path} could not be parsed.";
        }

        // The owner can always rewrite the DACL, so an untrusted owner is as good as write access.
        if (sd.Owner is null)
        {
            return $"{path} has no owner recorded.";
        }
        if (!IsTrusted(sd.Owner))
        {
            return $"{path} is owned by {Name(sd.Owner)}, which can change its permissions.";
        }

        if (sd.DiscretionaryAcl is null)
        {
            // A NULL DACL grants everyone full access.
            return $"{path} has no access list (everyone has full access).";
        }

        int mask = scope == Scope.Ancestor ? AncestorReplaceMask : ContentWriteMask;
        foreach (GenericAce ace in sd.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce known
                || known.AceQualifier != AceQualifier.AccessAllowed
                || (ace.AceFlags & AceFlags.InheritOnly) != 0
                || (known.AccessMask & mask) == 0
                || IsTrusted(known.SecurityIdentifier)
                || IsCreatorPlaceholder(known.SecurityIdentifier))
            {
                continue;
            }

            return scope == Scope.Ancestor
                ? $"{Name(known.SecurityIdentifier)} can move or replace {path}, a parent of the folder."
                : $"{Name(known.SecurityIdentifier)} can write to {path}.";
        }

        return null;
    }

    private static string? Read(FileSystemInfo info)
    {
        try
        {
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
            FileSystemSecurity security = info is DirectoryInfo d
                ? d.GetAccessControl(sections)
                : ((FileInfo)info).GetAccessControl(sections);
            return security.GetSecurityDescriptorSddlForm(sections);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or PlatformNotSupportedException)
        {
            return null;
        }
    }

    private static bool IsTrusted(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
        || sid.Equals(TrustedInstaller);

    /// <summary>CREATOR OWNER / CREATOR GROUP only matter when inherited, where they become a real SID.</summary>
    private static bool IsCreatorPlaceholder(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid) || sid.IsWellKnown(WellKnownSidType.CreatorGroupSid);

    private static string Name(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
        {
            return sid.Value;
        }
    }
}
