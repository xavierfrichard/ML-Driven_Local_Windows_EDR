using System.ComponentModel;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace Warden.Hardening;

/// <summary>
/// Outcome of hardening or verifying the data directory tree. <see cref="Success"/> is true only when no
/// redirect (junction, symlink, mount point or hard link) was found and nothing failed.
/// </summary>
public sealed record DataDirectoryReport(IReadOnlyList<string> Redirects, IReadOnlyList<string> Problems)
{
    public bool Success => Redirects.Count == 0 && Problems.Count == 0;

    /// <summary>One-line summary for logs and tamper events.</summary>
    public string Summary()
    {
        var parts = new List<string>();
        if (Redirects.Count > 0)
        {
            parts.Add("redirects: " + string.Join("; ", Redirects.Take(10)) + (Redirects.Count > 10 ? $" (+{Redirects.Count - 10} more)" : ""));
        }
        if (Problems.Count > 0)
        {
            parts.Add("problems: " + string.Join("; ", Problems.Take(10)) + (Problems.Count > 10 ? $" (+{Problems.Count - 10} more)" : ""));
        }
        return parts.Count == 0 ? "ok" : string.Join(" | ", parts);
    }
}

/// <summary>
/// Locks the agent's data directory tree to SYSTEM + Administrators. Writes only the owner and DACL
/// sections: the single-argument overloads default to <c>All</c>, which tries to write the SACL and fails
/// without <c>SeSecurityPrivilege</c>. No method throws.
/// </summary>
/// <remarks>
/// <para>Standard users can create folders under <c>C:\ProgramData</c>, so the data directory may have been
/// created, and still be owned, by someone else before install. The owner can always rewrite the DACL.
/// <see cref="HardenDataDirectory"/> therefore resets the owner as well as the DACL, on the directory and on
/// everything inside it.</para>
/// <para>Junctions, symbolic links, mount points and hard links inside the tree would redirect SYSTEM's
/// owner and ACL writes (and later file writes) to a target someone else chose. The tree is scanned before
/// anything is changed, and if any of them is found nothing is changed and the report fails.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DataDirectoryHardener
{
    /// <summary>Default cap on files + folders visited; a larger tree is reported as a problem, never as safe.</summary>
    public const int DefaultMaxEntries = 200_000;

    private static readonly string[] HardeningPrivileges =
    {
        "SeTakeOwnershipPrivilege", // take ownership of objects whose DACL shuts SYSTEM out
        "SeRestorePrivilege",       // set Administrators as owner, write any DACL
        "SeBackupPrivilege",        // read and list objects whose DACL shuts SYSTEM out
    };

    private readonly ILogger<DataDirectoryHardener> _logger;
    private readonly DataDirectoryPolicy _policy;
    private readonly int _maxEntries;

    public DataDirectoryHardener(ILogger<DataDirectoryHardener> logger)
        : this(logger, DataDirectoryPolicy.Default)
    {
    }

    public DataDirectoryHardener(ILogger<DataDirectoryHardener> logger, DataDirectoryPolicy policy, int maxEntries = DefaultMaxEntries)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(policy);
        _logger = logger;
        _policy = policy;
        _maxEntries = maxEntries;
    }

    // ---- whole-tree hardening (H4) ---------------------------------------------------------------------

    /// <summary>
    /// Creates (if needed) and locks the data directory tree:
    /// <list type="number">
    /// <item>refuses, changing nothing, if the directory, an ancestor or anything inside it is a junction,
    /// symlink, mount point or hard link;</item>
    /// <item>sets the owner to Administrators wherever the owner is not trusted;</item>
    /// <item>writes the protected SYSTEM + Administrators DACL on the directory;</item>
    /// <item>removes every allow entry for an untrusted principal from everything inside it;</item>
    /// <item>verifies the result.</item>
    /// </list>
    /// </summary>
    public DataDirectoryReport HardenDataDirectory(string path)
    {
        var redirects = new List<string>();
        var problems = new List<string>();
        try
        {
            var root = new DirectoryInfo(Path.GetFullPath(path));

            ScanForRedirects(root, redirects, problems);
            if (redirects.Count > 0 || problems.Count > 0)
            {
                return new DataDirectoryReport(redirects, problems);
            }

            using (NativeMethods.PrivilegeScope.Enable(HardeningPrivileges))
            {
                root.Create();
                root.Refresh();
                if (IsReparsePoint(root))
                {
                    // Swapped in after the scan.
                    redirects.Add(root.FullName);
                    return new DataDirectoryReport(redirects, problems);
                }

                if (!EnsureTrustedOwner(root, problems))
                {
                    return new DataDirectoryReport(redirects, problems);
                }

                try
                {
                    var security = new DirectorySecurity();
                    security.SetSecurityDescriptorSddlForm(_policy.DirectoryDaclSddl, AccessControlSections.Access);
                    root.SetAccessControl(security);
                }
                catch (Exception ex) when (IsAclFailure(ex))
                {
                    problems.Add($"Could not set the access list of {root.FullName} ({ex.GetType().Name}).");
                    return new DataDirectoryReport(redirects, problems);
                }

                Walk(root, entry =>
                {
                    if (IsRedirect(entry, problems))
                    {
                        redirects.Add(entry.FullName);
                        return false;
                    }
                    ResetEntry(entry, problems);
                    return true;
                }, problems);
            }

            if (redirects.Count > 0 || problems.Count > 0)
            {
                return new DataDirectoryReport(redirects, problems);
            }
            return VerifyDataDirectory(root.FullName, requireTrustedOwnership: true);
        }
        catch (Exception ex) when (IsAclFailure(ex))
        {
            problems.Add($"Hardening {path} failed ({ex.GetType().Name}: {ex.Message}).");
            return new DataDirectoryReport(redirects, problems);
        }
    }

    /// <summary>
    /// Read-only check, run before the service uses the data directory. Always fails on a junction,
    /// symlink, mount point or hard link in the tree or on an ancestor. With
    /// <paramref name="requireTrustedOwnership"/> it also fails when the directory or anything inside it has
    /// an untrusted owner, no DACL, or an allow entry for an untrusted principal.
    /// A directory that does not exist yet passes (the service creates it).
    /// </summary>
    public DataDirectoryReport VerifyDataDirectory(string path, bool requireTrustedOwnership)
    {
        var redirects = new List<string>();
        var problems = new List<string>();
        try
        {
            var root = new DirectoryInfo(Path.GetFullPath(path));
            ScanForRedirects(root, redirects, problems);
            if (!requireTrustedOwnership || redirects.Count > 0 || !root.Exists)
            {
                return new DataDirectoryReport(redirects, problems);
            }

            CheckEntry(root, problems);
            Walk(root, entry =>
            {
                CheckEntry(entry, problems);
                return true;
            }, problems);
        }
        catch (Exception ex) when (IsAclFailure(ex))
        {
            problems.Add($"Checking {path} failed ({ex.GetType().Name}: {ex.Message}).");
        }
        return new DataDirectoryReport(redirects, problems);
    }

    // ---- single-object helpers (kept for callers and tests) -------------------------------------------

    /// <summary>
    /// Writes the protected SYSTEM + Administrators DACL on one directory (not its owner, not its children).
    /// Refuses a reparse point. Returns true on success. Prefer <see cref="HardenDataDirectory"/>.
    /// </summary>
    public bool HardenDirectory(string path)
    {
        try
        {
            var dir = new DirectoryInfo(path);
            if (dir.Exists && IsReparsePoint(dir))
            {
                _logger.LogError("Refusing to lock {Path}: it is a junction or symbolic link.", path);
                return false;
            }
            dir.Create();
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(_policy.DirectoryDaclSddl, AccessControlSections.Access);
            dir.SetAccessControl(security);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not lock down data directory {Path} (needs SYSTEM/Admin).", path);
            return false;
        }
    }

    /// <summary>
    /// Locks a file (the database) to SYSTEM + Administrators. Refuses a symlink or a file with more than
    /// one hard link (the ACL write would land on another file). Returns true on success.
    /// </summary>
    public bool HardenFile(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return false;
            }
            if (IsReparsePoint(file) || NativeMethods.HardLinkCount(file.FullName) > 1)
            {
                _logger.LogError("Refusing to lock {Path}: it is a symbolic link or has several hard links.", path);
                return false;
            }
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(HardeningSddl.DataFileDacl, AccessControlSections.Access);
            file.SetAccessControl(security);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not lock down file {Path} (needs SYSTEM/Admin).", path);
            return false;
        }
    }

    /// <summary>
    /// Returns the SIDs, other than SYSTEM, Administrators and TrustedInstaller, that hold a
    /// <b>write</b>-class allow ACE that applies to the directory itself. Any SID counts, not only
    /// well-known groups. Empty means "only privileged accounts can write". Null when the DACL could not be
    /// read. The owner is not checked here; <see cref="InstallSelfCheck"/> does that.
    /// </summary>
    public static IReadOnlyList<string>? LowPrivilegeWriters(string path)
    {
        try
        {
            const FileSystemRights writeClass =
                FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.CreateFiles
                | FileSystemRights.CreateDirectories | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
                | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.ChangePermissions
                | FileSystemRights.TakeOwnership | FileSystemRights.FullControl | FileSystemRights.Write | FileSystemRights.Modify;
            const int genericWriteOrAll = 0x40000000 | 0x10000000;

            var offenders = new List<string>();
            AuthorizationRuleCollection rules = new DirectoryInfo(path)
                .GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow
                    || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0
                    || ((int)rule.FileSystemRights & ((int)writeClass | genericWriteOrAll)) == 0)
                {
                    continue;
                }

                var sid = (SecurityIdentifier)rule.IdentityReference;
                if (!DataDirectoryPolicy.Default.IsTrusted(sid) && !IsCreatorPlaceholder(sid))
                {
                    offenders.Add(sid.Value);
                }
            }
            return offenders;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or IdentityNotMappedException)
        {
            return null;
        }
    }

    /// <summary>Read the current DACL of a directory as SDDL (for verification / tests), or null.</summary>
    public static string? ReadDirectoryDacl(string path)
    {
        try
        {
            return new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>True if the directory's DACL is protected (does not inherit from its parent).</summary>
    public static bool IsProtected(string path)
    {
        try
        {
            return new DirectoryInfo(path).GetAccessControl().AreAccessRulesProtected;
        }
        catch
        {
            return false;
        }
    }

    // ---- internals -------------------------------------------------------------------------------------

    /// <summary>Records every redirect on the ancestors, the root and (if it exists) the whole tree.</summary>
    private void ScanForRedirects(DirectoryInfo root, List<string> redirects, List<string> problems)
    {
        for (DirectoryInfo? d = root.Parent; d is not null; d = d.Parent)
        {
            if (d.Exists && IsReparsePoint(d))
            {
                redirects.Add(d.FullName);
            }
        }

        if (!root.Exists)
        {
            if (File.Exists(root.FullName))
            {
                problems.Add($"{root.FullName} is a file, not a directory.");
            }
            return;
        }
        if (IsReparsePoint(root))
        {
            redirects.Add(root.FullName);
            return;
        }

        Walk(root, entry =>
        {
            if (IsRedirect(entry, problems))
            {
                redirects.Add(entry.FullName);
                return false;
            }
            return true;
        }, problems);
    }

    /// <summary>
    /// Visits every entry under <paramref name="root"/> top-down, one directory listing at a time, never
    /// descending into a reparse point. <paramref name="visit"/> runs before a directory is listed (so its
    /// ACL can be fixed first) and returns false to skip descending into it.
    /// </summary>
    private void Walk(DirectoryInfo root, Func<FileSystemInfo, bool> visit, List<string> problems)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            AttributesToSkip = 0,         // include hidden and system entries
            IgnoreInaccessible = false,   // an unreadable entry is a problem, not a skip
            ReturnSpecialDirectories = false,
        };

        int seen = 0;
        var pending = new Stack<DirectoryInfo>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            DirectoryInfo dir = pending.Pop();
            try
            {
                foreach (FileSystemInfo entry in dir.EnumerateFileSystemInfos("*", options))
                {
                    if (++seen > _maxEntries)
                    {
                        problems.Add($"{root.FullName} holds more than {_maxEntries} files and folders; too many to verify.");
                        return;
                    }
                    bool descend = visit(entry);
                    if (descend && entry is DirectoryInfo sub && !IsReparsePoint(sub))
                    {
                        pending.Push(sub);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                problems.Add($"{dir.FullName} could not be listed ({ex.GetType().Name}).");
            }
        }
    }

    private static bool IsReparsePoint(FileSystemInfo info) => (info.Attributes & FileAttributes.ReparsePoint) != 0;

    /// <summary>A reparse point, or a file with more than one hard link.</summary>
    private static bool IsRedirect(FileSystemInfo entry, List<string> problems)
    {
        if (IsReparsePoint(entry))
        {
            return true;
        }
        if (entry is FileInfo)
        {
            try
            {
                return NativeMethods.HardLinkCount(entry.FullName) > 1;
            }
            catch (Win32Exception ex)
            {
                problems.Add($"The link count of {entry.FullName} could not be read (error {ex.NativeErrorCode}).");
            }
        }
        return false;
    }

    /// <summary>Sets the policy owner when the current one is untrusted or unreadable. False on failure.</summary>
    private bool EnsureTrustedOwner(FileSystemInfo entry, List<string> problems)
    {
        RawSecurityDescriptor? sd = TryRead(entry);
        if (sd?.Owner is not null && _policy.IsTrusted(sd.Owner))
        {
            return true;
        }

        try
        {
            FileSystemSecurity security = entry is DirectoryInfo ? new DirectorySecurity() : new FileSecurity();
            security.SetSecurityDescriptorSddlForm("O:" + _policy.Owner.Value, AccessControlSections.Owner);
            SetAccessControl(entry, security);
            return true;
        }
        catch (Exception ex) when (IsAclFailure(ex))
        {
            string current = sd?.Owner?.Value ?? "unreadable";
            problems.Add($"Could not take ownership of {entry.FullName} (owner {current}; {ex.GetType().Name}).");
            return false;
        }
    }

    /// <summary>Trusted owner, then drop every allow entry for an untrusted principal.</summary>
    private void ResetEntry(FileSystemInfo entry, List<string> problems)
    {
        if (!EnsureTrustedOwner(entry, problems))
        {
            return;
        }

        RawSecurityDescriptor? sd = TryRead(entry);
        if (sd is null)
        {
            problems.Add($"The permissions of {entry.FullName} could not be read.");
            return;
        }

        RawAcl filtered;
        bool changed;
        if (sd.DiscretionaryAcl is null)
        {
            // NULL DACL = everyone has full access. Replace it with an empty, inheriting one.
            filtered = new RawAcl(GenericAcl.AclRevision, 0);
            changed = true;
        }
        else
        {
            filtered = new RawAcl(sd.DiscretionaryAcl.Revision, sd.DiscretionaryAcl.Count);
            changed = false;
            foreach (GenericAce ace in sd.DiscretionaryAcl)
            {
                if (IsUntrustedAllow(ace))
                {
                    changed = true;
                    continue;
                }
                filtered.InsertAce(filtered.Count, ace);
            }
        }
        if (!changed)
        {
            return;
        }

        try
        {
            ControlFlags flags = (sd.ControlFlags & (ControlFlags.DiscretionaryAclProtected | ControlFlags.DiscretionaryAclAutoInherited))
                                 | ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative;
            string dacl = new RawSecurityDescriptor(flags, null, null, null, filtered).GetSddlForm(AccessControlSections.Access);
            FileSystemSecurity security = entry is DirectoryInfo ? new DirectorySecurity() : new FileSecurity();
            security.SetSecurityDescriptorSddlForm(dacl, AccessControlSections.Access);
            SetAccessControl(entry, security);
        }
        catch (Exception ex) when (IsAclFailure(ex))
        {
            problems.Add($"Could not reset the access list of {entry.FullName} ({ex.GetType().Name}).");
        }
    }

    /// <summary>Read-only: untrusted owner, NULL DACL, or an allow entry for an untrusted principal.</summary>
    private void CheckEntry(FileSystemInfo entry, List<string> problems)
    {
        RawSecurityDescriptor? sd = TryRead(entry);
        if (sd is null)
        {
            problems.Add($"The permissions of {entry.FullName} could not be read.");
            return;
        }
        if (sd.Owner is null || !_policy.IsTrusted(sd.Owner))
        {
            problems.Add($"{entry.FullName} is owned by {sd.Owner?.Value ?? "nobody"}.");
        }
        if (sd.DiscretionaryAcl is null)
        {
            problems.Add($"{entry.FullName} has no access list (everyone has full access).");
            return;
        }
        foreach (GenericAce ace in sd.DiscretionaryAcl)
        {
            if (IsUntrustedAllow(ace))
            {
                string who = ace is QualifiedAce q ? q.SecurityIdentifier.Value : "an unrecognised entry";
                problems.Add($"{entry.FullName} grants access to {who}.");
            }
        }
    }

    /// <summary>
    /// An allow entry (inherit-only included) for anyone outside the policy, or an entry type this code
    /// does not understand. CREATOR OWNER / CREATOR GROUP placeholders are kept: only trusted principals
    /// can create objects here, so they resolve to a trusted SID.
    /// </summary>
    private bool IsUntrustedAllow(GenericAce ace)
    {
        if (ace is not QualifiedAce qualified)
        {
            return true;
        }
        return qualified.AceQualifier == AceQualifier.AccessAllowed
               && !_policy.IsTrusted(qualified.SecurityIdentifier)
               && !IsCreatorPlaceholder(qualified.SecurityIdentifier);
    }

    private static bool IsCreatorPlaceholder(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid) || sid.IsWellKnown(WellKnownSidType.CreatorGroupSid);

    private static RawSecurityDescriptor? TryRead(FileSystemInfo entry)
    {
        try
        {
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
            FileSystemSecurity security = entry is DirectoryInfo d
                ? d.GetAccessControl(sections)
                : ((FileInfo)entry).GetAccessControl(sections);
            return new RawSecurityDescriptor(security.GetSecurityDescriptorSddlForm(sections));
        }
        catch (Exception ex) when (IsAclFailure(ex))
        {
            return null;
        }
    }

    private static void SetAccessControl(FileSystemInfo entry, FileSystemSecurity security)
    {
        if (entry is DirectoryInfo d)
        {
            d.SetAccessControl((DirectorySecurity)security);
        }
        else
        {
            ((FileInfo)entry).SetAccessControl((FileSecurity)security);
        }
    }

    private static bool IsAclFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException
            or NotSupportedException or System.Security.SecurityException or Win32Exception;
}
