using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace Warden.Hardening;

/// <summary>
/// Applies the restrictive DACL (SYSTEM + Administrators only, no inheritance) to the agent's data
/// directory and database file, so a standard user cannot read the database or tamper with on-disk
/// state. Mirrors the quarantine store's ACL approach: set only the DACL section
/// (<see cref="AccessControlSections.Access"/>) — the single-arg overload defaults to
/// <c>All</c>, which tries to write the SACL and fails without <c>SeSecurityPrivilege</c>. Every method
/// is best-effort and never throws; the applier is exercised in tests against a temp directory.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DataDirectoryHardener
{
    private readonly ILogger<DataDirectoryHardener> _logger;

    public DataDirectoryHardener(ILogger<DataDirectoryHardener> logger) => _logger = logger;

    /// <summary>Lock a directory to SYSTEM + Administrators. Returns true on success.</summary>
    public bool HardenDirectory(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(HardeningSddl.DataDirectoryDacl, AccessControlSections.Access);
            new DirectoryInfo(path).SetAccessControl(security);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not lock down data directory {Path} (needs SYSTEM/Admin).", path);
            return false;
        }
    }

    /// <summary>Lock a file (the database) to SYSTEM + Administrators. Returns true on success.</summary>
    public bool HardenFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }
            var security = new FileSecurity();
            security.SetSecurityDescriptorSddlForm(HardeningSddl.DataFileDacl, AccessControlSections.Access);
            new FileInfo(path).SetAccessControl(security);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not lock down file {Path} (needs SYSTEM/Admin).", path);
            return false;
        }
    }

    /// <summary>
    /// Returns the well-known low-privilege principals (Everyone, Authenticated Users, Users, Interactive,
    /// the current non-admin user) that hold a <b>write</b>-class allow ACE on the directory — i.e. who could
    /// swap the binaries a LocalSystem service loads from it. Empty means "only privileged accounts can
    /// write". Null when the DACL could not be read.
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

            var lowPrivilege = new[]
            {
                WellKnownSidType.WorldSid,
                WellKnownSidType.AuthenticatedUserSid,
                WellKnownSidType.BuiltinUsersSid,
                WellKnownSidType.InteractiveSid,
                WellKnownSidType.BuiltinGuestsSid,
                WellKnownSidType.AnonymousSid,
            };

            var offenders = new List<string>();
            AuthorizationRuleCollection rules = new DirectoryInfo(path)
                .GetAccessControl(AccessControlSections.Access)
                .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(System.Security.Principal.SecurityIdentifier));

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & writeClass) == 0)
                {
                    continue;
                }

                var sid = (System.Security.Principal.SecurityIdentifier)rule.IdentityReference;
                if (lowPrivilege.Any(sid.IsWellKnown))
                {
                    offenders.Add(sid.Value);
                }
            }
            return offenders;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                   or System.Security.Principal.IdentityNotMappedException)
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
}
