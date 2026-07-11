using System.Runtime.Versioning;
using System.Security.AccessControl;
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
