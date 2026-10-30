using System.Security.Principal;

namespace Warden.Hardening;

/// <summary>
/// Who may own, and hold rights in, the agent's data directory tree. Production uses
/// <see cref="Default"/>: owner Administrators; trusted SYSTEM, Administrators and TrustedInstaller; the
/// directory DACL from <see cref="HardeningSddl.DataDirectoryDacl"/>. Tests pass their own policy so the
/// recursion and reparse-point logic can run on a temp directory without elevation.
/// </summary>
public sealed class DataDirectoryPolicy
{
    /// <summary>NT SERVICE\TrustedInstaller.</summary>
    public static readonly SecurityIdentifier TrustedInstallerSid =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>The production policy.</summary>
    public static DataDirectoryPolicy Default { get; } = new(
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            TrustedInstallerSid,
        },
        HardeningSddl.DataDirectoryDacl);

    private readonly HashSet<SecurityIdentifier> _trusted;

    public DataDirectoryPolicy(SecurityIdentifier owner, IEnumerable<SecurityIdentifier> trusted, string directoryDaclSddl)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(trusted);
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryDaclSddl);
        Owner = owner;
        _trusted = new HashSet<SecurityIdentifier>(trusted);
        _trusted.Add(owner);
        DirectoryDaclSddl = directoryDaclSddl;
    }

    /// <summary>The owner set on any object whose current owner is not trusted.</summary>
    public SecurityIdentifier Owner { get; }

    /// <summary>The protected DACL written on the data directory itself (children inherit it).</summary>
    public string DirectoryDaclSddl { get; }

    /// <summary>True when the SID may own objects or hold allow ACEs in the tree.</summary>
    public bool IsTrusted(SecurityIdentifier sid) => sid is not null && _trusted.Contains(sid);
}
