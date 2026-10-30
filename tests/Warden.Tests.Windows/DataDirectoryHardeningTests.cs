using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Hardening;

namespace Warden.Tests.Windows;

/// <summary>
/// H4: the data-directory hardener resets the owner and access lists of the whole tree, refuses junctions
/// and hard links, and fails closed when it cannot take ownership. Runs on temp directories; tests that
/// need ownership changes use a policy that trusts the current (unelevated) user, so only the production
/// owner/trust set differs from what the service runs with.
/// </summary>
public sealed class DataDirectoryHardeningTests : IDisposable
{
    private static readonly SecurityIdentifier Me = WindowsIdentity.GetCurrent().User!;
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier ForeignUser = new("S-1-5-21-1111111111-2222222222-3333333333-1001");

    private readonly List<string> _cleanup = new();

    /// <summary>Production rules, except that the test user is the owner and is trusted.</summary>
    private static DataDirectoryPolicy TestPolicy() => new(
        Me,
        new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) },
        $"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{Me.Value})");

    private static DataDirectoryHardener Hardener(DataDirectoryPolicy policy) =>
        new(NullLogger<DataDirectoryHardener>.Instance, policy);

    [Fact]
    public void Given_foreign_grants_throughout_the_tree_When_hardened_Then_every_untrusted_allow_entry_is_removed()
    {
        string root = NewTempDir();
        string ml = Directory.CreateDirectory(Path.Combine(root, "ml")).FullName;
        string wdac = Directory.CreateDirectory(Path.Combine(root, "wdac")).FullName;
        string model = Path.Combine(ml, "model.onnx");
        File.WriteAllText(model, "planted");

        Grant(new DirectoryInfo(root), Everyone, FileSystemRights.Modify, inherit: true);
        // A protected child DACL (like the quarantine store's) that also lets Everyone in.
        ProtectAndGrant(new DirectoryInfo(ml), Everyone, FileSystemRights.FullControl);
        Grant(new FileInfo(model), ForeignUser, FileSystemRights.Write, inherit: false);
        // Inherit-only: new files in wdac\ would be writable by Users.
        Grant(new DirectoryInfo(wdac), Users, FileSystemRights.Write, inherit: true, inheritOnly: true);

        DataDirectoryReport report = Hardener(TestPolicy()).HardenDataDirectory(root);

        Assert.True(report.Success, report.Summary());
        Assert.True(DataDirectoryHardener.IsProtected(root));
        foreach (string path in new[] { root, ml, wdac })
        {
            Assert.Empty(UntrustedAllowSids(new DirectoryInfo(path)));
        }
        Assert.Empty(UntrustedAllowSids(new FileInfo(model)));
        // The child's own protection is kept: only the untrusted entry went.
        Assert.True(DataDirectoryHardener.IsProtected(ml));
        Assert.True(Hardener(TestPolicy()).VerifyDataDirectory(root, requireTrustedOwnership: true).Success);
    }

    [Fact]
    public void Given_a_junction_inside_the_tree_When_hardened_Then_nothing_is_changed_and_the_junction_is_reported()
    {
        string root = NewTempDir();
        string target = NewTempDir();
        Grant(new DirectoryInfo(root), Everyone, FileSystemRights.Modify, inherit: true);
        Grant(new DirectoryInfo(target), Everyone, FileSystemRights.Modify, inherit: true);
        string junction = Path.Combine(root, "wdac");
        MkLink("/J", junction, target);

        DataDirectoryReport report = Hardener(TestPolicy()).HardenDataDirectory(root);

        Assert.False(report.Success);
        Assert.Contains(report.Redirects, r => string.Equals(r, junction, StringComparison.OrdinalIgnoreCase));
        // Refused before any change: neither the tree nor the junction's target was touched.
        Assert.Contains(Everyone, UntrustedAllowSids(new DirectoryInfo(root)));
        Assert.Contains(Everyone, UntrustedAllowSids(new DirectoryInfo(target)));
        Assert.False(DataDirectoryHardener.IsProtected(root));
    }

    [Fact]
    public void Given_the_data_directory_itself_is_a_junction_When_verified_in_a_dev_run_Then_it_fails()
    {
        string parent = NewTempDir();
        string target = NewTempDir();
        string dataDir = Path.Combine(parent, "Warden");
        MkLink("/J", dataDir, target);

        DataDirectoryReport report = Hardener(TestPolicy()).VerifyDataDirectory(dataDir, requireTrustedOwnership: false);

        Assert.False(report.Success);
        Assert.Contains(report.Redirects, r => string.Equals(r, dataDir, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Given_a_hard_linked_file_in_the_tree_When_hardened_Then_it_is_refused_as_a_redirect()
    {
        string root = NewTempDir();
        string outside = Path.Combine(NewTempDir(), "victim.txt");
        File.WriteAllText(outside, "x");
        string link = Path.Combine(root, "warden.db");
        MkLink("/H", link, outside);

        var hardener = Hardener(TestPolicy());
        DataDirectoryReport report = hardener.HardenDataDirectory(root);

        Assert.False(report.Success);
        Assert.Contains(report.Redirects, r => string.Equals(r, link, StringComparison.OrdinalIgnoreCase));
        Assert.False(hardener.HardenFile(link));
    }

    [Fact]
    public void Given_a_directory_owned_by_a_standard_user_When_hardened_with_the_production_policy_Then_the_owner_is_reset_or_it_fails_closed()
    {
        string root = NewTempDir();
        Grant(new DirectoryInfo(root), Everyone, FileSystemRights.Modify, inherit: true);

        DataDirectoryReport report = new DataDirectoryHardener(NullLogger<DataDirectoryHardener>.Instance).HardenDataDirectory(root);

        if (IsElevated())
        {
            Assert.True(report.Success, report.Summary());
            var owner = (SecurityIdentifier)new DirectoryInfo(root).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))!;
            Assert.True(owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        }
        else
        {
            // Without the right to take ownership the directory stays untrusted: report it, change nothing.
            Assert.False(report.Success);
            Assert.Contains(report.Problems, p => p.Contains("take ownership", StringComparison.Ordinal));
            Assert.Contains(Everyone, UntrustedAllowSids(new DirectoryInfo(root)));
        }
    }

    [Fact]
    public void Given_a_directory_owned_by_a_standard_user_When_verified_with_ownership_required_Then_the_owner_is_reported()
    {
        string root = NewTempDir();
        Directory.CreateDirectory(Path.Combine(root, "logs"));
        var hardener = new DataDirectoryHardener(NullLogger<DataDirectoryHardener>.Instance);

        DataDirectoryReport strict = hardener.VerifyDataDirectory(root, requireTrustedOwnership: true);
        DataDirectoryReport devRun = hardener.VerifyDataDirectory(root, requireTrustedOwnership: false);

        Assert.False(strict.Success);
        Assert.Contains(strict.Problems, p => p.Contains("is owned by " + Me.Value, StringComparison.Ordinal));
        Assert.True(devRun.Success, devRun.Summary());
    }

    [Fact]
    public void Given_a_tree_larger_than_the_cap_When_hardened_Then_it_is_reported_not_trusted()
    {
        string root = NewTempDir();
        for (int i = 0; i < 5; i++)
        {
            File.WriteAllText(Path.Combine(root, $"f{i}.txt"), "x");
        }

        DataDirectoryReport report = new DataDirectoryHardener(NullLogger<DataDirectoryHardener>.Instance, TestPolicy(), maxEntries: 3)
            .HardenDataDirectory(root);

        Assert.False(report.Success);
        Assert.Contains(report.Problems, p => p.Contains("too many", StringComparison.Ordinal));
    }

    [Fact]
    public void Given_a_folder_writable_by_an_arbitrary_user_sid_When_probed_Then_that_sid_is_reported()
    {
        string root = NewTempDir();
        Grant(new DirectoryInfo(root), ForeignUser, FileSystemRights.Write, inherit: false);

        IReadOnlyList<string>? writers = DataDirectoryHardener.LowPrivilegeWriters(root);

        Assert.NotNull(writers);
        Assert.Contains(ForeignUser.Value, writers!);
    }

    // ---- helpers -----------------------------------------------------------------------------------

    private string NewTempDir()
    {
        string path = Path.Combine(Path.GetTempPath(), "warden-h4-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        _cleanup.Add(path);
        return path;
    }

    private static void Grant(FileSystemInfo item, SecurityIdentifier sid, FileSystemRights rights, bool inherit, bool inheritOnly = false)
    {
        InheritanceFlags flags = inherit && item is DirectoryInfo
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;
        PropagationFlags propagation = inheritOnly ? PropagationFlags.InheritOnly : PropagationFlags.None;
        var rule = new FileSystemAccessRule(sid, rights, flags, propagation, AccessControlType.Allow);
        if (item is DirectoryInfo d)
        {
            DirectorySecurity sec = d.GetAccessControl(AccessControlSections.Access);
            sec.AddAccessRule(rule);
            d.SetAccessControl(sec);
        }
        else
        {
            var f = (FileInfo)item;
            FileSecurity sec = f.GetAccessControl(AccessControlSections.Access);
            sec.AddAccessRule(rule);
            f.SetAccessControl(sec);
        }
    }

    private static void ProtectAndGrant(DirectoryInfo dir, SecurityIdentifier sid, FileSystemRights rights)
    {
        var sec = new DirectorySecurity();
        sec.SetSecurityDescriptorSddlForm(
            $"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{Me.Value})", AccessControlSections.Access);
        sec.AddAccessRule(new FileSystemAccessRule(sid, rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(sec);
    }

    /// <summary>SIDs other than SYSTEM, Administrators and the test user holding an allow entry.</summary>
    private static List<SecurityIdentifier> UntrustedAllowSids(FileSystemInfo item)
    {
        FileSystemSecurity sec = item is DirectoryInfo d
            ? d.GetAccessControl(AccessControlSections.Access)
            : ((FileInfo)item).GetAccessControl(AccessControlSections.Access);
        return sec.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .Select(r => (SecurityIdentifier)r.IdentityReference)
            .Where(s => !s.Equals(Me)
                        && !s.IsWellKnown(WellKnownSidType.LocalSystemSid)
                        && !s.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            .ToList();
    }

    private static void MkLink(string kind, string link, string target)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("/c");
        psi.ArgumentList.Add("mklink");
        psi.ArgumentList.Add(kind);
        psi.ArgumentList.Add(link);
        psi.ArgumentList.Add(target);
        using Process p = Process.Start(psi)!;
        p.WaitForExit(10_000);
        Assert.True(p.ExitCode == 0, $"mklink {kind} failed: {p.StandardError.ReadToEnd()}");
    }

    private static bool IsElevated() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public void Dispose()
    {
        foreach (string path in _cleanup)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    continue;
                }
                // Give the test user its access back (it may have been removed or the owner reset).
                var di = new DirectoryInfo(path);
                DirectorySecurity sec = di.GetAccessControl();
                sec.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
                sec.AddAccessRule(new FileSystemAccessRule(Me, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                di.SetAccessControl(sec);
                // Recursive delete removes junctions without following them.
                Directory.Delete(path, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                // best effort
            }
        }
    }
}
