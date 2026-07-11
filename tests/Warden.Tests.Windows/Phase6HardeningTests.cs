using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Hardening;

namespace Warden.Tests.Windows;

/// <summary>
/// Tests for the Phase 6 hardening: the security-descriptor constants, the sc.exe argument builders, and
/// the data-directory ACL applier (exercised against a temporary directory — no service, no admin needed).
/// </summary>
public sealed class Phase6HardeningTests
{
    // ---- SDDL constants ---------------------------------------------------------------------------

    [Fact]
    public void Data_directory_dacl_is_protected_and_system_admin_only()
    {
        string sddl = HardeningSddl.DataDirectoryDacl;
        Assert.Contains("PAI", sddl, StringComparison.Ordinal); // protected + auto-inherited
        Assert.Contains(";;;SY)", sddl, StringComparison.Ordinal);
        Assert.Contains(";;;BA)", sddl, StringComparison.Ordinal);
        // No entry for Everyone / Authenticated Users / Users.
        Assert.DoesNotContain(";;;WD)", sddl, StringComparison.Ordinal);
        Assert.DoesNotContain(";;;AU)", sddl, StringComparison.Ordinal);
    }

    [Fact]
    public void Service_dacl_lets_standard_users_query_but_not_stop_or_delete()
    {
        string sddl = HardeningSddl.ServiceDacl;
        // SYSTEM + Administrators get full control (includes WP=stop, DC=change, SD=delete).
        Assert.Contains("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)", sddl, StringComparison.Ordinal);
        Assert.Contains("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)", sddl, StringComparison.Ordinal);
        // Authenticated Users: query/read only — no RP(start)/WP(stop)/DC(change)/SD(delete).
        Assert.Contains("(A;;CCLCSWLOCRRC;;;AU)", sddl, StringComparison.Ordinal);
    }

    // ---- sc.exe argument builders -----------------------------------------------------------------

    [Fact]
    public void SdSet_arguments_reference_the_service_and_dacl()
    {
        string args = ServiceHardener.BuildSdSetArguments("WardenAgent", HardeningSddl.ServiceDacl);
        Assert.Equal($"sdset WardenAgent {HardeningSddl.ServiceDacl}", args);
    }

    [Fact]
    public void Failure_arguments_configure_restart_on_kill()
    {
        string args = ServiceHardener.BuildFailureArguments("WardenAgent", 86400, 60000);
        Assert.Equal("failure WardenAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000", args);
    }

    [Fact]
    public void Failure_flag_arguments_enable_recovery_on_non_crash_stop()
    {
        Assert.Equal("failureflag WardenAgent 1", ServiceHardener.BuildFailureFlagArguments("WardenAgent"));
    }

    // ---- Data-directory ACL applier ---------------------------------------------------------------

    [Fact]
    public void Harden_directory_protects_the_acl()
    {
        var hardener = new DataDirectoryHardener(NullLogger<DataDirectoryHardener>.Instance);
        string temp = Path.Combine(Path.GetTempPath(), "warden-hard-" + Guid.NewGuid().ToString("N"));
        try
        {
            bool ok = hardener.HardenDirectory(temp);

            Assert.True(ok);
            Assert.True(DataDirectoryHardener.IsProtected(temp)); // no longer inherits from %TEMP%
            string? dacl = DataDirectoryHardener.ReadDirectoryDacl(temp);
            Assert.NotNull(dacl);
            Assert.Contains("SY", dacl!, StringComparison.Ordinal); // SYSTEM retained
        }
        finally
        {
            RestoreAndDelete(temp);
        }
    }

    /// <summary>
    /// After locking a directory to SYSTEM + Administrators the test user has no explicit access; as the
    /// owner it can still rewrite the DACL. Re-grant itself full control (and re-enable inheritance) so
    /// the temp directory can be deleted.
    /// </summary>
    private static void RestoreAndDelete(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return;
            }
            var di = new DirectoryInfo(path);
            DirectorySecurity sec = di.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);
            SecurityIdentifier me = WindowsIdentity.GetCurrent().User!;
            sec.AddAccessRule(new FileSystemAccessRule(
                me, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            di.SetAccessControl(sec);
            Directory.Delete(path, recursive: true);
        }
        catch
        {
            // best effort — the temp dir will be cleaned by the OS eventually
        }
    }
}
