using System.Security.AccessControl;
using System.Security.Principal;
using Warden.Hardening;

namespace Warden.Tests.Windows;

/// <summary>
/// Tests for the check that gates "Folder → Allow" rules: only folders that standard users cannot write to,
/// or move aside, may carry one. The security descriptors below mirror real Windows defaults.
/// </summary>
public sealed class FolderWriteAccessTests
{
    private const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    // C:\Program Files: TrustedInstaller-owned; Users and AppContainers read/execute only.
    private const string ProgramFilesSddl =
        "O:" + TrustedInstaller + "D:PAI(A;;FA;;;" + TrustedInstaller + ")(A;OICIIO;GA;;;" + TrustedInstaller + ")"
        + "(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)"
        + "(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;AC)";

    // C:\ itself: Authenticated Users may create folders here (LC = 0x4) and get Modify on what they create.
    private const string DriveRootSddl =
        "O:" + TrustedInstaller + "D:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)"
        + "(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)";

    // A folder an administrator created at C:\Tools: it inherits Modify for Authenticated Users from C:\.
    private const string AdminFolderUnderDriveRootSddl =
        "O:BAD:AI(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)"
        + "(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)";

    [Fact]
    public void A_program_files_folder_is_safe()
    {
        Assert.Null(FolderWriteAccess.Describe(@"C:\Program Files\App", ProgramFilesSddl, FolderWriteAccess.Scope.Content));
        Assert.Null(FolderWriteAccess.Describe(@"C:\Program Files", ProgramFilesSddl, FolderWriteAccess.Scope.Ancestor));
    }

    [Fact]
    public void The_drive_root_is_a_safe_ancestor_but_not_a_safe_folder()
    {
        // As a parent: creating NEW folders there does not let anyone replace an existing one.
        Assert.Null(FolderWriteAccess.Describe(@"C:\", DriveRootSddl, FolderWriteAccess.Scope.Ancestor));
        // As the rule's folder itself: anyone could drop files into it.
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\", DriveRootSddl, FolderWriteAccess.Scope.Content));
    }

    [Fact]
    public void A_folder_created_under_the_drive_root_is_writable_by_authenticated_users()
    {
        string? problem = FolderWriteAccess.Describe(@"C:\Tools", AdminFolderUnderDriveRootSddl, FolderWriteAccess.Scope.Content);
        Assert.NotNull(problem);
        Assert.Contains(@"C:\Tools", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void A_user_owned_folder_is_refused_even_with_an_admin_only_acl()
    {
        // The owner can always rewrite the DACL.
        const string sddl = "O:S-1-5-21-1111111111-2222222222-3333333333-1001D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\Users\bob\App", sddl, FolderWriteAccess.Scope.Content));
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\Users\bob", sddl, FolderWriteAccess.Scope.Ancestor));
    }

    [Theory]
    [InlineData("O:BAD:(A;;0x40;;;BU)")]        // Users may delete children: can rename the folder away
    [InlineData("O:BAD:(A;;0x10000;;;AU)")]     // Authenticated Users may delete/rename the ancestor itself
    [InlineData("O:BAD:(A;;WD;;;WD)")]          // Everyone may rewrite the DACL
    public void An_ancestor_that_lets_users_replace_the_folder_is_refused(string sddl)
    {
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\Parent", sddl, FolderWriteAccess.Scope.Ancestor));
    }

    [Theory]
    [InlineData("O:BAD:(A;;0x2;;;BU)")]            // create files
    [InlineData("O:BAD:(A;;0x4;;;BU)")]            // create subfolders
    [InlineData("O:BAD:(A;;GW;;;S-1-5-11)")]       // generic write
    [InlineData("O:BAD:(A;;GA;;;WD)")]             // generic all
    [InlineData("O:BAD:NO_ACCESS_CONTROL")]        // NULL DACL
    [InlineData("O:BAD:(A;;FA;;;S-1-5-19)")]       // LOCAL SERVICE is not trusted
    public void Any_untrusted_write_right_on_the_folder_is_refused(string sddl)
    {
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\App", sddl, FolderWriteAccess.Scope.Content));
    }

    [Fact]
    public void Inherit_only_and_deny_entries_do_not_count_as_write_access()
    {
        const string sddl = "O:SYD:P(A;;FA;;;SY)(A;OICIIO;FA;;;BU)(D;;FA;;;WD)(A;OICIIO;GA;;;CO)";
        Assert.Null(FolderWriteAccess.Describe(@"C:\App", sddl, FolderWriteAccess.Scope.Content));
    }

    [Fact]
    public void Unreadable_or_unparseable_permissions_are_refused()
    {
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\App", null, FolderWriteAccess.Scope.Content));
        Assert.NotNull(FolderWriteAccess.Describe(@"C:\App", "not sddl", FolderWriteAccess.Scope.Content));
    }

    [Fact]
    public void A_missing_folder_is_refused()
    {
        string missing = Path.Combine(Path.GetTempPath(), "warden-missing-" + Guid.NewGuid().ToString("N"));
        Assert.NotNull(FolderWriteAccess.FindProblem(missing));
    }

    [Fact]
    public void A_real_folder_with_a_user_writable_file_is_refused()
    {
        string dir = Path.Combine(Path.GetTempPath(), "warden-fwa-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string file = Path.Combine(dir, "tool.exe");
            File.WriteAllBytes(file, new byte[] { (byte)'M', (byte)'Z' });
            var info = new FileInfo(file);
            FileSecurity security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Modify, AccessControlType.Allow));
            info.SetAccessControl(security);

            // Under %TEMP% the parents are user-owned anyway; either way this must never come back "safe".
            Assert.NotNull(FolderWriteAccess.FindProblem(dir));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void A_tree_larger_than_the_cap_is_refused()
    {
        string? problem = FolderWriteAccess.FindProblem(Environment.GetFolderPath(Environment.SpecialFolder.System), maxEntries: 1);
        Assert.NotNull(problem);
    }
}
