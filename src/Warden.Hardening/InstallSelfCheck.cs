using System.Runtime.Versioning;
using System.Security.AccessControl;

namespace Warden.Hardening;

/// <summary>
/// Startup self-check of the code a LocalSystem service loads: its own binaries, the <c>dotnet.exe</c> host,
/// <c>hostfxr</c> and the shared runtime. Anyone other than SYSTEM, Administrators or TrustedInstaller who
/// owns or can write any of these (or move a parent folder aside and recreate it) can run code as SYSTEM
/// at the next (auto-restarted) start.
/// </summary>
/// <remarks>
/// Uses <see cref="FolderWriteAccess"/> for each folder tree: it checks the owner and every allow entry of
/// any SID (not only well-known groups), every parent folder up to the volume root, and refuses reparse
/// points. The <c>dotnet</c> folder itself is checked without recursion: it also holds SDKs and packs the
/// service never loads, and can be larger than the walk cap.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class InstallSelfCheck
{
    /// <summary>
    /// Returns one human-readable problem per untrusted location; empty when everything checked is
    /// controlled only by SYSTEM, Administrators or TrustedInstaller.
    /// </summary>
    /// <param name="serviceDirectory">The service's binaries (<c>AppContext.BaseDirectory</c>).</param>
    /// <param name="hostPath">The process image (<c>Environment.ProcessPath</c>), usually <c>dotnet.exe</c>.</param>
    /// <param name="runtimeDirectory">The shared runtime folder (<c>RuntimeEnvironment.GetRuntimeDirectory()</c>).</param>
    public static IReadOnlyList<string> FindProblems(string serviceDirectory, string? hostPath, string? runtimeDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceDirectory);
        var problems = new List<string>();
        string serviceDir = Trim(serviceDirectory);

        Add(problems, FolderWriteAccess.FindProblem(serviceDir));

        if (!string.IsNullOrWhiteSpace(hostPath))
        {
            string? hostDir = Path.GetDirectoryName(Path.GetFullPath(hostPath));
            if (hostDir is not null && !SamePath(hostDir, serviceDir))
            {
                Add(problems, CheckSingle(new FileInfo(hostPath)));
                Add(problems, CheckSingle(new DirectoryInfo(hostDir)));
                Add(problems, CheckAncestors(new DirectoryInfo(hostDir)));

                string fxr = Path.Combine(hostDir, "host", "fxr");
                if (Directory.Exists(fxr))
                {
                    Add(problems, FolderWriteAccess.FindProblem(fxr));
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(runtimeDirectory))
        {
            string runtimeDir = Trim(runtimeDirectory);
            if (!SamePath(runtimeDir, serviceDir))
            {
                Add(problems, FolderWriteAccess.FindProblem(runtimeDir));
            }
        }

        return problems;
    }

    private static string? CheckSingle(FileSystemInfo item)
    {
        if (!item.Exists)
        {
            return $"{item.FullName} does not exist.";
        }
        if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return $"{item.FullName} is a symbolic link or junction.";
        }
        return FolderWriteAccess.Describe(item.FullName, ReadSddl(item), FolderWriteAccess.Scope.Content);
    }

    private static string? CheckAncestors(DirectoryInfo dir)
    {
        for (DirectoryInfo? parent = dir.Parent; parent is not null; parent = parent.Parent)
        {
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return $"{parent.FullName} is a symbolic link or junction.";
            }
            if (FolderWriteAccess.Describe(parent.FullName, ReadSddl(parent), FolderWriteAccess.Scope.Ancestor) is { } problem)
            {
                return problem;
            }
        }
        return null;
    }

    private static string? ReadSddl(FileSystemInfo info)
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

    private static void Add(List<string> problems, string? problem)
    {
        if (problem is not null)
        {
            problems.Add(problem);
        }
    }

    private static string Trim(string path) => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static bool SamePath(string a, string b) => string.Equals(Trim(a), Trim(b), StringComparison.OrdinalIgnoreCase);
}
