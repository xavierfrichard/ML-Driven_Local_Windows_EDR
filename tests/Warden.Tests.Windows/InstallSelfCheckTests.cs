using Warden.Hardening;

namespace Warden.Tests.Windows;

/// <summary>
/// The startup self-check of the code the LocalSystem service loads: service folder and its parents, the
/// dotnet host, hostfxr and the shared runtime, including the owner and any non-admin SID.
/// </summary>
public sealed class InstallSelfCheckTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "warden-selfcheck-" + Guid.NewGuid().ToString("N"));

    public InstallSelfCheckTests() => Directory.CreateDirectory(_temp);

    /// <summary>The shared runtime this test runs on, when it is a machine-wide install under Program Files.</summary>
    private static string? MachineRuntimeDirectory()
    {
        string? runtime = Path.GetDirectoryName(typeof(object).Assembly.Location);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return runtime is not null && runtime.StartsWith(programFiles + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            ? runtime
            : null;
    }

    [Fact]
    public void Given_a_service_folder_owned_by_a_standard_user_When_checked_Then_a_problem_is_reported()
    {
        // The old check looked only at well-known groups in the folder's own DACL: a user-owned folder under
        // the profile passed it.
        Assert.Empty(DataDirectoryHardener.LowPrivilegeWriters(_temp)!
            .Where(s => s is "S-1-1-0" or "S-1-5-11" or "S-1-5-32-545" or "S-1-5-4"));

        IReadOnlyList<string> problems = InstallSelfCheck.FindProblems(_temp, hostPath: null, runtimeDirectory: null);

        Assert.NotEmpty(problems);
    }

    [Fact]
    public void Given_a_dotnet_host_in_a_user_writable_folder_When_checked_Then_the_host_is_reported()
    {
        string? runtime = MachineRuntimeDirectory();
        if (runtime is null)
        {
            return; // needs a machine-wide runtime to use as the trusted service folder
        }
        string host = Path.Combine(_temp, "dotnet.exe");
        File.WriteAllText(host, "not really dotnet");

        IReadOnlyList<string> problems = InstallSelfCheck.FindProblems(runtime, host, runtimeDirectory: null);

        Assert.NotEmpty(problems);
        Assert.Contains(problems, p => p.Contains(_temp, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Given_a_shared_runtime_in_a_user_writable_folder_When_checked_Then_it_is_reported()
    {
        string? runtime = MachineRuntimeDirectory();
        if (runtime is null)
        {
            return;
        }

        IReadOnlyList<string> problems = InstallSelfCheck.FindProblems(runtime, hostPath: null, runtimeDirectory: _temp);

        Assert.NotEmpty(problems);
    }

    [Fact]
    public void Given_the_machine_wide_dotnet_install_When_checked_Then_no_problem_is_reported()
    {
        string? runtime = MachineRuntimeDirectory();
        if (runtime is null)
        {
            return;
        }
        // ...\dotnet\shared\Microsoft.NETCore.App\<version>
        string dotnetRoot = Path.GetFullPath(Path.Combine(runtime, "..", "..", ".."));
        string host = Path.Combine(dotnetRoot, "dotnet.exe");
        if (!File.Exists(host))
        {
            return;
        }

        IReadOnlyList<string> problems = InstallSelfCheck.FindProblems(runtime, host, runtime);

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_temp, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // best effort
        }
    }
}
