using System.Diagnostics;
using System.Text;
using Warden.Secrets;

namespace Warden.Tests;

/// <summary>
/// Audit M4: API keys move from world-readable machine environment variables to a DPAPI store that only
/// SYSTEM and Administrators can read; the environment stays as a deprecated, warned fallback.
/// </summary>
public sealed class SecretStoreTests : IDisposable
{
    // Owner Administrators, SYSTEM + Administrators only: what install.ps1 / Set-WardenSecret.ps1 produce.
    private const string LockedDir = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    private const string LockedFile = "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
    private const string UsersCanRead = "O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
    private const string UsersCanWriteDir = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100002;;;BU)";
    private const string OwnedByAttacker = "O:S-1-5-21-1111111111-2222222222-3333333333-1001G:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    private readonly string _dataDir;

    public SecretStoreTests()
    {
        _dataDir = Path.Combine(Path.GetTempPath(), "warden-secrets-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_dataDir, "secrets"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dataDir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static string? NoEnvironment(string _) => null;

    private void Store(string name, string value, string? asName = null)
    {
        byte[] blob = DpapiMachineProtector.Protect(Encoding.UTF8.GetBytes(value), WardenSecretStore.EntropyFor(name));
        File.WriteAllBytes(Path.Combine(_dataDir, "secrets", (asName ?? name) + ".bin"), blob);
    }

    /// <summary>Hands out locked SDDL for every path except the ones overridden.</summary>
    private TrustedFileChain.SddlReader Sddl(Func<string, string?>? overrideFor = null) => (path, isDirectory) =>
        overrideFor?.Invoke(path) ?? (isDirectory ? LockedDir : LockedFile);

    [Fact]
    public void Given_no_store_entry_and_no_variable_When_read_Then_nothing_is_configured()
    {
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        SecretLookup lookup = store.GetWithLegacyFallback(WardenSecretStore.VirusTotalApiKey, "WARDEN_VT_API_KEY", NoEnvironment);

        Assert.Equal(SecretOrigin.None, lookup.Origin);
        Assert.Null(lookup.Value);
    }

    [Fact]
    public void Given_only_the_legacy_variable_When_read_Then_it_is_used_with_a_world_readable_warning()
    {
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        SecretLookup lookup = store.GetWithLegacyFallback(WardenSecretStore.VirusTotalApiKey, "WARDEN_VT_API_KEY",
            name => name == "WARDEN_VT_API_KEY" ? " vt-from-env " : null);

        Assert.Equal(SecretOrigin.LegacyEnvironment, lookup.Origin);
        Assert.Equal("vt-from-env", lookup.Value);
        Assert.Contains("every user can read", lookup.Message, StringComparison.Ordinal);
        Assert.Contains("Set-WardenSecret.ps1", lookup.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("vt-from-env", lookup.Message, StringComparison.Ordinal); // never log the key
    }

    [Fact]
    public void Given_a_locked_store_entry_When_read_Then_it_wins_over_the_legacy_variable()
    {
        Store(WardenSecretStore.AnthropicApiKey, "sk-from-store");
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        SecretLookup lookup = store.GetWithLegacyFallback(WardenSecretStore.AnthropicApiKey, "WARDEN_ANTHROPIC_API_KEY",
            _ => "sk-from-env");

        Assert.Equal(SecretOrigin.Store, lookup.Origin);
        Assert.Equal("sk-from-store", lookup.Value);
        Assert.Null(lookup.Message);
    }

    [Theory]
    [InlineData("file-users-read")]
    [InlineData("file-owned-by-attacker")]
    [InlineData("secrets-dir-users-write")]
    [InlineData("data-dir-owned-by-attacker")]
    [InlineData("file-unreadable-acl")]
    public void Given_a_store_entry_with_unsafe_permissions_When_read_Then_it_is_refused_with_no_fallback(string scenario)
    {
        Store(WardenSecretStore.VirusTotalApiKey, "vt-from-store");
        string file = Path.Combine(_dataDir, "secrets", "VirusTotalApiKey.bin");
        string secretsDir = Path.Combine(_dataDir, "secrets");
        TrustedFileChain.SddlReader sddl = Sddl(path => scenario switch
        {
            "file-users-read" when path == file => UsersCanRead,
            "file-owned-by-attacker" when path == file => OwnedByAttacker,
            "secrets-dir-users-write" when path == secretsDir => UsersCanWriteDir,
            "data-dir-owned-by-attacker" when path == _dataDir => OwnedByAttacker,
            "file-unreadable-acl" when path == file => string.Empty,
            _ => null,
        });
        var store = new WardenSecretStore(_dataDir, readSddl: sddl);

        SecretLookup lookup = store.GetWithLegacyFallback(WardenSecretStore.VirusTotalApiKey, "WARDEN_VT_API_KEY", _ => "vt-from-env");

        Assert.Equal(SecretOrigin.Refused, lookup.Origin);
        Assert.True(lookup.IsCritical);
        Assert.Null(lookup.Value); // neither the stored value nor the environment
        Assert.DoesNotContain("vt-from", lookup.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Given_a_store_entry_in_a_real_user_owned_folder_When_read_Then_the_file_system_check_refuses_it()
    {
        // No injected SDDL: the real owner/ACL of a %TEMP% folder (the test user can write it) must fail.
        Store(WardenSecretStore.VirusTotalApiKey, "vt-from-store");
        var store = new WardenSecretStore(_dataDir);

        SecretLookup lookup = store.Get(WardenSecretStore.VirusTotalApiKey);

        Assert.Equal(SecretOrigin.Refused, lookup.Origin);
        Assert.Null(lookup.Value);
    }

    [Fact]
    public void Given_a_blob_copied_to_another_name_When_read_Then_it_does_not_decrypt()
    {
        Store(WardenSecretStore.VirusTotalApiKey, "vt-key", asName: WardenSecretStore.AnthropicApiKey);
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        SecretLookup lookup = store.Get(WardenSecretStore.AnthropicApiKey);

        Assert.Equal(SecretOrigin.Refused, lookup.Origin);
        Assert.Null(lookup.Value);
    }

    [Fact]
    public void Given_a_corrupt_blob_When_read_Then_it_is_refused()
    {
        File.WriteAllBytes(Path.Combine(_dataDir, "secrets", "MlModelSha256.bin"), new byte[] { 1, 2, 3, 4, 5 });
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        SecretLookup lookup = store.Get(WardenSecretStore.MlModelSha256);

        Assert.Equal(SecretOrigin.Refused, lookup.Origin);
    }

    [Fact]
    public void Given_an_oversized_blob_When_read_Then_it_is_refused_without_decrypting()
    {
        File.WriteAllBytes(Path.Combine(_dataDir, "secrets", "MlModelSha256.bin"), new byte[WardenSecretStore.MaxBlobBytes + 1]);
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        Assert.Equal(SecretOrigin.Refused, store.Get(WardenSecretStore.MlModelSha256).Origin);
    }

    [Fact]
    public void Given_a_secrets_folder_that_is_a_junction_When_read_Then_it_is_refused()
    {
        string elsewhere = Path.Combine(_dataDir, "elsewhere");
        Directory.CreateDirectory(elsewhere);
        Directory.Delete(Path.Combine(_dataDir, "secrets"));
        CreateJunction(Path.Combine(_dataDir, "secrets"), elsewhere);
        Store(WardenSecretStore.VirusTotalApiKey, "vt-key");
        var store = new WardenSecretStore(_dataDir, readSddl: Sddl());

        SecretLookup lookup = store.Get(WardenSecretStore.VirusTotalApiKey);

        Assert.Equal(SecretOrigin.Refused, lookup.Origin);
        Assert.Contains("junction", lookup.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"..\x")]
    [InlineData("a.b")]
    [InlineData("")]
    public void Given_an_invalid_secret_name_When_used_Then_it_throws(string name)
    {
        var store = new WardenSecretStore(_dataDir);
        Assert.ThrowsAny<ArgumentException>(() => store.PathFor(name));
    }

    [Fact]
    public void Given_the_strict_policy_When_a_directory_only_grants_inherit_only_rights_Then_it_is_accepted()
    {
        // Inherit-only ACEs do not apply to the folder itself; children are checked on their own.
        const string sddl = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FR;;;BU)";
        Assert.Null(WardenSecretStore.DescribeStrict(@"C:\ProgramData\Warden", sddl, ChainRole.Ancestor));
    }

    internal static void CreateJunction(string link, string target)
    {
        using var p = Process.Start(new ProcessStartInfo("cmd.exe")
        {
            ArgumentList = { "/c", "mklink", "/J", link, target },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
    }
}

/// <summary>The file-and-parents walk used before trusting the claude CLI, the ML model and the store.</summary>
public sealed class TrustedFileChainTests : IDisposable
{
    private readonly string _root;

    public TrustedFileChainTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "warden-chain-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_root, "a", "b"));
        File.WriteAllText(Path.Combine(_root, "a", "b", "tool.exe"), "x");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    [Fact]
    public void Given_a_file_When_walked_Then_the_file_its_folder_and_every_parent_are_checked_in_order()
    {
        var seen = new List<(string Path, ChainRole Role, bool HasSddl)>();
        string file = Path.Combine(_root, "a", "b", "tool.exe");

        string? problem = TrustedFileChain.FindProblem(file, (p, sddl, role) => { seen.Add((p, role, sddl is not null)); return null; });

        Assert.Null(problem);
        Assert.Equal((file, ChainRole.File), (seen[0].Path, seen[0].Role));
        Assert.Equal((Path.Combine(_root, "a", "b"), ChainRole.Container), (seen[1].Path, seen[1].Role));
        Assert.Equal((Path.Combine(_root, "a"), ChainRole.Ancestor), (seen[2].Path, seen[2].Role));
        Assert.Equal(Path.GetPathRoot(file), seen[^1].Path);   // walked all the way to the volume root
        Assert.All(seen, s => Assert.True(s.HasSddl));           // read the real security descriptors
    }

    [Fact]
    public void Given_a_stop_folder_When_walked_Then_the_walk_ends_there()
    {
        var seen = new List<string>();
        string file = Path.Combine(_root, "a", "b", "tool.exe");

        TrustedFileChain.FindProblem(file, (p, _, _) => { seen.Add(p); return null; }, stopAt: Path.Combine(_root, "a"));

        Assert.Equal(new[] { file, Path.Combine(_root, "a", "b"), Path.Combine(_root, "a") }, seen);
    }

    [Fact]
    public void Given_a_problem_on_a_parent_When_walked_Then_it_is_reported_and_the_walk_stops()
    {
        int calls = 0;
        string? problem = TrustedFileChain.FindProblem(Path.Combine(_root, "a", "b", "tool.exe"), (p, _, role) =>
        {
            calls++;
            return role == ChainRole.Container ? $"Users can write to {p}." : null;
        });

        Assert.Equal($"Users can write to {Path.Combine(_root, "a", "b")}.", problem);
        Assert.Equal(2, calls);
    }

    [Theory]
    [InlineData(@"tool.exe")]
    [InlineData(@"C:tool.exe")]
    [InlineData(@"\\server\share\tool.exe")]
    public void Given_a_non_local_or_relative_path_When_walked_Then_it_is_refused(string path)
    {
        Assert.NotNull(TrustedFileChain.FindProblem(path, (_, _, _) => null));
    }

    [Fact]
    public void Given_a_missing_file_When_walked_Then_it_is_refused()
    {
        Assert.NotNull(TrustedFileChain.FindProblem(Path.Combine(_root, "missing.exe"), (_, _, _) => null));
    }

    [Fact]
    public void Given_a_file_outside_the_stop_folder_When_walked_Then_it_is_refused()
    {
        Assert.NotNull(TrustedFileChain.FindProblem(Path.Combine(_root, "a", "b", "tool.exe"), (_, _, _) => null,
            stopAt: Path.Combine(_root, "other")));
    }

    [Fact]
    public void Given_a_junction_in_the_chain_When_walked_Then_it_is_refused()
    {
        string link = Path.Combine(_root, "link");
        SecretStoreTests.CreateJunction(link, Path.Combine(_root, "a"));

        string? problem = TrustedFileChain.FindProblem(Path.Combine(link, "b", "tool.exe"), (_, _, _) => null);

        Assert.NotNull(problem);
        Assert.Contains("junction", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Given_a_user_owned_temp_file_When_checked_with_the_strict_policy_Then_it_is_refused()
    {
        string? problem = TrustedFileChain.FindProblem(Path.Combine(_root, "a", "b", "tool.exe"), WardenSecretStore.DescribeStrict);

        Assert.NotNull(problem);
    }
}
