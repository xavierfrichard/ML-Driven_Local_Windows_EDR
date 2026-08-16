using System.Security.AccessControl;
using System.Security.Principal;
using Warden.Core;
using Warden.Trust;

namespace Warden.Tests.Windows;

/// <summary>
/// The Authenticode trust gate is the only tier that can turn a block into an allow without a human,
/// a reputation service, or a model. These tests pin the properties that make that safe: the signature
/// must <b>verify for the file's bytes</b> (not merely be present), the publisher match is exact, the
/// path check excludes the user-writable pockets under <c>C:\Windows</c>, and the file must be owned by a
/// privileged account.
/// </summary>
public sealed class TrustGateTests
{
    private static SignerInfo VerifiedMicrosoft() => new(
        IsSigned: true, IsValid: true,
        SubjectName: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        IssuerName: "CN=Microsoft Code Signing PCA 2011",
        Thumbprint: "AAAA", IsMicrosoft: true)
    { SubjectCommonName = "Microsoft Corporation" };

    private static SignerInfo VerifiedPublisher(string cn, string thumbprint = "BBBB") => new(
        IsSigned: true, IsValid: true,
        SubjectName: $"CN={cn}, O=Whatever, C=US",
        IssuerName: "CN=Some Public CA",
        Thumbprint: thumbprint, IsMicrosoft: false)
    { SubjectCommonName = cn };

    private static VerdictContext Ctx(string path, SignerInfo signer) => new(
        Sha256: new string('0', 64),
        ImagePath: path,
        CommandLine: $"\"{path}\"",
        Pid: 1, ParentPid: 0, ParentPath: string.Empty, ParentSha256: null,
        Signer: signer,
        MotwZone: VerdictContext.NoMotw,
        Pe: new Lazy<PeFeatures>(() => PeFeatures.NotPortableExecutable),
        Chain: AttackChainNode.None,
        Timestamp: DateTimeOffset.UnixEpoch,
        CorrelationId: 1);

    private static AuthenticodeTrustGate Gate(Action<TrustGateOptions>? configure = null, IFileInspector? inspector = null)
    {
        var o = new TrustGateOptions { RequireAdminOwnedImage = false };
        configure?.Invoke(o);
        return new AuthenticodeTrustGate(o, inspector);
    }

    private static async Task<VerdictResult> Run(AuthenticodeTrustGate gate, VerdictContext ctx) =>
        await gate.EvaluateAsync(ctx, CancellationToken.None);

    // ---- signature must VERIFY, not merely exist -----------------------------------------------------

    [Fact]
    public async Task A_signed_but_unverified_signature_is_never_fast_allowed()
    {
        // This is exactly what a certificate grafted from another binary looks like after WinVerifyTrust.
        var borrowed = VerifiedMicrosoft() with { IsValid = false, VerificationStatus = unchecked((int)0x80096010) };
        VerdictResult r = await Run(Gate(), Ctx(@"C:\Windows\System32\evil.exe", borrowed));
        Assert.Equal(Verdict.Unknown, r.Verdict);
    }

    [Fact]
    public async Task Verified_microsoft_binary_under_system32_is_allowed_when_owner_check_is_off()
    {
        VerdictResult r = await Run(Gate(), Ctx(@"C:\Windows\System32\cmd.exe", VerifiedMicrosoft()));
        Assert.Equal(Verdict.Allow, r.Verdict);
    }

    // ---- user-writable pockets under trusted roots --------------------------------------------------

    [Theory]
    [InlineData(@"C:\Windows\Temp\payload.exe")]
    [InlineData(@"C:\Windows\Tasks\payload.exe")]
    [InlineData(@"C:\Windows\tracing\payload.exe")]
    [InlineData(@"C:\Windows\System32\Tasks\payload.exe")]
    [InlineData(@"C:\Windows\System32\spool\drivers\color\payload.exe")]
    [InlineData(@"c:\windows\temp\sub\payload.exe")]
    public async Task Verified_signature_in_a_user_writable_windows_subdirectory_is_undecided(string path)
    {
        VerdictResult r = await Run(Gate(), Ctx(path, VerifiedMicrosoft()));
        Assert.Equal(Verdict.Unknown, r.Verdict);
        Assert.Contains("user-writable", r.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"C:\Windows2\payload.exe")]                       // prefix is directory-bounded
    [InlineData(@"C:\Windows\..\Users\bob\payload.exe")]           // traversal is canonicalized away
    [InlineData(@"\\?\C:\Windows\System32\payload.exe")]           // extended prefix is not fast-allowed
    [InlineData(@"\\server\share\Windows\payload.exe")]            // UNC
    [InlineData(@"D:\Windows\System32\payload.exe")]               // other volume
    public async Task Paths_that_only_look_trusted_are_undecided(string path)
    {
        VerdictResult r = await Run(Gate(), Ctx(path, VerifiedMicrosoft()));
        Assert.Equal(Verdict.Unknown, r.Verdict);
    }

    // ---- publisher matching is exact ---------------------------------------------------------------

    [Fact]
    public async Task Publisher_match_is_exact_common_name_not_substring()
    {
        var gate = Gate(o => o.TrustedPublishers.Add("Contoso"));

        VerdictResult notContoso = await Run(gate, Ctx(@"C:\Program Files\App\app.exe", VerifiedPublisher("Not Contoso")));
        Assert.Equal(Verdict.Unknown, notContoso.Verdict);

        VerdictResult contoso = await Run(gate, Ctx(@"C:\Program Files\App\app.exe", VerifiedPublisher("contoso")));
        Assert.Equal(Verdict.Allow, contoso.Verdict);
    }

    [Fact]
    public async Task Publisher_can_be_pinned_by_thumbprint()
    {
        var gate = Gate(o => o.TrustedPublisherThumbprints.Add("bb bb"));
        VerdictResult r = await Run(gate, Ctx(@"C:\Program Files\App\app.exe", VerifiedPublisher("Anyone", "BBBB")));
        Assert.Equal(Verdict.Allow, r.Verdict);
    }

    [Fact]
    public async Task Microsoft_flag_alone_is_not_enough_when_trust_microsoft_is_off()
    {
        var gate = Gate(o => o.TrustMicrosoft = false);
        VerdictResult r = await Run(gate, Ctx(@"C:\Windows\System32\cmd.exe", VerifiedMicrosoft()));
        Assert.Equal(Verdict.Unknown, r.Verdict);
    }

    [Fact]
    public void Common_name_extraction_handles_quoted_values()
    {
        Assert.Equal("Contoso, Inc.", AuthenticodeTrustGate.ExtractCommonName("CN=\"Contoso, Inc.\", O=Contoso, C=US"));
        Assert.Equal("Plain", AuthenticodeTrustGate.ExtractCommonName("O=X, CN=Plain"));
        Assert.Null(AuthenticodeTrustGate.ExtractCommonName("O=NoCommonName"));
    }

    // ---- owner check ---------------------------------------------------------------------------------

    [Fact]
    public async Task Owner_check_required_without_an_inspector_declines_rather_than_allows()
    {
        var gate = new AuthenticodeTrustGate(new TrustGateOptions { RequireAdminOwnedImage = true }, inspector: null);
        VerdictResult r = await Run(gate, Ctx(@"C:\Windows\System32\cmd.exe", VerifiedMicrosoft()));
        Assert.Equal(Verdict.Unknown, r.Verdict);
    }

    [Fact]
    public async Task Owner_check_declines_a_user_owned_image_and_allows_a_privileged_one()
    {
        var gate = Gate(o => o.RequireAdminOwnedImage = true, inspector: new FakeOwnerInspector(privileged: false));
        Assert.Equal(Verdict.Unknown, (await Run(gate, Ctx(@"C:\Windows\System32\cmd.exe", VerifiedMicrosoft()))).Verdict);

        gate = Gate(o => o.RequireAdminOwnedImage = true, inspector: new FakeOwnerInspector(privileged: true));
        Assert.Equal(Verdict.Allow, (await Run(gate, Ctx(@"C:\Windows\System32\cmd.exe", VerifiedMicrosoft()))).Verdict);
    }

    private sealed class FakeOwnerInspector : IFileInspector
    {
        private readonly bool _privileged;
        public FakeOwnerInspector(bool privileged) => _privileged = privileged;
        public string? ComputeSha256(string path) => null;
        public long GetFileSize(string path) => -1;
        public SignerInfo ReadSigner(string path) => SignerInfo.Unsigned;
        public int ReadMotwZone(string path) => VerdictContext.NoMotw;
        public bool IsOwnedByPrivilegedAccount(string path) => _privileged;
    }
}

/// <summary>
/// End-to-end checks of <see cref="FileInspector.ReadSigner"/> against a real Microsoft-signed binary
/// (the .NET host). The critical case is the <b>borrowed signature</b>: a copy of the file with one byte
/// flipped still carries the genuine Microsoft certificate, and must be reported signed-but-invalid.
/// </summary>
public sealed class FileInspectorSignatureTests
{
    private static string? FindMicrosoftSignedExe()
    {
        // The dotnet muxer carries an embedded Microsoft signature (most System32 binaries are catalog-signed).
        foreach (string candidate in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe"),
            Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } root ? Path.Combine(root, "dotnet.exe") : string.Empty,
        })
        {
            if (candidate.Length > 0 && File.Exists(candidate))
            {
                return candidate;
            }
        }
        return null;
    }

    [Fact]
    public void A_genuine_microsoft_signed_binary_verifies_and_is_microsoft()
    {
        string? exe = FindMicrosoftSignedExe();
        if (exe is null) { return; } // environment without the .NET host at a known location

        SignerInfo s = new FileInspector().ReadSigner(exe);

        Assert.True(s.IsSigned);
        Assert.True(s.IsValid, $"WinVerifyTrust status 0x{s.VerificationStatus:X8}");
        Assert.True(s.IsMicrosoft, $"root {s.RootThumbprint} is not in the pinned Microsoft set");
        Assert.Contains("O=Microsoft Corporation", s.SubjectName, StringComparison.Ordinal); // CN is ".NET" for the muxer
        Assert.False(string.IsNullOrEmpty(s.SubjectCommonName));
        Assert.True(new FileInspector().IsOwnedByPrivilegedAccount(exe));
    }

    [Fact]
    public void A_borrowed_signature_is_signed_but_invalid_and_not_microsoft()
    {
        string? exe = FindMicrosoftSignedExe();
        if (exe is null) { return; }

        string tampered = Path.Combine(Path.GetTempPath(), "warden-borrowed-" + Guid.NewGuid().ToString("N") + ".exe");
        try
        {
            byte[] bytes = File.ReadAllBytes(exe);
            // Flip a byte in the middle of the image (code/data), leaving the certificate table at the tail intact.
            bytes[bytes.Length / 2] ^= 0xFF;
            File.WriteAllBytes(tampered, bytes);

            SignerInfo s = new FileInspector().ReadSigner(tampered);

            Assert.True(s.IsSigned);                     // the Microsoft certificate is still embedded ...
            Assert.False(s.IsValid);                     // ... but it does not verify for these bytes
            Assert.False(s.IsMicrosoft);
            Assert.False(s.IsTrustedSignature);
            Assert.Equal(unchecked((int)0x80096010), s.VerificationStatus); // TRUST_E_BAD_DIGEST
        }
        finally
        {
            try { File.Delete(tampered); } catch (IOException) { }
        }
    }

    [Fact]
    public void An_unsigned_file_is_reported_unsigned()
    {
        string tmp = Path.Combine(Path.GetTempPath(), "warden-unsigned-" + Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(tmp, new byte[] { 0x4D, 0x5A, 0, 0, 0, 0 });
            SignerInfo s = new FileInspector().ReadSigner(tmp);
            Assert.False(s.IsSigned);
            Assert.False(s.IsTrustedSignature);
        }
        finally
        {
            try { File.Delete(tmp); } catch (IOException) { }
        }
    }

    [Fact]
    public void A_user_owned_file_is_not_privileged_owned()
    {
        using var me = WindowsIdentity.GetCurrent();
        if (me.User is null || me.User.IsWellKnown(WellKnownSidType.LocalSystemSid)) { return; }

        string tmp = Path.Combine(Path.GetTempPath(), "warden-owner-" + Guid.NewGuid().ToString("N") + ".bin");
        try
        {
            File.WriteAllBytes(tmp, new byte[] { 1, 2, 3 });
            var fi = new FileInfo(tmp);
            FileSecurity acl = fi.GetAccessControl(AccessControlSections.Owner);
            acl.SetOwner(me.User);
            fi.SetAccessControl(acl);

            Assert.False(new FileInspector().IsOwnedByPrivilegedAccount(tmp));
        }
        finally
        {
            try { File.Delete(tmp); } catch (IOException) { }
        }
    }
}
