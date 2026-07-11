using System.Collections.Immutable;
using Warden.AntiExploit;
using Warden.Firewall;
using Warden.WebApps;

namespace Warden.Tests.Windows;

/// <summary>
/// Pure-logic tests for the Phase 5 engines: the web-app scorer, the vulnerable-app seeder, the ASR
/// command builder, the Exploit Protection XML builder, the firewall rule specs, and the IFEO key path.
/// None of these touch the real system (no registry writes, no COM, no PowerShell) — the system-mutating
/// appliers are exercised only in the VM.
/// </summary>
public sealed class Phase5LogicTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.UnixEpoch;

    private static WebAppStaticInput Static(
        string[]? imports = null, string[]? siblings = null, string? originalFilename = null,
        string? productName = null, bool httpHandler = false, int otherSchemes = 0) =>
        new(
            "app.exe",
            (imports ?? Array.Empty<string>()).ToImmutableArray(),
            (siblings ?? Array.Empty<string>()).ToImmutableArray(),
            originalFilename,
            productName,
            httpHandler,
            otherSchemes);

    // ---- Web-app scorer ---------------------------------------------------------------------------

    [Fact]
    public void Electron_ships_asar_pak_icu_is_web_facing()
    {
        var input = Static(siblings: new[] { "app.asar", "chrome_100_percent.pak", "icudtl.dat", "ffmpeg.dll" });
        WebAppClassification c = WebAppScorer.ClassifyStatic(@"C:\Apps\Claude.exe", input, T0);

        Assert.True(c.IsWebFacing);
        Assert.Equal(WebAppEngine.Electron, c.Engine);
        Assert.True(c.StaticScore >= 100);
    }

    [Fact]
    public void WebView2_loader_import_is_web_facing()
    {
        WebAppClassification c = WebAppScorer.ClassifyStatic(@"C:\Apps\App.exe", Static(imports: new[] { "webview2loader.dll" }), T0);
        Assert.True(c.IsWebFacing);
        Assert.Equal(WebAppEngine.WebView2, c.Engine);
    }

    [Fact]
    public void Cef_libcef_import_is_web_facing()
    {
        WebAppClassification c = WebAppScorer.ClassifyStatic(@"C:\Apps\App.exe", Static(imports: new[] { "libcef.dll" }), T0);
        Assert.True(c.IsWebFacing);
        Assert.Equal(WebAppEngine.Cef, c.Engine);
    }

    [Fact]
    public void Registered_http_handler_is_web_facing()
    {
        WebAppClassification c = WebAppScorer.ClassifyStatic(@"C:\Apps\browser.exe", Static(httpHandler: true), T0);
        Assert.True(c.IsWebFacing); // +90 reaches the threshold
    }

    [Fact]
    public void Urlmon_alone_is_not_web_facing()
    {
        // urlmon.dll is imported by many non-browser apps — a single 60-point signal must not cross 90.
        WebAppClassification c = WebAppScorer.ClassifyStatic(@"C:\Apps\updater.exe", Static(imports: new[] { "urlmon.dll" }), T0);
        Assert.False(c.IsWebFacing);
    }

    [Fact]
    public void Plain_native_exe_is_not_web_facing()
    {
        var input = Static(imports: new[] { "kernel32.dll", "user32.dll" }, siblings: new[] { "config.ini" });
        WebAppClassification c = WebAppScorer.ClassifyStatic(@"C:\Apps\tool.exe", input, T0);

        Assert.False(c.IsWebFacing);
        Assert.Equal(WebAppEngine.None, c.Engine);
        Assert.Equal(0, c.StaticScore);
    }

    [Fact]
    public void Runtime_confirmation_upgrades_a_borderline_app()
    {
        var staticInput = Static(imports: new[] { "urlmon.dll" }); // 60, below threshold
        var runtime = new WebAppRuntimeInput(
            ChildImageNames: ImmutableArray.Create("msedgewebview2.exe"),
            HasRendererChild: false,
            HasEbWebViewFolder: true,
            LoadedModuleNames: ImmutableArray<string>.Empty);

        WebAppClassification c = WebAppScorer.ClassifyWithRuntime(@"C:\Apps\App.exe", staticInput, runtime, T0);

        Assert.True(c.IsWebFacing);              // 60 + 80 + 60 = 200
        Assert.True(c.RuntimeScore >= 140);
        Assert.Equal(WebAppEngine.WebView2, c.Engine);
    }

    // ---- Vulnerable-app seeder --------------------------------------------------------------------

    [Fact]
    public void Seeder_tags_entry_points_and_lolbins()
    {
        var seed = VulnerableAppSeeder.Seed();

        Assert.Contains(seed, a => a.FileName == "winword.exe" && a.Reason == VulnerableAppReason.InternetFacing);
        Assert.Contains(seed, a => a.FileName == "mshta.exe" && a.Reason == VulnerableAppReason.Lolbin);
        Assert.Contains(seed, a => a.FileName == "vssadmin.exe" && a.Reason == VulnerableAppReason.Lolbin);
        Assert.All(seed, a => Assert.False(string.IsNullOrWhiteSpace(a.FileName)));
        Assert.Equal("internet-facing", VulnerableAppSeeder.ReasonToString(VulnerableAppReason.InternetFacing));
        Assert.Equal("lolbin", VulnerableAppSeeder.ReasonToString(VulnerableAppReason.Lolbin));
    }

    // ---- ASR command builder ----------------------------------------------------------------------

    [Fact]
    public void Asr_build_script_defaults_to_audit_mode()
    {
        var rules = new[] { AsrRules.BlockLsassCredentialTheft, AsrRules.BlockOfficeChildProcesses };
        string script = AsrRuleManager.BuildApplyScript(rules, AsrAction.AuditMode);

        Assert.Contains("Add-MpPreference", script, StringComparison.Ordinal);
        Assert.Contains(AsrRules.BlockLsassCredentialTheft.Guid, script, StringComparison.Ordinal);
        Assert.Contains("AuditMode,AuditMode", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Asr_build_script_is_empty_for_no_rules()
    {
        Assert.Equal(string.Empty, AsrRuleManager.BuildApplyScript(Array.Empty<AsrRule>(), AsrAction.Enabled));
    }

    [Fact]
    public void Asr_action_keywords_map_correctly()
    {
        Assert.Equal("Enabled", AsrRules.ToActionKeyword(AsrAction.Enabled));
        Assert.Equal("AuditMode", AsrRules.ToActionKeyword(AsrAction.AuditMode));
        Assert.Equal("Disabled", AsrRules.ToActionKeyword(AsrAction.Disabled));
        Assert.Equal("Warn", AsrRules.ToActionKeyword(AsrAction.Warn));
    }

    // ---- Exploit Protection XML builder -----------------------------------------------------------

    [Fact]
    public void Exploit_protection_default_profile_is_conservative_and_audit_first()
    {
        var profile = ExploitProtectionProfile.DefaultFor(VulnerableAppReason.InternetFacing);
        string xml = ExploitProtectionPolicyBuilder.BuildXml("winword.exe", profile);

        Assert.Contains("Executable=\"winword.exe\"", xml, StringComparison.Ordinal);
        Assert.Contains("<DEP", xml, StringComparison.Ordinal);
        Assert.Contains("<ControlFlowGuard", xml, StringComparison.Ordinal);
        Assert.Contains("<UserShadowStack", xml, StringComparison.Ordinal);
        // App-breaking mitigations are opt-in and off by default.
        Assert.DoesNotContain("<ChildProcess", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("<BlockNonMicrosoftBinaries", xml, StringComparison.Ordinal);
        // Audit-first: the audit-capable mitigations are in audit mode.
        Assert.Contains("Audit=\"true\"", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void Exploit_protection_child_blocking_is_emitted_when_enabled()
    {
        var profile = new ExploitProtectionProfile { DisallowChildProcessCreation = true, Audit = false };
        string xml = ExploitProtectionPolicyBuilder.BuildXml("acrord32.exe", profile);

        Assert.Contains("DisallowChildProcessCreation=\"true\"", xml, StringComparison.Ordinal);
        Assert.Contains("Audit=\"false\"", xml, StringComparison.Ordinal);
    }

    // ---- Firewall rule specs ----------------------------------------------------------------------

    [Fact]
    public void Firewall_block_both_makes_one_inbound_and_one_outbound_rule()
    {
        var specs = FirewallRuleSpecs.BlockBoth(@"C:\Apps\chrome.exe");

        Assert.Equal(2, specs.Length);
        Assert.Contains(specs, s => s.Direction == FirewallDirection.Inbound && s.RuleName == "Warden Block IN: chrome.exe");
        Assert.Contains(specs, s => s.Direction == FirewallDirection.Outbound && s.RuleName == "Warden Block OUT: chrome.exe");
        Assert.All(specs, s => Assert.Equal(@"C:\Apps\chrome.exe", s.AppPath));
        Assert.Equal("inbound", FirewallRuleSpecs.DirectionToString(FirewallDirection.Inbound));
        Assert.Equal("outbound", FirewallRuleSpecs.DirectionToString(FirewallDirection.Outbound));
    }

    // ---- IFEO key path validation -----------------------------------------------------------------

    [Fact]
    public void Ifeo_key_path_accepts_a_bare_exe_name()
    {
        string path = IfeoWriter.KeyPath("winword.exe");
        Assert.EndsWith(@"Image File Execution Options\winword.exe", path, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"C:\evil\winword.exe")]
    [InlineData(@"..\winword.exe")]
    [InlineData("sub/dir.exe")]
    [InlineData("")]
    public void Ifeo_key_path_rejects_non_bare_names(string bad)
    {
        Assert.Throws<ArgumentException>(() => IfeoWriter.KeyPath(bad));
    }
}
