using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Warden.Wdac;

/// <summary>
/// Manages the Warden allow-list supplemental WDAC policy in C#, porting the validated deploy-script
/// logic: seed the supplemental, add an allow-by-hash (via New-CIPolicy, which computes the correct
/// Authenticode hash), link it to the active base, back up the prior version, compile, and deploy via
/// CiTool — all without a reboot. Refuses to deploy a supplemental with no base linkage.
/// </summary>
public sealed class WdacAllowlistManager : IWdacAllowlistManager
{
    private const string EmptyGuid = "{00000000-0000-0000-0000-000000000000}";

    private readonly WdacOptions _options;
    private readonly ProcessRunner _runner;
    private readonly ILogger<WdacAllowlistManager> _logger;

    public WdacAllowlistManager(WdacOptions options, ProcessRunner runner, ILogger<WdacAllowlistManager> logger)
    {
        _options = options;
        _runner = runner;
        _logger = logger;
    }

    private string SupplementalXmlPath => Path.Combine(_options.WorkDir, "WardenAllowlist.Supplemental.xml");
    private string BackupDir => Path.Combine(_options.WorkDir, "backup");

    public async Task<WdacUpdateResult> AllowAsync(WdacAllowRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            if (!File.Exists(request.ImagePath))
            {
                return WdacUpdateResult.Fail($"File not found: {request.ImagePath}");
            }

            string? baseGuid = _options.BasePolicyGuid ?? await GetActiveBasePolicyGuidAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(baseGuid) || baseGuid == EmptyGuid)
            {
                return WdacUpdateResult.Fail(
                    "No active WDAC base policy found to attach the supplemental to. Deploy the base policy first "
                    + "(scripts/Deploy-WardenSpikePolicy.ps1 in the VM).");
            }

            Directory.CreateDirectory(_options.WorkDir);
            Directory.CreateDirectory(BackupDir);
            EnsureSupplementalSeeded();

            string? backupPath = BackupCurrent();

            // Isolate the target file so New-CIPolicy hashes only it.
            string scanDir = Path.Combine(_options.WorkDir, "scan");
            ResetDirectory(scanDir);
            string scannedCopy = Path.Combine(scanDir, Path.GetFileName(request.ImagePath));
            File.Copy(request.ImagePath, scannedCopy, overwrite: true);

            string tmpHashXml = Path.Combine(_options.WorkDir, "_tmp_hash.xml");
            string mergedXml = Path.Combine(_options.WorkDir, "_tmp_merged.xml");

            string script = BuildAllowScript(SupplementalXmlPath, scanDir, tmpHashXml, mergedXml, _options.WorkDir, baseGuid);
            ProcessResult ps = await _runner.RunPowerShellAsync(script, _options.Timeout, cancellationToken).ConfigureAwait(false);
            if (!ps.Ok)
            {
                return WdacUpdateResult.Fail($"ConfigCI failed: {Trim(ps.StdErr)} {Trim(ps.StdOut)}");
            }

            string? policyId = ParseTagged(ps.StdOut, "POLICYID=");
            string? cipPath = ParseTagged(ps.StdOut, "CIP=");
            if (string.IsNullOrWhiteSpace(policyId) || string.IsNullOrWhiteSpace(cipPath) || !File.Exists(cipPath))
            {
                return WdacUpdateResult.Fail($"ConfigCI did not produce a .cip. Output: {Trim(ps.StdOut)}");
            }

            ProcessResult deploy = await _runner.RunAsync(
                _options.CiToolPath, $"--update-policy \"{cipPath}\" --json", _options.Timeout, cancellationToken)
                .ConfigureAwait(false);
            if (!deploy.Ok)
            {
                return WdacUpdateResult.Fail($"CiTool --update-policy failed (exit {deploy.ExitCode}): {Trim(deploy.StdErr)}");
            }

            string ruleAdded = request.PreferPublisher && !string.IsNullOrEmpty(request.SignerSubject)
                ? $"hash+publisher:{request.SignerSubject}"
                : $"hash:{request.Sha256}";

            _logger.LogInformation("WDAC supplemental {Policy} updated for {File}.", policyId, Path.GetFileName(request.ImagePath));
            return new WdacUpdateResult(true, ruleAdded, policyId, backupPath, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WDAC AllowAsync failed for {File}", request.ImagePath);
            return WdacUpdateResult.Fail(ex.Message);
        }
    }

    public async Task<IReadOnlyList<WdacPolicyInfo>> ListPoliciesAsync(CancellationToken cancellationToken = default)
    {
        ProcessResult res = await _runner.RunAsync(
            _options.CiToolPath, "--list-policies --json", _options.Timeout, cancellationToken).ConfigureAwait(false);
        if (!res.Ok || string.IsNullOrWhiteSpace(res.StdOut))
        {
            _logger.LogWarning("CiTool --list-policies failed (exit {Exit}): {Err}", res.ExitCode, Trim(res.StdErr));
            return Array.Empty<WdacPolicyInfo>();
        }

        var list = new List<WdacPolicyInfo>();
        try
        {
            using JsonDocument doc = JsonDocument.Parse(res.StdOut);
            if (!TryGetPoliciesArray(doc.RootElement, out JsonElement policies))
            {
                return list;
            }

            foreach (JsonElement p in policies.EnumerateArray())
            {
                string policyId = GetString(p, "PolicyID", "PolicyId") ?? string.Empty;
                string baseId = GetString(p, "BasePolicyID", "BasePolicyId") ?? string.Empty;
                string name = GetString(p, "FriendlyName", "PolicyName") ?? string.Empty;
                bool isBase = !string.IsNullOrEmpty(policyId)
                              && policyId.Equals(baseId, StringComparison.OrdinalIgnoreCase);
                bool isEnforced = GetBool(p, "IsEnforced") ?? true;
                list.Add(new WdacPolicyInfo(policyId, name, isBase, isEnforced));
            }
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Could not parse CiTool --list-policies JSON.");
        }

        return list;
    }

    public async Task<string?> GetActiveBasePolicyGuidAsync(CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrWhiteSpace(_options.BasePolicyGuid))
        {
            return _options.BasePolicyGuid;
        }

        IReadOnlyList<WdacPolicyInfo> policies = await ListPoliciesAsync(cancellationToken).ConfigureAwait(false);

        // Prefer a base whose friendly name identifies the Warden/DefaultWindows-derived policy; otherwise
        // fall back to any base policy that is not obviously a Microsoft/system one.
        WdacPolicyInfo? preferred = policies.FirstOrDefault(p =>
            p.IsBase && (p.FriendlyName.Contains("Warden", StringComparison.OrdinalIgnoreCase)
                         || p.FriendlyName.Contains("DefaultWindows", StringComparison.OrdinalIgnoreCase)));
        preferred ??= policies.FirstOrDefault(p =>
            p.IsBase && !p.FriendlyName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));

        return preferred?.PolicyGuid;
    }

    private void EnsureSupplementalSeeded()
    {
        if (!File.Exists(SupplementalXmlPath))
        {
            File.WriteAllText(SupplementalXmlPath, SupplementalTemplate, new UTF8Encoding(false));
        }
    }

    private string? BackupCurrent()
    {
        if (!File.Exists(SupplementalXmlPath))
        {
            return null;
        }
        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss");
        string dest = Path.Combine(BackupDir, $"WardenAllowlist.Supplemental_{stamp}.xml");
        File.Copy(SupplementalXmlPath, dest, overwrite: true);
        return dest;
    }

    private static string BuildAllowScript(
        string supplemental, string scanDir, string tmpHashXml, string mergedXml, string workDir, string baseGuid)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference='Stop'");
        sb.AppendLine("Import-Module ConfigCI -ErrorAction Stop");
        sb.AppendLine($"$sup = {Ps(supplemental)}");
        sb.AppendLine($"$scan = {Ps(scanDir)}");
        sb.AppendLine($"$tmp = {Ps(tmpHashXml)}");
        sb.AppendLine($"$merged = {Ps(mergedXml)}");
        sb.AppendLine("New-CIPolicy -Level Hash -ScanPath $scan -FilePath $tmp -MultiplePolicyFormat -UserPEs | Out-Null");
        sb.AppendLine("Merge-CIPolicy -PolicyPaths $sup,$tmp -OutputFilePath $merged | Out-Null");
        sb.AppendLine("Copy-Item $merged $sup -Force");
        sb.AppendLine($"Set-CIPolicyIdInfo -FilePath $sup -SupplementsBasePolicyID {Ps(baseGuid)} | Out-Null");
        sb.AppendLine("$doc = [xml](Get-Content -Raw $sup)");
        sb.AppendLine("$policyId = $doc.SiPolicy.PolicyID");
        sb.AppendLine("$baseId = $doc.SiPolicy.BasePolicyID");
        sb.AppendLine("if ([string]::IsNullOrWhiteSpace($baseId) -or $baseId -eq '{00000000-0000-0000-0000-000000000000}') { throw 'BasePolicyID not set after linkage' }");
        sb.AppendLine($"$cip = Join-Path {Ps(workDir)} ($policyId + '.cip')");
        sb.AppendLine("ConvertFrom-CIPolicy -XmlFilePath $sup -BinaryFilePath $cip | Out-Null");
        sb.AppendLine("Write-Output ('POLICYID=' + $policyId)");
        sb.AppendLine("Write-Output ('CIP=' + $cip)");
        return sb.ToString();
    }

    private static string Ps(string value) => "'" + value.Replace("'", "''") + "'";

    private static string? ParseTagged(string output, string tag)
    {
        foreach (string line in output.Split('\n'))
        {
            string t = line.Trim();
            if (t.StartsWith(tag, StringComparison.Ordinal))
            {
                return t.Substring(tag.Length).Trim();
            }
        }
        return null;
    }

    private static void ResetDirectory(string dir)
    {
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }
        Directory.CreateDirectory(dir);
    }

    private static string Trim(string s) => s.Length > 600 ? s[..600] : s;

    private static bool TryGetPoliciesArray(JsonElement root, out JsonElement policies)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            policies = root;
            return true;
        }
        foreach (string name in new[] { "Policies", "policies" })
        {
            if (root.TryGetProperty(name, out policies) && policies.ValueKind == JsonValueKind.Array)
            {
                return true;
            }
        }
        policies = default;
        return false;
    }

    private static string? GetString(JsonElement e, params string[] names)
    {
        foreach (string n in names)
        {
            if (e.TryGetProperty(n, out JsonElement v) && v.ValueKind == JsonValueKind.String)
            {
                return v.GetString();
            }
        }
        return null;
    }

    private static bool? GetBool(JsonElement e, params string[] names)
    {
        foreach (string n in names)
        {
            if (e.TryGetProperty(n, out JsonElement v) &&
                (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False))
            {
                return v.GetBoolean();
            }
        }
        return null;
    }

    // Minimal, valid supplemental (empty FileRules; New-CIPolicy/Merge populates the allow rules). The
    // fixed PolicyID keeps redeploys updating this same supplemental rather than stacking new ones.
    private const string SupplementalTemplate = """
        <?xml version="1.0" encoding="utf-8"?>
        <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Supplemental Policy">
          <VersionEx>1.0.0.0</VersionEx>
          <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
          <Rules>
            <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
            <Rule><Option>Enabled:Inherit Default Policy</Option></Rule>
          </Rules>
          <EKUs />
          <FileRules />
          <Signers />
          <SigningScenarios>
            <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Kernel Mode">
              <ProductSigners />
            </SigningScenario>
            <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode">
              <ProductSigners />
            </SigningScenario>
          </SigningScenarios>
          <UpdatePolicySigners />
          <CiSigners />
          <HvciOptions>0</HvciOptions>
          <BasePolicyID>{00000000-0000-0000-0000-000000000000}</BasePolicyID>
          <PolicyID>{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}</PolicyID>
          <Settings>
            <Setting Provider="PolicyInfo" Key="Information" ValueName="Name"><Value><String>Warden Allowlist Supplemental</String></Value></Setting>
            <Setting Provider="PolicyInfo" Key="Information" ValueName="Id"><Value><String>WardenAllowlistSupplemental</String></Value></Setting>
          </Settings>
        </SiPolicy>
        """;
}
