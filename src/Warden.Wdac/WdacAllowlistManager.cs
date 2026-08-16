using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace Warden.Wdac;

/// <summary>
/// Manages the Warden allow-list supplemental WDAC policy in C#, porting the validated deploy-script
/// logic: seed the supplemental, add an allow-by-hash (via New-CIPolicy, which computes the correct
/// Authenticode hash), link it to the active base, back up the prior version, bump the version, compile,
/// and deploy via CiTool — all without a reboot. Refuses to deploy a supplemental with no base linkage,
/// and refuses to allow-list bytes whose hash differs from the judged hash.
/// </summary>
public sealed class WdacAllowlistManager : IWdacAllowlistManager
{
    private const string EmptyGuid = "{00000000-0000-0000-0000-000000000000}";

    private readonly WdacOptions _options;
    private readonly ProcessRunner _runner;
    private readonly ILogger<WdacAllowlistManager> _logger;
    private readonly SemaphoreSlim _policyGate = new(1, 1);

    public WdacAllowlistManager(WdacOptions options, ProcessRunner runner, ILogger<WdacAllowlistManager> logger)
    {
        _options = options;
        _runner = runner;
        _logger = logger;
    }

    private string SupplementalXmlPath => Path.Combine(_options.WorkDir, "WardenAllowlist.Supplemental.xml");
    private string LedgerPath => Path.Combine(_options.WorkDir, "WardenAllowlist.Ledger.json");
    private string BackupDir => Path.Combine(_options.WorkDir, "backup");

    public async Task<WdacUpdateResult> AllowAsync(WdacAllowRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The pipeline path: the judged hash is mandatory — no hash means the file could not be hashed at
        // inspection time, and unknown bytes are never allow-listed.
        if (string.IsNullOrWhiteSpace(request.Sha256))
        {
            return WdacUpdateResult.Fail("No judged hash supplied; refusing to allow-list unverified bytes.");
        }

        WdacBatchResult batch = await AllowManyAsync(
            new[] { new WdacAllowFile(request.ImagePath, request.Sha256) }, cancellationToken).ConfigureAwait(false);

        WdacFileAllowResult? file = batch.Files.Count > 0 ? batch.Files[0] : null;
        if (!batch.Success)
        {
            return WdacUpdateResult.Fail(batch.Error ?? file?.Error ?? "WDAC allow failed.");
        }
        if (file is null || !file.Success)
        {
            return WdacUpdateResult.Fail(file?.Error ?? "WDAC allow failed.");
        }

        return new WdacUpdateResult(true, $"hash:{request.Sha256}", batch.PolicyGuid, batch.BackupPath, null);
    }

    /// <summary>Largest file that is allow-listed (copied for scanning) — an administrator's click must not copy gigabytes.</summary>
    private const long MaxAllowFileBytes = 256L * 1024 * 1024;

    public async Task<WdacBatchResult> AllowManyAsync(IReadOnlyList<WdacAllowFile> files, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        if (files.Count == 0)
        {
            return new WdacBatchResult(true, string.Empty, Array.Empty<WdacFileAllowResult>(), null, null);
        }

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string? baseGuid = _options.BasePolicyGuid ?? await GetActiveBasePolicyGuidAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(baseGuid) || baseGuid == EmptyGuid || !Guid.TryParseExact(baseGuid.Trim('{', '}'), "D", out _))
            {
                return Fail(files,
                    "No valid active WDAC base policy found to attach the supplemental to. Deploy the base policy first "
                    + "(scripts/Deploy-WardenSpikePolicy.ps1 in the VM), or set WARDEN_WDAC_BASE_POLICY_GUID.");
            }

            Directory.CreateDirectory(_options.WorkDir);
            Directory.CreateDirectory(BackupDir);
            EnsureSupplementalSeeded();
            string? backupPath = BackupCurrent();

            // Isolate the files so New-CIPolicy hashes only them. Each goes into its own numbered subfolder
            // (same-named files must not collide) and the copy is what gets allow-listed, so a caller that
            // supplied the judged hash gets a byte-for-byte check against a swap between judgement and
            // deployment; an administrator's explicit choice is hashed as found and reported back.
            string scanDir = Path.Combine(_options.WorkDir, "scan");
            ResetDirectory(scanDir);

            var results = new WdacFileAllowResult[files.Count];
            var copies = new List<(int Index, string Copy, string Sha)>();
            for (int i = 0; i < files.Count; i++)
            {
                WdacAllowFile f = files[i];
                string? error = null;
                string? sha = null;
                try
                {
                    if (string.IsNullOrWhiteSpace(f.Path) || !File.Exists(f.Path))
                    {
                        error = "File not found.";
                    }
                    else if (IsReparsePoint(f.Path))
                    {
                        error = "Refusing to allow-list through a reparse point (symlink/junction).";
                    }
                    else if (new FileInfo(f.Path).Length > MaxAllowFileBytes)
                    {
                        error = "File is larger than the allow-list size cap.";
                    }
                    else
                    {
                        string sub = Path.Combine(scanDir, i.ToString("D4", CultureInfo.InvariantCulture));
                        Directory.CreateDirectory(sub);
                        string copy = Path.Combine(sub, Path.GetFileName(f.Path));
                        File.Copy(f.Path, copy, overwrite: true);
                        sha = ComputeSha256(copy);
                        if (!string.IsNullOrWhiteSpace(f.ExpectedSha256)
                            && !string.Equals(sha, f.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                        {
                            _logger.LogError(
                                "WDAC allow refused for {File}: file changed since it was judged (judged {Judged}, found {Found}).",
                                Path.GetFileName(f.Path), f.ExpectedSha256, sha);
                            error = "The file's bytes differ from the ones that were judged/recorded; not allow-listed.";
                            Directory.Delete(sub, recursive: true);
                        }
                        else
                        {
                            copies.Add((i, copy, sha));
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    error = ex.Message;
                }

                results[i] = new WdacFileAllowResult(f.Path, sha, error is null, error);
            }

            if (copies.Count == 0)
            {
                return new WdacBatchResult(false, string.Empty, results, backupPath, "No file could be allow-listed.");
            }

            // Snapshot the rule set so the ledger can record exactly which rules this batch adds.
            IReadOnlySet<string> before = SupplementalPolicyXml.AllowRuleIds(LoadXml(SupplementalXmlPath));

            string tmpHashXml = Path.Combine(_options.WorkDir, "_tmp_hash.xml");
            string mergedXml = Path.Combine(_options.WorkDir, "_tmp_merged.xml");
            string mergeScript = BuildMergeScript(SupplementalXmlPath, scanDir, tmpHashXml, mergedXml, baseGuid);
            ProcessResult ps = await _runner.RunPowerShellAsync(mergeScript, _options.Timeout, cancellationToken).ConfigureAwait(false);
            if (!ps.Ok)
            {
                return Fail(files, $"ConfigCI failed: {Trim(ps.StdErr)} {Trim(ps.StdOut)}", results);
            }

            XDocument doc = LoadXml(SupplementalXmlPath);
            string? linkedBase = SupplementalPolicyXml.BasePolicyId(doc);
            if (string.IsNullOrWhiteSpace(linkedBase) || linkedBase == EmptyGuid)
            {
                return Fail(files, "BasePolicyID not set after linkage; refusing to compile an inert supplemental.", results);
            }

            // Attribute the new rules to files: New-CIPolicy names each hash rule "<scanned path> Hash …",
            // and every scanned copy sits in its own folder, so the copy path is a unique prefix.
            IReadOnlySet<string> after = SupplementalPolicyXml.AllowRuleIds(doc);
            var added = new HashSet<string>(after.Where(id => !before.Contains(id)), StringComparer.OrdinalIgnoreCase);
            AllowRuleLedger ledger = AllowRuleLedger.Load(LedgerPath);
            foreach ((int index, string copy, string sha) in copies)
            {
                var mine = SupplementalPolicyXml.AllowRuleIdsByFriendlyNamePrefix(doc, copy).Where(added.Contains).ToList();
                ledger.Record(sha.ToUpperInvariant(), mine);
                if (mine.Count == 0)
                {
                    _logger.LogWarning("No hash rules were generated for {File}; it may not be a PE image.", results[index].Path);
                    results[index] = results[index] with { Success = false, Error = "ConfigCI produced no rules for this file (not a PE image?)." };
                }
            }
            string version = SupplementalPolicyXml.BumpVersion(doc);
            SaveXml(doc, SupplementalXmlPath);
            ledger.Save(LedgerPath);

            WdacUpdateResult deploy = await CompileAndDeployAsync(cancellationToken).ConfigureAwait(false);
            if (!deploy.Success)
            {
                return Fail(files, deploy.Error ?? "Deployment failed.", results);
            }

            _logger.LogInformation(
                "WDAC supplemental {Policy} v{Version} updated: +{Rules} rules for {Files} file(s).",
                deploy.PolicyGuid, version, added.Count, copies.Count);
            return new WdacBatchResult(true, deploy.PolicyGuid, results, backupPath, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WDAC AllowManyAsync failed.");
            return Fail(files, ex.Message);
        }
        finally
        {
            _policyGate.Release();
        }

        static WdacBatchResult Fail(IReadOnlyList<WdacAllowFile> files, string error, WdacFileAllowResult[]? partial = null)
        {
            WdacFileAllowResult[] rows = partial is not null
                ? partial.Select(r => r.Success ? r with { Success = false, Error = error } : r).ToArray()
                : files.Select(f => new WdacFileAllowResult(f.Path, null, false, error)).ToArray();
            return new WdacBatchResult(false, string.Empty, rows, null, error);
        }
    }

    public async Task<WdacUpdateResult> RevokeAsync(string sha256, string? imageName = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);
        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(SupplementalXmlPath))
            {
                // Nothing was ever allowed: the OS already blocks it.
                return new WdacUpdateResult(true, "none", string.Empty, null, null);
            }

            Directory.CreateDirectory(BackupDir);
            string? backupPath = BackupCurrent();

            XDocument doc = LoadXml(SupplementalXmlPath);
            AllowRuleLedger ledger = AllowRuleLedger.Load(LedgerPath);
            string key = sha256.ToUpperInvariant();

            var ids = new HashSet<string>(ledger.RulesFor(key), StringComparer.OrdinalIgnoreCase);
            if (ids.Count == 0 && !string.IsNullOrWhiteSpace(imageName))
            {
                // Rules recorded before the ledger existed: New-CIPolicy named them "<scan path> Hash …".
                // Over-matching here only ever removes allows (fail-safe), never adds one.
                foreach (string id in SupplementalPolicyXml.AllowRuleIdsByScannedFileName(doc, Path.GetFileName(imageName), Path.Combine(_options.WorkDir, "scan")))
                {
                    ids.Add(id);
                }
            }

            if (ids.Count == 0)
            {
                ledger.Remove(key);
                ledger.Save(LedgerPath);
                return new WdacUpdateResult(true, "none", SupplementalPolicyXml.PolicyId(doc) ?? string.Empty, backupPath, null);
            }

            int removed = SupplementalPolicyXml.RemoveAllowRules(doc, ids);
            string version = SupplementalPolicyXml.BumpVersion(doc);
            SaveXml(doc, SupplementalXmlPath);
            ledger.Remove(key);
            ledger.Save(LedgerPath);

            WdacUpdateResult deploy = await CompileAndDeployAsync(cancellationToken).ConfigureAwait(false);
            if (!deploy.Success)
            {
                return deploy;
            }

            _logger.LogInformation(
                "WDAC supplemental {Policy} v{Version}: revoked {Sha} (-{Rules} rules).", deploy.PolicyGuid, version, key, removed);
            return new WdacUpdateResult(true, $"revoked:{key}", deploy.PolicyGuid, backupPath, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WDAC RevokeAsync failed for {Sha}", sha256);
            return WdacUpdateResult.Fail(ex.Message);
        }
        finally
        {
            _policyGate.Release();
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

    // ---- compile + deploy (shared by allow and revoke) ---------------------------------------------

    private async Task<WdacUpdateResult> CompileAndDeployAsync(CancellationToken cancellationToken)
    {
        string script = BuildCompileScript(SupplementalXmlPath, _options.WorkDir);
        ProcessResult ps = await _runner.RunPowerShellAsync(script, _options.Timeout, cancellationToken).ConfigureAwait(false);
        if (!ps.Ok)
        {
            return WdacUpdateResult.Fail($"ConfigCI compile failed: {Trim(ps.StdErr)} {Trim(ps.StdOut)}");
        }

        string? policyId = ParseTagged(ps.StdOut, "POLICYID=");
        string? cipPath = ParseTagged(ps.StdOut, "CIP=");
        if (string.IsNullOrWhiteSpace(policyId) || string.IsNullOrWhiteSpace(cipPath))
        {
            return WdacUpdateResult.Fail($"ConfigCI did not produce a .cip. Output: {Trim(ps.StdOut)}");
        }

        // The .cip must be the one we asked for, inside our work dir — never a path echoed by something else.
        string fullCip;
        try
        {
            fullCip = Path.GetFullPath(cipPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return WdacUpdateResult.Fail("ConfigCI reported an invalid .cip path.");
        }
        string workRoot = Path.GetFullPath(_options.WorkDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!fullCip.StartsWith(workRoot, StringComparison.OrdinalIgnoreCase) || !File.Exists(fullCip) || fullCip.Contains('"', StringComparison.Ordinal))
        {
            return WdacUpdateResult.Fail("ConfigCI reported a .cip outside the work directory; refusing to deploy it.");
        }

        ProcessResult deploy = await _runner.RunAsync(
            _options.CiToolPath, $"--update-policy \"{fullCip}\" --json", _options.Timeout, cancellationToken)
            .ConfigureAwait(false);
        if (!deploy.Ok)
        {
            return WdacUpdateResult.Fail($"CiTool --update-policy failed (exit {deploy.ExitCode}): {Trim(deploy.StdErr)}");
        }

        return new WdacUpdateResult(true, string.Empty, policyId, null, null);
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
        // Millisecond stamp so two changes in the same second do not overwrite one backup.
        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss_fff", CultureInfo.InvariantCulture);
        string dest = Path.Combine(BackupDir, $"WardenAllowlist.Supplemental_{stamp}.xml");
        File.Copy(SupplementalXmlPath, dest, overwrite: true);
        return dest;
    }

    /// <summary>Step 1: hash the scan dir, merge into the supplemental, link the base. Nothing is compiled here.</summary>
    private static string BuildMergeScript(string supplemental, string scanDir, string tmpHashXml, string mergedXml, string baseGuid)
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
        sb.AppendLine($"Set-CIPolicyIdInfo -FilePath $merged -SupplementsBasePolicyID {Ps(baseGuid)} | Out-Null");
        // Only replace the live supplemental once the merged file is fully linked, so a failure between
        // steps never leaves a merged-but-unlinked file behind.
        sb.AppendLine("Copy-Item -LiteralPath $merged -Destination $sup -Force");
        return sb.ToString();
    }

    /// <summary>Step 2: compile the (already version-bumped, linked) supplemental to a .cip and report its path.</summary>
    private static string BuildCompileScript(string supplemental, string workDir)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference='Stop'");
        sb.AppendLine("Import-Module ConfigCI -ErrorAction Stop");
        sb.AppendLine($"$sup = {Ps(supplemental)}");
        sb.AppendLine("$doc = [xml](Get-Content -Raw -LiteralPath $sup)");
        sb.AppendLine("$policyId = $doc.SiPolicy.PolicyID");
        sb.AppendLine("$baseId = $doc.SiPolicy.BasePolicyID");
        sb.AppendLine("if ([string]::IsNullOrWhiteSpace($baseId) -or $baseId -eq '{00000000-0000-0000-0000-000000000000}') { throw 'BasePolicyID not set after linkage' }");
        sb.AppendLine($"$cip = Join-Path {Ps(workDir)} ($policyId + '.cip')");
        sb.AppendLine("ConvertFrom-CIPolicy -XmlFilePath $sup -BinaryFilePath $cip | Out-Null");
        sb.AppendLine("Write-Output ('POLICYID=' + $policyId)");
        sb.AppendLine("Write-Output ('CIP=' + $cip)");
        return sb.ToString();
    }

    /// <summary>Single-quoted PowerShell literal with the only escape that matters inside it (' → '').</summary>
    public static string Ps(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
    }

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

    private static bool IsReparsePoint(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (IOException) { return true; }
        catch (UnauthorizedAccessException) { return true; }
    }

    private static string ComputeSha256(string path)
    {
        using FileStream fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    private static XDocument LoadXml(string path) => XDocument.Load(path, LoadOptions.PreserveWhitespace);

    private static void SaveXml(XDocument doc, string path)
    {
        string tmp = path + ".tmp";
        doc.Save(tmp);
        File.Move(tmp, path, overwrite: true);
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
