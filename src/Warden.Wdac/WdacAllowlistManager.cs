using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace Warden.Wdac;

/// <summary>
/// Manages the Warden allow-list supplemental WDAC policy: add an allow-by-hash (via New-CIPolicy, which
/// computes the Authenticode hashes), link it to the active base, bump the version, compile, and deploy via
/// CiTool, all without a reboot.
/// </summary>
/// <remarks>
/// <para><b>Transactional.</b> Every change is built in staging files next to the live ones. The live
/// supplemental XML and the rule ledger are replaced only after CiTool has deployed the staged policy, so
/// a failed allow never sits in the live XML waiting for the next successful deploy (M1). If promoting the
/// staged files fails after the deploy, the previous XML and ledger are put back and the previous policy is
/// redeployed with a higher version.</para>
/// <para><b>Validated.</b> The supplemental on disk and every policy about to be compiled must pass
/// <see cref="SupplementalPolicyValidator"/>: Warden's own PolicyID, linked to the expected base, hash
/// Allow rules only (H4). A merged policy may only add the hashes of the files this call scanned, and the
/// scanned copies are re-hashed after New-CIPolicy so a copy swapped while ConfigCI ran is refused.</para>
/// <para><b>Revoke by hash.</b> The ledger records each file's rule <c>Hash=</c> values (rule IDs can be
/// renumbered by Merge-CIPolicy). A revoke that finds nothing to remove for a ledger entry fails instead
/// of reporting success.</para>
/// </remarks>
public sealed class WdacAllowlistManager : IWdacAllowlistManager
{
    /// <summary>The fixed PolicyID of the Warden allow-list supplemental. Redeploys update this one policy.</summary>
    public const string SupplementalPolicyId = "{7A4D1C0A-5B2E-4F6A-9C3D-000000000001}";

    private const string EmptyGuid = "{00000000-0000-0000-0000-000000000000}";

    /// <summary>Largest file that is allow-listed (copied for scanning): an administrator's click must not copy gigabytes.</summary>
    private const long MaxAllowFileBytes = 256L * 1024 * 1024;

    private readonly WdacOptions _options;
    private readonly IWdacPolicyTools _tools;
    private readonly ILogger<WdacAllowlistManager> _logger;
    private readonly SemaphoreSlim _policyGate = new(1, 1);

    public WdacAllowlistManager(WdacOptions options, IWdacPolicyTools tools, ILogger<WdacAllowlistManager> logger)
    {
        _options = options;
        _tools = tools;
        _logger = logger;
    }

    private string SupplementalXmlPath => Path.Combine(_options.WorkDir, "WardenAllowlist.Supplemental.xml");
    private string LedgerPath => Path.Combine(_options.WorkDir, "WardenAllowlist.Ledger.json");
    private string BackupDir => Path.Combine(_options.WorkDir, "backup");
    private string StagedXmlPath => Path.Combine(_options.WorkDir, "_staged.Supplemental.xml");
    private string StagedLedgerPath => Path.Combine(_options.WorkDir, "_staged.Ledger.json");
    private string RollbackXmlPath => Path.Combine(_options.WorkDir, "_rollback.Supplemental.xml");
    private string CipPath => Path.Combine(_options.WorkDir, SupplementalPolicyId + ".cip");

    public async Task<WdacUpdateResult> AllowAsync(WdacAllowRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The pipeline path: the judged hash is mandatory. No hash means the file could not be hashed at
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

    public async Task<WdacBatchResult> AllowManyAsync(IReadOnlyList<WdacAllowFile> files, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        if (files.Count == 0)
        {
            return new WdacBatchResult(true, string.Empty, Array.Empty<WdacFileAllowResult>(), null, null);
        }

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string stagedInput = Path.Combine(_options.WorkDir, "_stage_input.xml");
        string tmpHashXml = Path.Combine(_options.WorkDir, "_tmp_hash.xml");
        string mergedXml = Path.Combine(_options.WorkDir, "_tmp_merged.xml");
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

            // The state everything is built on, checked before it is used: a planted or edited supplemental
            // is refused here, never merged and deployed.
            if (!TrySnapshot(out Snapshot previous, out string? snapError))
            {
                return Fail(files, snapError!);
            }
            AllowRuleLedger ledger = previous.Ledger;
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

            // ConfigCI works on a staged copy of the validated current policy; the live XML is not touched.
            DeleteIfExists(tmpHashXml);
            DeleteIfExists(mergedXml);
            SaveXml(previous.Doc, stagedInput);
            ProcessResult ps = await _tools.BuildMergedAsync(stagedInput, scanDir, tmpHashXml, mergedXml, baseGuid, cancellationToken).ConfigureAwait(false);
            if (!ps.Ok)
            {
                return Fail(files, $"ConfigCI failed: {Trim(ps.StdErr)} {Trim(ps.StdOut)}", results);
            }

            // The rules New-CIPolicy produced must describe the bytes that were checked above: a scan copy
            // swapped while ConfigCI ran would otherwise be allow-listed under the checked hash's name.
            foreach ((int index, string copy, string sha) in copies)
            {
                string? now = File.Exists(copy) ? ComputeSha256(copy) : null;
                if (!string.Equals(now, sha, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError(
                        "WDAC allow refused: the scan copy of {File} changed while ConfigCI hashed it (checked {Checked}, now {Now}).",
                        results[index].Path, sha, now ?? "(missing)");
                    return Fail(files, "A scanned copy changed while ConfigCI was hashing it; nothing was deployed.", results);
                }
            }

            if (!File.Exists(tmpHashXml) || !File.Exists(mergedXml))
            {
                return Fail(files, "ConfigCI did not produce the merged policy.", results);
            }
            XDocument hashDoc = LoadXml(tmpHashXml);
            XDocument merged = LoadXml(mergedXml);

            // Attribute the new rules to files by hash value. New-CIPolicy names each hash rule
            // "<scanned path> Hash …" and the hash-only policy holds just this batch, so the copy path is a
            // unique prefix there; rule IDs are not used because Merge-CIPolicy may renumber them.
            IReadOnlySet<string> beforeHashes = SupplementalPolicyXml.AllowRuleHashes(previous.Doc);
            IReadOnlySet<string> mergedHashes = SupplementalPolicyXml.AllowRuleHashes(merged);
            var ours = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach ((int index, string copy, string sha) in copies)
            {
                IReadOnlySet<string> mine = SupplementalPolicyXml.AllowRuleHashesForScannedFile(hashDoc, copy);
                if (mine.Count == 0)
                {
                    _logger.LogWarning("No hash rules were generated for {File}; it may not be a PE image.", results[index].Path);
                    results[index] = results[index] with { Success = false, Error = "ConfigCI produced no rules for this file (not a PE image?)." };
                    continue;
                }
                if (!mine.All(mergedHashes.Contains))
                {
                    return Fail(files, "The merged policy is missing rules ConfigCI generated; nothing was deployed.", results);
                }
                ledger.RecordHashes(sha.ToUpperInvariant(), mine);
                ours.UnionWith(mine);
            }

            var unexpected = mergedHashes.Where(h => !beforeHashes.Contains(h) && !ours.Contains(h)).ToList();
            if (unexpected.Count > 0)
            {
                _logger.LogError(
                    "WDAC allow refused: the merged policy carries {Count} allow hash(es) that no requested file produced (first: {Hash}).",
                    unexpected.Count, unexpected[0]);
                return Fail(files, "The merged policy allows hashes no requested file produced; nothing was deployed.", results);
            }

            if (ours.Count == 0)
            {
                return new WdacBatchResult(false, string.Empty, results, backupPath, "ConfigCI produced no rules for any file; nothing was deployed.");
            }

            string version = SupplementalPolicyXml.BumpVersion(merged);
            string? commitError = await CommitAsync(merged, ledger, previous, baseGuid, cancellationToken).ConfigureAwait(false);
            if (commitError is not null)
            {
                return Fail(files, commitError, results);
            }

            _logger.LogInformation(
                "WDAC supplemental {Policy} v{Version} updated: +{Rules} hash rule(s) for {Files} file(s).",
                SupplementalPolicyId, version, ours.Count(h => !beforeHashes.Contains(h)), results.Count(r => r.Success));
            return new WdacBatchResult(true, SupplementalPolicyId, results, backupPath, null);
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
            DeleteQuietly(stagedInput);
            DeleteQuietly(tmpHashXml);
            DeleteQuietly(mergedXml);
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
            string key = sha256.ToUpperInvariant();
            if (!File.Exists(SupplementalXmlPath))
            {
                if (!AllowRuleLedger.TryLoad(LedgerPath, out AllowRuleLedger orphan, out string? ledgerError))
                {
                    return WdacUpdateResult.Fail($"The rule ledger is unreadable ({ledgerError}); cannot tell whether {key} is allowed.");
                }
                if (orphan.HasEntry(key))
                {
                    _logger.LogError("WDAC revoke of {Sha}: the ledger records rules but the supplemental XML is missing.", key);
                    return WdacUpdateResult.Fail("The ledger records an allow for this file but the supplemental policy file is missing; cannot revoke it.");
                }
                // Nothing was ever allowed: the OS already blocks it.
                return new WdacUpdateResult(true, "none", string.Empty, null, null);
            }

            if (!TrySnapshot(out Snapshot previous, out string? snapError))
            {
                return WdacUpdateResult.Fail(snapError!);
            }

            XDocument doc = new(previous.Doc);
            AllowRuleLedger ledger = previous.Ledger;
            string? linkedBase = SupplementalPolicyXml.BasePolicyId(doc);

            IReadOnlyCollection<string> recordedHashes = ledger.HashesFor(key);
            IReadOnlyCollection<string> legacyIds = ledger.LegacyRuleIdsFor(key);
            bool hadEntries = recordedHashes.Count > 0 || legacyIds.Count > 0;

            var targetHashes = new HashSet<string>(recordedHashes, StringComparer.OrdinalIgnoreCase);
            // Legacy ledgers recorded rule IDs; resolve them to the hashes they carry now. Over-matching only
            // ever removes allows.
            targetHashes.UnionWith(SupplementalPolicyXml.AllowRuleHashesById(doc, legacyIds));
            if ((legacyIds.Count > 0 || !hadEntries) && !string.IsNullOrWhiteSpace(imageName))
            {
                // Rules recorded before the hash ledger (or before any ledger): New-CIPolicy named them
                // "<scan path> Hash …". Also used when legacy IDs were renumbered away.
                IReadOnlySet<string> byName = SupplementalPolicyXml.AllowRuleIdsByScannedFileName(
                    doc, Path.GetFileName(imageName), Path.Combine(_options.WorkDir, "scan"));
                targetHashes.UnionWith(SupplementalPolicyXml.AllowRuleHashesById(doc, byName));
            }

            IReadOnlySet<string> ids = SupplementalPolicyXml.AllowRuleIdsByHash(doc, targetHashes);
            if (ids.Count == 0)
            {
                if (hadEntries)
                {
                    _logger.LogError(
                        "WDAC revoke of {Sha} failed: the ledger records {Hashes} hash(es) / {Ids} legacy ID(s) but no matching rule is in the policy.",
                        key, recordedHashes.Count, legacyIds.Count);
                    return WdacUpdateResult.Fail(
                        "The ledger records an allow for this file, but none of its rules were found in the supplemental policy; the allow could not be confirmed removed.");
                }
                return new WdacUpdateResult(true, "none", SupplementalPolicyXml.PolicyId(doc) ?? string.Empty, null, null);
            }

            string? backupPath = BackupCurrent();
            int removed = SupplementalPolicyXml.RemoveAllowRules(doc, ids);
            if (removed == 0 || SupplementalPolicyXml.AllowRuleIdsByHash(doc, targetHashes).Count > 0)
            {
                return WdacUpdateResult.Fail("An allow rule for this file is still in the policy after removal; nothing was deployed.");
            }

            ledger.Remove(key);
            string version = SupplementalPolicyXml.BumpVersion(doc);
            string? commitError = await CommitAsync(doc, ledger, previous, linkedBase ?? string.Empty, cancellationToken).ConfigureAwait(false);
            if (commitError is not null)
            {
                return WdacUpdateResult.Fail(commitError);
            }

            _logger.LogInformation(
                "WDAC supplemental {Policy} v{Version}: revoked {Sha} (-{Rules} rules).", SupplementalPolicyId, version, key, removed);
            return new WdacUpdateResult(true, $"revoked:{key}", SupplementalPolicyId, backupPath, null);
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
        ProcessResult res = await _tools.ListPoliciesAsync(cancellationToken).ConfigureAwait(false);
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

    // ---- transaction ------------------------------------------------------------------------------

    /// <summary>The live state a change starts from, kept so it can be put back.</summary>
    private sealed record Snapshot(XDocument Doc, AllowRuleLedger Ledger, byte[]? XmlBytes);

    /// <summary>
    /// Reads and validates the live supplemental (the seed template when there is none) and the ledger.
    /// False, with a logged reason, when either is not something Warden wrote.
    /// </summary>
    private bool TrySnapshot(out Snapshot snapshot, out string? error)
    {
        snapshot = null!;
        byte[]? xmlBytes = File.Exists(SupplementalXmlPath) ? File.ReadAllBytes(SupplementalXmlPath) : null;
        string? ledgerText = File.Exists(LedgerPath) ? File.ReadAllText(LedgerPath) : null;

        XDocument doc;
        try
        {
            doc = xmlBytes is null ? ParseXml(SupplementalTemplate) : LoadXml(new MemoryStream(xmlBytes));
        }
        catch (XmlException ex)
        {
            error = $"The supplemental policy file {SupplementalXmlPath} is not valid XML ({ex.Message}); refusing to build on it.";
            _logger.LogError("WDAC: {Error}", error);
            return false;
        }

        IReadOnlyList<string> problems = SupplementalPolicyValidator.Validate(doc, SupplementalPolicyId, expectedBasePolicyId: null, allowUnlinked: true);
        if (problems.Count > 0)
        {
            error = $"The supplemental policy file {SupplementalXmlPath} is not one Warden produced; refusing to build on it or deploy it: "
                    + string.Join(" ", problems);
            _logger.LogError("WDAC: {Error}", error);
            return false;
        }

        if (!AllowRuleLedger.TryParse(ledgerText, out AllowRuleLedger ledger, out string? ledgerError))
        {
            error = $"The rule ledger {LedgerPath} is unreadable ({ledgerError}); refusing to change the policy without it.";
            _logger.LogError("WDAC: {Error}", error);
            return false;
        }

        snapshot = new Snapshot(doc, ledger, xmlBytes);
        error = null;
        return true;
    }

    /// <summary>
    /// Validates, stages, compiles and deploys <paramref name="next"/>, then promotes the staged XML and
    /// ledger to live. Returns null on success or the reason for failure; on failure the live XML and
    /// ledger are the ones from <paramref name="previous"/>.
    /// </summary>
    private async Task<string?> CommitAsync(XDocument next, AllowRuleLedger nextLedger, Snapshot previous, string expectedBase, CancellationToken cancellationToken)
    {
        if (RejectInvalid(next, expectedBase, "the staged policy") is { } invalid)
        {
            return invalid;
        }

        try
        {
            return await StageDeployAndPromoteAsync(next, nextLedger, previous, expectedBase, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Staged files never outlive the attempt: a later run must not pick them up.
            DeleteQuietly(StagedXmlPath);
            DeleteQuietly(StagedLedgerPath);
            DeleteQuietly(CipPath);
        }
    }

    private async Task<string?> StageDeployAndPromoteAsync(XDocument next, AllowRuleLedger nextLedger, Snapshot previous, string expectedBase, CancellationToken cancellationToken)
    {
        try
        {
            SaveXml(next, StagedXmlPath);
            nextLedger.Save(StagedLedgerPath);

            // Compile what is on disk, so check what is on disk.
            if (RejectInvalid(LoadXml(StagedXmlPath), expectedBase, "the staged policy file") is { } stagedInvalid)
            {
                return stagedInvalid;
            }

            string? deployError = await CompileAndDeployAsync(StagedXmlPath, cancellationToken).ConfigureAwait(false);
            if (deployError is not null)
            {
                return deployError;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException)
        {
            _logger.LogError(ex, "WDAC: staging the supplemental failed; nothing was deployed.");
            return "Staging the policy failed; nothing was deployed: " + ex.Message;
        }

        // Deployed. Promote: XML first, then the ledger. Each move replaces the live file atomically.
        bool xmlPromoted = false;
        try
        {
            File.Move(StagedXmlPath, SupplementalXmlPath, overwrite: true);
            xmlPromoted = true;
            File.Move(StagedLedgerPath, LedgerPath, overwrite: true);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogCritical(ex,
                "WDAC: the policy was deployed but saving it failed; restoring the previous XML and ledger and redeploying the previous policy.");
            // The ledger is promoted last, so when anything here throws it still holds the previous entries.
            RestoreFile(SupplementalXmlPath, previous.XmlBytes, xmlPromoted);
            string? rollbackError = await RedeployPreviousAsync(previous, next, expectedBase, cancellationToken).ConfigureAwait(false);
            return rollbackError is null
                ? "Saving the updated policy failed; the previous policy was restored and redeployed: " + ex.Message
                : $"Saving the updated policy failed and redeploying the previous one also failed ({rollbackError}). "
                  + "The deployed supplemental may contain an allow that is not recorded; check it with CiTool --list-policies.";
        }
    }

    /// <summary>
    /// Compensating deploy after a promotion failure: the previous content, with a version above the one
    /// just deployed (WDAC applies an update only when the version increases). The result becomes the live XML.
    /// </summary>
    private async Task<string?> RedeployPreviousAsync(Snapshot previous, XDocument deployed, string expectedBase, CancellationToken cancellationToken)
    {
        try
        {
            XDocument doc = new(previous.Doc);
            string? linked = SupplementalPolicyXml.BasePolicyId(doc);
            if (string.IsNullOrWhiteSpace(linked) || linked == EmptyGuid)
            {
                SupplementalPolicyXml.SetBasePolicyId(doc, expectedBase);
            }
            SupplementalPolicyXml.SetVersion(doc, SupplementalPolicyXml.GetVersion(deployed) ?? "1.0.0.0");
            SupplementalPolicyXml.BumpVersion(doc);
            if (RejectInvalid(doc, expectedBase, "the rollback policy") is { } invalid)
            {
                return invalid;
            }

            SaveXml(doc, RollbackXmlPath);
            string? error = await CompileAndDeployAsync(RollbackXmlPath, cancellationToken).ConfigureAwait(false);
            if (error is not null)
            {
                return error;
            }
            File.Move(RollbackXmlPath, SupplementalXmlPath, overwrite: true);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException or InvalidOperationException)
        {
            return ex.Message;
        }
        finally
        {
            DeleteQuietly(RollbackXmlPath);
            DeleteQuietly(CipPath);
        }
    }

    private string? RejectInvalid(XDocument doc, string expectedBase, string what)
    {
        IReadOnlyList<string> problems = SupplementalPolicyValidator.Validate(doc, SupplementalPolicyId, expectedBase);
        if (problems.Count == 0)
        {
            return null;
        }
        string error = $"Refusing to deploy {what}: " + string.Join(" ", problems);
        _logger.LogError("WDAC: {Error}", error);
        return error;
    }

    private async Task<string?> CompileAndDeployAsync(string xmlPath, CancellationToken cancellationToken)
    {
        DeleteIfExists(CipPath);
        ProcessResult compile = await _tools.CompileAsync(xmlPath, CipPath, cancellationToken).ConfigureAwait(false);
        if (!compile.Ok)
        {
            return $"ConfigCI compile failed: {Trim(compile.StdErr)} {Trim(compile.StdOut)}";
        }
        if (!File.Exists(CipPath))
        {
            return "ConfigCI did not produce a .cip.";
        }

        ProcessResult deploy = await _tools.DeployAsync(CipPath, cancellationToken).ConfigureAwait(false);
        if (!deploy.Ok)
        {
            return $"CiTool --update-policy failed (exit {deploy.ExitCode}): {Trim(deploy.StdErr)}";
        }
        return null;
    }

    private void RestoreFile(string path, byte[]? bytes, bool changed)
    {
        if (!changed)
        {
            return;
        }
        try
        {
            if (bytes is null)
            {
                DeleteIfExists(path);
            }
            else
            {
                File.WriteAllBytes(path, bytes);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogCritical(ex, "WDAC: could not restore {File}.", path);
        }
    }

    private string? BackupCurrent()
    {
        if (!File.Exists(SupplementalXmlPath))
        {
            return null;
        }
        Directory.CreateDirectory(BackupDir);
        // Millisecond stamp so two changes in the same second do not overwrite one backup.
        string stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd_HHmmss_fff", CultureInfo.InvariantCulture);
        string dest = Path.Combine(BackupDir, $"WardenAllowlist.Supplemental_{stamp}.xml");
        File.Copy(SupplementalXmlPath, dest, overwrite: true);
        return dest;
    }

    // ---- helpers ----------------------------------------------------------------------------------

    /// <summary>
    /// Single-quoted PowerShell literal. PowerShell treats ASCII <c>'</c> and the typographic single quotes
    /// U+2018–U+201B alike as quote characters, and a doubled quote character is one literal character, so
    /// each of them is doubled.
    /// </summary>
    public static string Ps(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sb = new StringBuilder(value.Length + 2);
        sb.Append('\'');
        foreach (char c in value)
        {
            sb.Append(c);
            if (c is '\'' or (>= (char)0x2018 and <= (char)0x201B))
            {
                sb.Append(c);
            }
        }
        sb.Append('\'');
        return sb.ToString();
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

    private static readonly XmlReaderSettings SafeXml = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };

    private static XDocument LoadXml(string path)
    {
        using XmlReader reader = XmlReader.Create(path, SafeXml);
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static XDocument LoadXml(Stream stream)
    {
        using XmlReader reader = XmlReader.Create(stream, SafeXml);
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static XDocument ParseXml(string text)
    {
        using XmlReader reader = XmlReader.Create(new StringReader(text), SafeXml);
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static void SaveXml(XDocument doc, string path)
    {
        string tmp = path + ".tmp";
        doc.Save(tmp);
        File.Move(tmp, path, overwrite: true);
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static void DeleteQuietly(string path)
    {
        try { DeleteIfExists(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
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
    internal const string SupplementalTemplate = """
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
