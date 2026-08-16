using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Warden.Firewall;
using Warden.Ipc;
using Warden.Storage;
using Warden.Wdac;

namespace Warden.Service;

/// <summary>
/// Serves the tray UI's panel reads and policy edits. The service owns every database write: the data
/// directory is ACL-locked to SYSTEM + Administrators, so a user-session UI cannot open the SQLite file
/// itself, and routing through here keeps the writes on the service's connections.
/// </summary>
/// <remarks>
/// <para>Authorization for mutating operations is enforced by <see cref="MgmtPipeServer"/> before dispatch
/// (impersonated Administrators check, default-deny for anything not on the read list). The
/// <c>callerIsAdmin</c> argument is re-checked here for every non-read, so a future caller of this class
/// cannot skip the gate.</para>
/// <para>Payloads are validated before they touch policy: a whitelist hash must be 64 hex characters, a
/// folder rule must be a rooted path that is not a drive root, and firewall changes apply to the path
/// recorded for the row, never a caller-supplied one.</para>
/// </remarks>
public sealed partial class MgmtRequestHandler : IMgmtHandler
{
    private readonly IWhitelistRepository _whitelist;
    private readonly IRulesRepository _rules;
    private readonly ICommandLineRepository _commandLines;
    private readonly IQuarantineRepository _quarantine;
    private readonly IAttackChainRepository _chains;
    private readonly IProtectedFolderRepository _folders;
    private readonly IVulnerableAppRepository _vulnApps;
    private readonly IMitigationProfileRepository _mitigations;
    private readonly IFirewallRuleRepository _firewallRules;
    private readonly IWebAppClassificationRepository _webApps;
    private readonly ITamperLogRepository _tamper;
    private readonly IFirewallRuleManager _firewall;
    private readonly IWdacAllowlistManager _wdac;
    private readonly ILogger<MgmtRequestHandler> _logger;

    public MgmtRequestHandler(
        IWhitelistRepository whitelist,
        IRulesRepository rules,
        ICommandLineRepository commandLines,
        IQuarantineRepository quarantine,
        IAttackChainRepository chains,
        IProtectedFolderRepository folders,
        IVulnerableAppRepository vulnApps,
        IMitigationProfileRepository mitigations,
        IFirewallRuleRepository firewallRules,
        IWebAppClassificationRepository webApps,
        ITamperLogRepository tamper,
        IFirewallRuleManager firewall,
        IWdacAllowlistManager wdac,
        ILogger<MgmtRequestHandler> logger)
    {
        _whitelist = whitelist;
        _rules = rules;
        _commandLines = commandLines;
        _quarantine = quarantine;
        _chains = chains;
        _folders = folders;
        _vulnApps = vulnApps;
        _mitigations = mitigations;
        _firewallRules = firewallRules;
        _webApps = webApps;
        _tamper = tamper;
        _firewall = firewall;
        _wdac = wdac;
        _logger = logger;
    }

    public async Task<MgmtResponse> HandleAsync(MgmtRequest request, bool callerIsAdmin, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Defence in depth: the pipe server already refused unprivileged non-reads (default-deny).
        if (!MgmtOperations.IsRead(request.Operation) && !callerIsAdmin)
        {
            return MgmtResponse.Fail(request.RequestId, MgmtProtocol.ElevationRequired);
        }

        Guid id = request.RequestId;

        return request.Operation switch
        {
            // ---- reads ------------------------------------------------------------------------------
            MgmtOperations.WhoAmI => MgmtResponse.Success(id, JsonSerializer.Serialize(new WhoAmIPayload(callerIsAdmin), IpcProtocol.Json)),
            MgmtOperations.WhitelistList => Json(id, await _whitelist.GetAllAsync(1000, cancellationToken).ConfigureAwait(false)),
            MgmtOperations.UserLogList => Json(id, await UserLogAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.RulesList => Json(id, await _rules.GetAllAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.CommandLinesList => Json(id, await _commandLines.GetAllAsync(1000, cancellationToken).ConfigureAwait(false)),
            MgmtOperations.QuarantineList => Json(id, await _quarantine.GetAllAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.ChainsList => Json(id, await _chains.GetRecentAsync(500, cancellationToken).ConfigureAwait(false)),
            MgmtOperations.FoldersList => Json(id, await _folders.GetAllAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.VulnAppsList => Json(id, await _vulnApps.GetAllAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.MitigationsList => Json(id, await _mitigations.GetAllAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.FirewallList => Json(id, await _firewallRules.GetAllAsync(cancellationToken).ConfigureAwait(false)),
            MgmtOperations.WebAppsList => Json(id, await _webApps.GetAllAsync(1000, cancellationToken).ConfigureAwait(false)),
            MgmtOperations.TamperList => Json(id, await _tamper.GetRecentAsync(500, cancellationToken).ConfigureAwait(false)),

            // ---- mutations --------------------------------------------------------------------------
            MgmtOperations.RulesAdd => await AddRuleAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.RulesDelete => await DeleteRuleAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.FoldersAdd => await AddFolderAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.FoldersDelete => await DeleteFolderAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.WhitelistAdd => await AddWhitelistAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.WhitelistSetAction => await SetWhitelistActionAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.WhitelistAllowFile => await AllowFileAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),
            MgmtOperations.VulnAppSetFirewall => await SetFirewallAsync(id, request.PayloadJson, cancellationToken).ConfigureAwait(false),

            _ => MgmtResponse.Fail(id, "Unknown operation."),
        };
    }

    /// <summary>The User Log is the subset of whitelist entries the user decided at a prompt.</summary>
    private async Task<IReadOnlyList<WhitelistEntry>> UserLogAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<WhitelistEntry> all = await _whitelist.GetAllAsync(1000, cancellationToken).ConfigureAwait(false);
        return all.Where(w => string.Equals(w.Source, "UserPrompt", StringComparison.OrdinalIgnoreCase)).ToList();
    }

    // ---- validation helpers -----------------------------------------------------------------------

    [GeneratedRegex("^[0-9A-Fa-f]{64}$")]
    private static partial Regex Sha256Hex();

    private static bool IsSha256(string? value) => value is not null && Sha256Hex().IsMatch(value);

    /// <summary>A rooted, canonical local path that is not a bare drive root (so "C:\" cannot become a rule).</summary>
    private static bool IsAcceptableLocalPath(string? value, bool allowDriveRoot, out string canonical, out string? error)
    {
        canonical = string.Empty;
        error = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            error = "Path is empty.";
            return false;
        }

        try
        {
            canonical = Path.GetFullPath(value);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            error = "Path is not a valid local path.";
            return false;
        }

        if (!Path.IsPathRooted(canonical) || canonical.StartsWith(@"\\", StringComparison.Ordinal))
        {
            error = "Path must be a rooted local path (no UNC/device paths).";
            return false;
        }

        if (!allowDriveRoot && Path.GetPathRoot(canonical) is { } root
            && string.Equals(root, canonical.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            error = "A drive root is not accepted here (it would apply to everything on the volume).";
            return false;
        }

        return true;
    }

    private static string? ValidateRule(RuleEntry rule)
    {
        if (string.IsNullOrWhiteSpace(rule.MatchValue))
        {
            return "Rule value is empty.";
        }

        if (!Enum.IsDefined(rule.Kind) || !Enum.IsDefined(rule.Action))
        {
            return "Rule kind/action is invalid.";
        }

        switch (rule.Kind)
        {
            case RuleKind.Hash:
                return IsSha256(rule.MatchValue) ? null : "A hash rule needs a 64-hex-character SHA-256.";
            case RuleKind.Signature:
                return rule.MatchValue.Trim().Length >= 3 ? null : "A signature rule needs at least 3 characters of publisher name.";
            case RuleKind.Folder:
                // A folder ALLOW on a drive root is a global allow; a BLOCK on a drive root is fine.
                return IsAcceptableLocalPath(rule.MatchValue, allowDriveRoot: rule.Action == PolicyAction.Block, out _, out string? err) ? null : err;
            case RuleKind.Extension:
                return rule.MatchValue.StartsWith('.') && rule.MatchValue.Length >= 2 && !rule.MatchValue.Any(char.IsWhiteSpace)
                    ? null
                    : "An extension rule looks like \".exe\".";
            default:
                return "Rule kind is invalid.";
        }
    }

    // ---- mutations --------------------------------------------------------------------------------

    /// <summary>Wire shape of rules.add: the rule plus (optionally) the file its match value came from.</summary>
    private sealed record RuleEnvelope(RuleEntry? Rule, string? SourcePath);

    private async Task<MgmtResponse> AddRuleAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        // { Rule, SourcePath } envelope (Browse… in the dialog) or a bare RuleEntry (older callers).
        RuleEntry? rule = null;
        string? sourcePath = null;
        if (TryParse(payload, out RuleEnvelope? env, out _) && env?.Rule is not null)
        {
            rule = env.Rule;
            sourcePath = env.SourcePath;
        }
        else if (!TryParse(payload, out rule, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (ValidateRule(rule!) is { } invalid)
        {
            return MgmtResponse.Fail(id, invalid);
        }

        long newId = await _rules.AddAsync(rule!, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: rule {Id} added ({Kind} {Action}).", newId, rule!.Kind, rule.Action);

        // The dialog told us which file the hash / publisher came from: allow-list THAT file now (for a
        // Hash rule its bytes must still match the hash; for a Signature rule the picked file is allowed
        // outright and the rule covers the publisher's other files on their next launch).
        if (rule.Action == PolicyAction.Allow && rule.Kind is RuleKind.Hash or RuleKind.Signature
            && !string.IsNullOrWhiteSpace(sourcePath)
            && IsAcceptableLocalPath(sourcePath, allowDriveRoot: false, out string sourceCanonical, out _)
            && File.Exists(sourceCanonical))
        {
            string? expected = rule.Kind == RuleKind.Hash ? rule.MatchValue : null;
            WdacBatchResult batch = await _wdac.AllowManyAsync(
                new[] { new WdacAllowFile(sourceCanonical, expected) }, cancellationToken).ConfigureAwait(false);
            WdacFileAllowResult r = batch.Files[0];
            if (batch.Success && r.Success && r.Sha256 is not null)
            {
                await RecordAdminAllowAsync(sourceCanonical, r.Sha256, "Rules", newId, cancellationToken).ConfigureAwait(false);
                return Message(id, rule.Kind == RuleKind.Hash
                    ? $"Rule added and {Path.GetFileName(sourceCanonical)} allow-listed in WDAC now. Relaunch the app."
                    : $"Rule added; {Path.GetFileName(sourceCanonical)} allow-listed in WDAC now. Other files from this publisher are allowed on their next launch.");
            }
            _logger.LogWarning("Mgmt: immediate allow for rule {Id} source {Path} failed: {Error}", newId, sourceCanonical, batch.Error ?? r.Error);
            return Message(id, $"Rule added, but {Path.GetFileName(sourceCanonical)} could not be allow-listed now ({batch.Error ?? r.Error}). It will apply on the file's next launch.");
        }

        // An Allow rule only takes effect at the file's NEXT block otherwise (the pipeline consults rules
        // when WDAC raises an event). For the two kinds where the files are knowable now, deploy the WDAC
        // hash rules immediately so the user does not need a fail-then-relaunch cycle.
        if (rule.Action == PolicyAction.Allow && rule.Kind == RuleKind.Folder && !rule.RequireSignature && !rule.RequireWhitelist)
        {
            return Message(id, await AllowFolderNowAsync(rule.MatchValue, newId, cancellationToken).ConfigureAwait(false));
        }

        if (rule.Action == PolicyAction.Allow && rule.Kind == RuleKind.Hash)
        {
            WhitelistEntry? known = await _whitelist.FindLatestBySha256Async(rule.MatchValue, cancellationToken).ConfigureAwait(false);
            if (known is not null && File.Exists(known.ProcessPath))
            {
                WdacBatchResult batch = await _wdac.AllowManyAsync(
                    new[] { new WdacAllowFile(known.ProcessPath, known.Sha256) }, cancellationToken).ConfigureAwait(false);
                if (batch.Success && batch.Allowed == 1)
                {
                    await _whitelist.SetActionAsync(known.Id, PolicyAction.Allow, cancellationToken).ConfigureAwait(false);
                    return Message(id, $"Rule added and WDAC allow rule deployed for {known.ProcessName}; relaunch the app.");
                }
                return Message(id, "Rule added, but the WDAC rule could not be deployed now (" + (batch.Error ?? batch.Files[0].Error) + "). It will apply on the file's next launch.");
            }
            return Message(id, "Rule added. It applies the next time a file with this hash is launched.");
        }

        return Message(id, rule.Action == PolicyAction.Allow
            ? "Rule added. It applies the next time a matching file is launched (blocked → allowed on relaunch)."
            : "Rule added.");
    }

    /// <summary>
    /// Allow-lists every PE file under a folder in one WDAC update and records a whitelist Allow row for
    /// each, so a "Folder → Allow" rule is effective immediately rather than one failed launch per DLL.
    /// </summary>
    private async Task<string> AllowFolderNowAsync(string folder, long ruleId, CancellationToken cancellationToken)
    {
        if (!IsAcceptableLocalPath(folder, allowDriveRoot: false, out string canonical, out string? invalid))
        {
            return "Rule added; " + invalid;
        }
        if (!Directory.Exists(canonical))
        {
            return "Rule added. The folder does not exist yet; files will be allowed as they are launched.";
        }

        var candidates = new List<string>();
        try
        {
            foreach (string f in Directory.EnumerateFiles(canonical, "*", SearchOption.AllDirectories))
            {
                if (candidates.Count >= MaxBulkAllowFiles)
                {
                    break;
                }
                if (IsPeCandidate(f))
                {
                    candidates.Add(f);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Mgmt: enumerating {Folder} for bulk allow failed.", canonical);
        }

        if (candidates.Count == 0)
        {
            return "Rule added. No executable files were found under the folder; anything launched from it will be allowed on its next launch.";
        }

        WdacBatchResult batch = await _wdac.AllowManyAsync(
            candidates.Select(c => new WdacAllowFile(c, null)).ToList(), cancellationToken).ConfigureAwait(false);

        int recorded = 0;
        foreach (WdacFileAllowResult r in batch.Files.Where(r => r.Success && r.Sha256 is not null))
        {
            await RecordAdminAllowAsync(r.Path, r.Sha256!, "Rules", ruleId, cancellationToken).ConfigureAwait(false);
            recorded++;
        }

        if (!batch.Success)
        {
            _logger.LogError("Mgmt: bulk allow for {Folder} failed: {Error}", canonical, batch.Error);
            return $"Rule added, but the WDAC deployment failed ({batch.Error}). Files will be allowed on their next launch.";
        }

        string more = candidates.Count >= MaxBulkAllowFiles ? $" (stopped at the {MaxBulkAllowFiles}-file cap; the rest are allowed on launch)" : string.Empty;
        return $"Rule added and {recorded} file(s) allow-listed in WDAC now, {batch.Skipped} skipped{more}. Relaunch the app.";
    }

    private const int MaxBulkAllowFiles = 500;

    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".ocx", ".cpl", ".scr", ".com", ".drv", ".ax", ".efi", ".mui", ".node", ".pyd", ".winmd", ".arx", ".dbx", ".crx",
    };

    /// <summary>Extension on the PE list AND an "MZ" header (cheap, avoids scanning renamed data files).</summary>
    private static bool IsPeCandidate(string path)
    {
        try
        {
            if (!PeExtensions.Contains(Path.GetExtension(path)))
            {
                return false;
            }
            var info = new FileInfo(path);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length < 64)
            {
                return false;
            }
            using FileStream fs = info.OpenRead();
            return fs.ReadByte() == 'M' && fs.ReadByte() == 'Z';
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task RecordAdminAllowAsync(string path, string sha256, string source, long? ruleId, CancellationToken cancellationToken)
    {
        long size = -1;
        try { size = new FileInfo(path).Length; } catch (IOException) { } catch (UnauthorizedAccessException) { }
        await _whitelist.AddAsync(new WhitelistEntry
        {
            Timestamp = DateTimeOffset.UtcNow,
            Action = PolicyAction.Allow,
            ProcessName = Path.GetFileName(path).ToLowerInvariant(),
            ProcessPath = path,
            Sha256 = sha256.ToUpperInvariant(),
            FileSize = size,
            Source = source,
            RuleId = ruleId,
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// "Allow file…": an administrator picks a file; it is hash-allow-listed in WDAC immediately and recorded
    /// as an Allow row (Source = Admin) so the whitelist tier replays it. The bytes present now are the
    /// bytes allowed.
    /// </summary>
    private async Task<MgmtResponse> AllowFileAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out AllowFilePayload? arg, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (!IsAcceptableLocalPath(arg!.Path, allowDriveRoot: false, out string canonical, out string? invalid))
        {
            return MgmtResponse.Fail(id, invalid!);
        }
        if (!File.Exists(canonical))
        {
            return MgmtResponse.Fail(id, "The file does not exist.");
        }

        WdacBatchResult batch = await _wdac.AllowManyAsync(new[] { new WdacAllowFile(canonical, null) }, cancellationToken).ConfigureAwait(false);
        WdacFileAllowResult r = batch.Files[0];
        if (!batch.Success || !r.Success || r.Sha256 is null)
        {
            _logger.LogError("Mgmt: allow-file failed for {Path}: {Error}", canonical, batch.Error ?? r.Error);
            return MgmtResponse.Fail(id, "WDAC allow failed: " + (batch.Error ?? r.Error ?? "unknown error"));
        }

        await RecordAdminAllowAsync(canonical, r.Sha256, "Admin", null, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: file allow-listed by administrator: {Sha} {Path}", r.Sha256, canonical);
        return Message(id, $"{Path.GetFileName(canonical)} is now allowed (WDAC rule deployed). Relaunch the app.");
    }

    private static MgmtResponse Message(Guid id, string text) =>
        MgmtResponse.Success(id, JsonSerializer.Serialize(new MgmtMessage(text), IpcProtocol.Json));

    private async Task<MgmtResponse> DeleteRuleAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out IdPayload? arg, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        await _rules.DeleteAsync(arg!.Id, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: rule {Id} deleted.", arg.Id);
        return MgmtResponse.Success(id);
    }

    private async Task<MgmtResponse> AddFolderAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out ProtectedFolder? folder, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (!IsAcceptableLocalPath(folder!.Path, allowDriveRoot: false, out string canonical, out string? invalid))
        {
            return MgmtResponse.Fail(id, invalid!);
        }

        if (!Directory.Exists(canonical))
        {
            return MgmtResponse.Fail(id, "The folder does not exist.");
        }

        await _folders.AddAsync(folder with { Path = canonical }, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: protected folder added.");
        return MgmtResponse.Success(id);
    }

    private async Task<MgmtResponse> DeleteFolderAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out IdPayload? arg, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        await _folders.DeleteAsync(arg!.Id, cancellationToken).ConfigureAwait(false);
        return MgmtResponse.Success(id);
    }

    private async Task<MgmtResponse> AddWhitelistAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out WhitelistEntry? entry, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (!IsSha256(entry!.Sha256))
        {
            return MgmtResponse.Fail(id, "A whitelist entry needs a 64-hex-character SHA-256.");
        }

        if (!Enum.IsDefined(entry.Action))
        {
            return MgmtResponse.Fail(id, "Unknown action value.");
        }

        // A manual entry is an administrator's decision: it carries the authoritative "Admin" source so an
        // automatic tier can never overwrite it (see WhitelistRepository.AuthoritativeSources).
        var normalized = entry with
        {
            Sha256 = entry.Sha256.ToUpperInvariant(),
            Source = "Admin",
            Timestamp = entry.Timestamp == default ? DateTimeOffset.UtcNow : entry.Timestamp,
        };

        await _whitelist.AddAsync(normalized, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: whitelist entry upserted for {Sha}.", normalized.Sha256);

        if (normalized.Action != PolicyAction.Allow)
        {
            // A manual Block: make sure no allow rule for that hash survives in WDAC.
            WdacUpdateResult revoke = await _wdac.RevokeAsync(normalized.Sha256, normalized.ProcessName, cancellationToken).ConfigureAwait(false);
            return Message(id, revoke.Success
                ? $"{normalized.ProcessName} recorded as Block."
                : $"{normalized.ProcessName} recorded as Block, but an existing WDAC allow rule could not be removed: {revoke.Error}");
        }

        if (!IsAcceptableLocalPath(normalized.ProcessPath, allowDriveRoot: false, out string canonical, out _) || !File.Exists(canonical))
        {
            return Message(id, $"{normalized.ProcessName} recorded as Allow. The file is not at that path, so the WDAC rule will be deployed on its next launch (blocked once, then allowed).");
        }

        WdacBatchResult batch = await _wdac.AllowManyAsync(
            new[] { new WdacAllowFile(canonical, normalized.Sha256) }, cancellationToken).ConfigureAwait(false);
        WdacFileAllowResult r = batch.Files[0];
        if (batch.Success && r.Success)
        {
            return Message(id, $"{normalized.ProcessName} is now allowed (WDAC rule deployed). Relaunch the app.");
        }
        return Message(id, $"{normalized.ProcessName} recorded as Allow, but the WDAC rule could not be deployed now: {batch.Error ?? r.Error}. If the file changed, use 'Allow file…' to allow the current bytes.");
    }

    /// <summary>
    /// Flips an entry between Allow and Block. Moving to <b>Block</b> is a revocation: the WDAC allow rule
    /// for that hash is removed first (otherwise the OS would keep allowing the file and the pipeline —
    /// including this Block — would never be consulted again). The DB is only updated if the WDAC change
    /// succeeded, so the panel never claims a revocation that is not in force.
    /// </summary>
    private async Task<MgmtResponse> SetWhitelistActionAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out SetActionPayload? arg, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (!Enum.IsDefined(typeof(PolicyAction), arg!.Action))
        {
            return MgmtResponse.Fail(id, "Unknown action value.");
        }

        var action = (PolicyAction)arg.Action;
        WhitelistEntry? entry = await _whitelist.GetByIdAsync(arg.Id, cancellationToken).ConfigureAwait(false);
        if (entry is null)
        {
            return MgmtResponse.Fail(id, "No whitelist entry with that id.");
        }

        if (action == PolicyAction.Block && IsSha256(entry.Sha256))
        {
            WdacUpdateResult revoke = await _wdac.RevokeAsync(entry.Sha256, entry.ProcessName, cancellationToken).ConfigureAwait(false);
            if (!revoke.Success)
            {
                _logger.LogError("Mgmt: WDAC revoke failed for {Sha}: {Error}", entry.Sha256, revoke.Error);
                return MgmtResponse.Fail(id, "The WDAC allow rule could not be revoked; the entry was left unchanged. See the agent log.");
            }

            await _whitelist.SetActionAsync(arg.Id, action, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Mgmt: whitelist entry {Id} set to Block (WDAC rule revoked).", arg.Id);
            return Message(id, $"{entry.ProcessName} is blocked again (WDAC allow rule removed).");
        }

        // Allow: deploy the WDAC rule NOW if the recorded file is still there with the recorded bytes;
        // otherwise the row still flips and the pipeline deploys on the file's next block.
        await _whitelist.SetActionAsync(arg.Id, action, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: whitelist entry {Id} set to {Action}.", arg.Id, action);

        if (!IsSha256(entry.Sha256) || string.IsNullOrWhiteSpace(entry.ProcessPath) || !File.Exists(entry.ProcessPath))
        {
            return Message(id, $"{entry.ProcessName} set to Allow. The file is not at its recorded path, so the WDAC rule will be deployed on its next launch (blocked once, then allowed).");
        }

        WdacBatchResult batch = await _wdac.AllowManyAsync(
            new[] { new WdacAllowFile(entry.ProcessPath, entry.Sha256) }, cancellationToken).ConfigureAwait(false);
        WdacFileAllowResult r = batch.Files[0];
        if (batch.Success && r.Success)
        {
            return Message(id, $"{entry.ProcessName} is now allowed (WDAC rule deployed). Relaunch the app.");
        }

        _logger.LogWarning("Mgmt: immediate WDAC allow for {Sha} failed: {Error}", entry.Sha256, batch.Error ?? r.Error);
        return Message(id,
            $"{entry.ProcessName} set to Allow, but the WDAC rule could not be deployed now: {batch.Error ?? r.Error}. "
            + "If the file has changed since it was recorded, use 'Allow file…' to allow the current bytes.");
    }

    /// <summary>
    /// Applies the Advanced panel's per-app firewall checkboxes: real Windows Firewall rules via the
    /// COM API, then the persisted state. The path is always the one recorded for the row — a caller
    /// cannot point the change at an arbitrary executable.
    /// </summary>
    private async Task<MgmtResponse> SetFirewallAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out SetFirewallPayload? arg, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        VulnerableAppRecord? app = await _vulnApps.GetByIdAsync(arg!.Id, cancellationToken).ConfigureAwait(false);
        if (app is null)
        {
            return MgmtResponse.Fail(id, "No vulnerable-app row with that id.");
        }

        string appPath = app.AppPath;
        if (!IsAcceptableLocalPath(appPath, allowDriveRoot: false, out string canonical, out _) || !File.Exists(canonical))
        {
            return MgmtResponse.Fail(
                id,
                "This entry is a seeded name, not a full path to an existing executable. Firewall rules key on the full "
                + "exe path, so this entry cannot be blocked until it is resolved to one.");
        }
        appPath = canonical;

        try
        {
            _firewall.SetBlocked(appPath, arg.BlockInbound, arg.BlockOutbound);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mgmt: firewall change failed for {App}.", appPath);
            return MgmtResponse.Fail(id, "Windows Firewall rejected the change; see the agent log for details.");
        }

        await _firewallRules.DeleteByAppAsync(appPath, cancellationToken).ConfigureAwait(false);

        if (arg.BlockInbound)
        {
            await AddFirewallRowAsync(appPath, "inbound", cancellationToken).ConfigureAwait(false);
        }

        if (arg.BlockOutbound)
        {
            await AddFirewallRowAsync(appPath, "outbound", cancellationToken).ConfigureAwait(false);
        }

        await _vulnApps.SetFirewallStateAsync(arg.Id, arg.BlockInbound, arg.BlockOutbound, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation(
            "Mgmt: firewall for {App} set to in={In} out={Out}.", appPath, arg.BlockInbound, arg.BlockOutbound);

        return MgmtResponse.Success(id);
    }

    private Task AddFirewallRowAsync(string appPath, string direction, CancellationToken cancellationToken) =>
        _firewallRules.AddAsync(
            new FirewallRuleRecord
            {
                AppPath = appPath,
                Direction = direction,
                FwRuleName = $"Warden Block {direction}: {Path.GetFileName(appPath)}",
                Enabled = true,
                CreatedTs = DateTimeOffset.UtcNow,
            },
            cancellationToken);

    private static MgmtResponse Json<T>(Guid id, IReadOnlyList<T> rows) =>
        MgmtResponse.Success(id, JsonSerializer.Serialize(rows, IpcProtocol.Json));

    private static bool TryParse<T>(string? payload, out T? value, out string error)
    {
        value = default;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(payload))
        {
            error = "Missing request payload.";
            return false;
        }

        try
        {
            value = JsonSerializer.Deserialize<T>(payload, IpcProtocol.Json);
        }
        catch (JsonException)
        {
            error = "Malformed request payload.";
            return false;
        }

        if (value is null)
        {
            error = "Empty request payload.";
            return false;
        }

        return true;
    }
}
