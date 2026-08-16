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

    private async Task<MgmtResponse> AddRuleAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out RuleEntry? rule, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (ValidateRule(rule!) is { } invalid)
        {
            return MgmtResponse.Fail(id, invalid);
        }

        long newId = await _rules.AddAsync(rule!, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: rule {Id} added ({Kind} {Action}).", newId, rule!.Kind, rule.Action);
        return MgmtResponse.Success(id);
    }

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

        var normalized = entry with
        {
            Sha256 = entry.Sha256.ToUpperInvariant(),
            Source = string.IsNullOrWhiteSpace(entry.Source) ? "Admin" : entry.Source,
            Timestamp = entry.Timestamp == default ? DateTimeOffset.UtcNow : entry.Timestamp,
        };

        await _whitelist.AddAsync(normalized, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: whitelist entry upserted for {Sha}.", normalized.Sha256);
        return MgmtResponse.Success(id);
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
        }

        await _whitelist.SetActionAsync(arg.Id, action, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: whitelist entry {Id} set to {Action}.", arg.Id, action);
        return MgmtResponse.Success(id);
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
