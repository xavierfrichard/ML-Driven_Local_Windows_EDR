using System.Text.Json;
using Microsoft.Extensions.Logging;
using Warden.Firewall;
using Warden.Ipc;
using Warden.Storage;

namespace Warden.Service;

/// <summary>
/// Serves the tray UI's panel reads and policy edits. The service owns every database write: the data
/// directory is ACL-locked to SYSTEM + Administrators, so a user-session UI cannot open the SQLite file
/// itself, and routing through here also keeps a single writer on the WAL.
/// </summary>
/// <remarks>
/// Authorization for mutating operations is enforced by <see cref="MgmtPipeServer"/> before dispatch
/// (impersonated Administrators check). The <c>callerIsAdmin</c> argument is re-checked here for the
/// operations that make real machine changes, so a future caller of this class cannot skip the gate.
/// </remarks>
public sealed class MgmtRequestHandler : IMgmtHandler
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
        _logger = logger;
    }

    public async Task<MgmtResponse> HandleAsync(MgmtRequest request, bool callerIsAdmin, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Defence in depth: the pipe server already refused unprivileged mutations.
        if (MgmtOperations.IsMutation(request.Operation) && !callerIsAdmin)
        {
            return MgmtResponse.Fail(request.RequestId, MgmtProtocol.ElevationRequired);
        }

        Guid id = request.RequestId;

        return request.Operation switch
        {
            // ---- reads ------------------------------------------------------------------------------
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

            _ => MgmtResponse.Fail(id, $"Unknown operation '{request.Operation}'."),
        };
    }

    /// <summary>The User Log is the subset of whitelist entries the user decided at a prompt.</summary>
    private async Task<IReadOnlyList<WhitelistEntry>> UserLogAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<WhitelistEntry> all = await _whitelist.GetAllAsync(1000, cancellationToken).ConfigureAwait(false);
        return all.Where(w => string.Equals(w.Source, "UserPrompt", StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private async Task<MgmtResponse> AddRuleAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out RuleEntry? rule, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        long newId = await _rules.AddAsync(rule!, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: rule {Id} added ({Kind} {Action} {Value}).", newId, rule!.Kind, rule.Action, rule.MatchValue);
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

        await _folders.AddAsync(folder!, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: protected folder added ({Path}).", folder!.Path);
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

        await _whitelist.AddAsync(entry!, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: whitelist entry upserted for {Sha}.", entry!.Sha256);
        return MgmtResponse.Success(id);
    }

    private async Task<MgmtResponse> SetWhitelistActionAsync(Guid id, string? payload, CancellationToken cancellationToken)
    {
        if (!TryParse(payload, out SetActionPayload? arg, out string? error))
        {
            return MgmtResponse.Fail(id, error);
        }

        if (!Enum.IsDefined(typeof(PolicyAction), arg!.Action))
        {
            return MgmtResponse.Fail(id, $"Unknown action value {arg.Action}.");
        }

        var action = (PolicyAction)arg.Action;
        await _whitelist.SetActionAsync(arg.Id, action, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Mgmt: whitelist entry {Id} set to {Action}.", arg.Id, action);
        return MgmtResponse.Success(id);
    }

    /// <summary>
    /// Applies the Advanced panel's per-app firewall checkboxes: real Windows Firewall rules via the
    /// COM API, then the persisted state. The rule change is attempted first so the database never
    /// claims a block that was not actually created.
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
            return MgmtResponse.Fail(id, $"No vulnerable-app row with id {arg.Id}.");
        }

        string appPath = string.IsNullOrWhiteSpace(arg.AppPath) ? app.AppPath : arg.AppPath;
        if (!Path.IsPathRooted(appPath))
        {
            return MgmtResponse.Fail(
                id,
                $"'{appPath}' is a seeded name, not a full path. Firewall rules key on the full exe path, "
                + "so this entry cannot be blocked until it is resolved to one.");
        }

        try
        {
            _firewall.SetBlocked(appPath, arg.BlockInbound, arg.BlockOutbound);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mgmt: firewall change failed for {App}.", appPath);
            return MgmtResponse.Fail(id, "Windows Firewall rejected the change: " + ex.Message);
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
        catch (JsonException ex)
        {
            error = "Malformed request payload: " + ex.Message;
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
