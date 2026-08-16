namespace Warden.Ipc;

/// <summary>
/// Operation names for the management channel. Authorization is <b>default-deny</b>: only the names in
/// <see cref="Reads"/> may be issued by a connected caller whose token is not an Administrators member;
/// every other name is treated as a mutation and refused unless the impersonated caller is elevated
/// (see <c>MgmtPipeServer</c>). Adding a new mutating operation therefore needs no bookkeeping — forgetting
/// to list it cannot make it callable by a non-admin. (The pipe DACL additionally admits only elevated
/// processes, so in production even reads require elevation; the read list matters for dev runs.)
/// </summary>
public static class MgmtOperations
{
    // ---- reads ------------------------------------------------------------------------------------
    public const string WhoAmI = "whoami";
    public const string WhitelistList = "whitelist.list";
    public const string UserLogList = "userlog.list";
    public const string RulesList = "rules.list";
    public const string CommandLinesList = "commandlines.list";
    public const string QuarantineList = "quarantine.list";
    public const string ChainsList = "chains.list";
    public const string FoldersList = "folders.list";
    public const string VulnAppsList = "vulnapps.list";
    public const string MitigationsList = "mitigations.list";
    public const string FirewallList = "firewall.list";
    public const string WebAppsList = "webapps.list";
    public const string TamperList = "tamper.list";

    // ---- mutations (Administrators only) ----------------------------------------------------------
    public const string RulesAdd = "rules.add";
    public const string RulesDelete = "rules.delete";
    public const string FoldersAdd = "folders.add";
    public const string FoldersDelete = "folders.delete";
    public const string WhitelistAdd = "whitelist.add";
    public const string WhitelistSetAction = "whitelist.setaction";
    public const string VulnAppSetFirewall = "vulnapp.setfirewall";

    /// <summary>The read-only operations — the only ones a non-elevated caller may issue.</summary>
    public static readonly IReadOnlySet<string> Reads = new HashSet<string>(StringComparer.Ordinal)
    {
        WhoAmI,
        WhitelistList,
        UserLogList,
        RulesList,
        CommandLinesList,
        QuarantineList,
        ChainsList,
        FoldersList,
        VulnAppsList,
        MitigationsList,
        FirewallList,
        WebAppsList,
        TamperList,
    };

    /// <summary>The known mutating operations (for display / tests). Authorization does not depend on this list.</summary>
    public static readonly IReadOnlySet<string> Mutations = new HashSet<string>(StringComparer.Ordinal)
    {
        RulesAdd,
        RulesDelete,
        FoldersAdd,
        FoldersDelete,
        WhitelistAdd,
        WhitelistSetAction,
        VulnAppSetFirewall,
    };

    /// <summary>True when <paramref name="operation"/> is on the read allow-list.</summary>
    public static bool IsRead(string operation) => operation is not null && Reads.Contains(operation);

    /// <summary>True when <paramref name="operation"/> needs Administrators — i.e. anything that is not a read.</summary>
    public static bool IsMutation(string operation) => !IsRead(operation);
}

/// <summary>
/// A management request from the tray UI (user session) to the service (session 0).
/// <paramref name="PayloadJson"/> carries the operation's argument object, or null for a plain read.
/// </summary>
public sealed record MgmtRequest(Guid RequestId, string Operation, string? PayloadJson);

/// <summary>
/// The service's reply. <paramref name="Ok"/> false always carries a human-readable
/// <paramref name="Error"/>; the UI shows it in the status bar rather than throwing.
/// </summary>
public sealed record MgmtResponse(Guid RequestId, bool Ok, string? Error, string? PayloadJson)
{
    public static MgmtResponse Fail(Guid id, string error) => new(id, false, error, null);

    public static MgmtResponse Success(Guid id, string? payloadJson = null) => new(id, true, null, payloadJson);
}

/// <summary>Reply to <see cref="MgmtOperations.WhoAmI"/>: whether the caller may issue mutations.</summary>
public sealed record WhoAmIPayload(bool IsAdministrator);

/// <summary>Argument payloads. Kept primitive so the wire format stays stable and UI-friendly.</summary>
public sealed record SetActionPayload(long Id, int Action);

/// <summary>Argument for toggling an app's inbound/outbound firewall block from the Advanced panel.</summary>
public sealed record SetFirewallPayload(long Id, string AppPath, bool BlockInbound, bool BlockOutbound);

/// <summary>Argument for the delete-by-id operations.</summary>
public sealed record IdPayload(long Id);

/// <summary>
/// Service-side dispatcher for management requests. Implementations own every database write, so the
/// tray UI never opens the (hardened, SYSTEM-owned) SQLite file itself.
/// </summary>
public interface IMgmtHandler
{
    /// <param name="callerIsAdmin">
    /// Whether the connected client's token is a member of the local Administrators group, resolved by
    /// impersonating the pipe client. Implementations must not perform a mutation when this is false.
    /// </param>
    Task<MgmtResponse> HandleAsync(MgmtRequest request, bool callerIsAdmin, CancellationToken cancellationToken);
}

/// <summary>Shared constants for the management channel (separate pipe from the block-prompt channel).</summary>
public static class MgmtProtocol
{
    /// <summary>Named pipe the service hosts for management traffic.</summary>
    public const string PipeName = "WardenAgent.Mgmt.v1";

    /// <summary>Message the server returns when a non-elevated caller attempts a mutation.</summary>
    public const string ElevationRequired =
        "This change requires an elevated Warden UI (the agent's policy is Administrators-only).";
}
