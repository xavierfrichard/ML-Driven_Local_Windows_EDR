using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace Warden.Firewall;

/// <summary>Creates and removes per-app firewall block rules.</summary>
public interface IFirewallRuleManager
{
    /// <summary>Block an app both ways (creates the inbound + outbound rules). Returns the rules created.</summary>
    IReadOnlyList<FirewallRuleSpec> BlockApp(string appPath);

    /// <summary>Remove all Warden-created rules for an app.</summary>
    void UnblockApp(string appPath);

    /// <summary>
    /// Sets an app's block state per direction (the Advanced panel's two checkboxes). Idempotent:
    /// existing Warden rules for the app are removed first, then only the requested directions are
    /// created. Passing false for both is equivalent to <see cref="UnblockApp"/>.
    /// </summary>
    IReadOnlyList<FirewallRuleSpec> SetBlocked(string appPath, bool inbound, bool outbound);

    /// <summary>Names of the Warden-created firewall rules currently present.</summary>
    IReadOnlyList<string> ListWardenRuleNames();
}

/// <summary>
/// Per-app firewall via the Windows Firewall COM API (<c>HNetCfg.FwPolicy2</c> / <c>HNetCfg.FWRule</c>,
/// late-bound so no interop assembly is needed). Blocking an app is two rules (inbound + outbound),
/// action = Block, protocol = ANY, all profiles, keyed on the full exe path. A real, machine-wide change
/// requiring elevation — invoked panel-driven and validated in the VM (<c>wf.msc</c>); the rule modeling
/// is in <see cref="FirewallRuleSpecs"/> and is unit-tested separately.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallRuleManager : IFirewallRuleManager
{
    // Windows Firewall COM constants.
    private const int DirIn = 1;
    private const int DirOut = 2;
    private const int ActionBlock = 0;
    private const int ProtocolAny = 256;
    private const int ProfilesAll = 0x7FFFFFFF;

    private readonly ILogger<FirewallRuleManager> _logger;

    public FirewallRuleManager(ILogger<FirewallRuleManager> logger) => _logger = logger;

    public IReadOnlyList<FirewallRuleSpec> BlockApp(string appPath)
    {
        var specs = FirewallRuleSpecs.BlockBoth(appPath);
        dynamic policy = CreatePolicy();

        foreach (FirewallRuleSpec spec in specs)
        {
            dynamic rule = CreateRuleObject();
            rule.Name = spec.RuleName;
            rule.Description = "Created by the Warden zero-trust agent.";
            rule.ApplicationName = spec.AppPath;
            rule.Direction = spec.Direction == FirewallDirection.Inbound ? DirIn : DirOut;
            rule.Action = ActionBlock;
            rule.Protocol = ProtocolAny;
            rule.Profiles = ProfilesAll;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }

        return specs;
    }

    public IReadOnlyList<FirewallRuleSpec> SetBlocked(string appPath, bool inbound, bool outbound)
    {
        // Rebuild from scratch so the resulting rule set always matches the requested state exactly.
        UnblockApp(appPath);

        if (!inbound && !outbound)
        {
            return Array.Empty<FirewallRuleSpec>();
        }

        var wanted = FirewallRuleSpecs.BlockBoth(appPath)
            .Where(s => s.Direction == FirewallDirection.Inbound ? inbound : outbound)
            .ToList();

        dynamic policy = CreatePolicy();
        foreach (FirewallRuleSpec spec in wanted)
        {
            dynamic rule = CreateRuleObject();
            rule.Name = spec.RuleName;
            rule.Description = "Created by the Warden zero-trust agent.";
            rule.ApplicationName = spec.AppPath;
            rule.Direction = spec.Direction == FirewallDirection.Inbound ? DirIn : DirOut;
            rule.Action = ActionBlock;
            rule.Protocol = ProtocolAny;
            rule.Profiles = ProfilesAll;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }

        return wanted;
    }

    public void UnblockApp(string appPath)
    {
        dynamic policy = CreatePolicy();
        var toRemove = new List<string>();

        foreach (dynamic rule in policy.Rules)
        {
            string name = rule.Name ?? string.Empty;
            string app = rule.ApplicationName ?? string.Empty;
            if (name.StartsWith(FirewallRuleSpecs.NamePrefix, StringComparison.Ordinal)
                && string.Equals(app, appPath, StringComparison.OrdinalIgnoreCase))
            {
                toRemove.Add(name);
            }
        }

        foreach (string name in toRemove)
        {
            try { policy.Rules.Remove(name); }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to remove firewall rule {Name}.", name); }
        }
    }

    public IReadOnlyList<string> ListWardenRuleNames()
    {
        dynamic policy = CreatePolicy();
        var names = new List<string>();
        foreach (dynamic rule in policy.Rules)
        {
            string name = rule.Name ?? string.Empty;
            if (name.StartsWith(FirewallRuleSpecs.NamePrefix, StringComparison.Ordinal))
            {
                names.Add(name);
            }
        }
        return names;
    }

    private static dynamic CreatePolicy()
    {
        Type type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new PlatformNotSupportedException("Windows Firewall COM API (HNetCfg.FwPolicy2) is unavailable.");
        return Activator.CreateInstance(type)!;
    }

    private static dynamic CreateRuleObject()
    {
        Type type = Type.GetTypeFromProgID("HNetCfg.FWRule")
            ?? throw new PlatformNotSupportedException("Windows Firewall COM API (HNetCfg.FWRule) is unavailable.");
        return Activator.CreateInstance(type)!;
    }
}
