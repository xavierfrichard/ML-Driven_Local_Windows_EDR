using System.Collections.Immutable;

namespace Warden.Firewall;

/// <summary>Direction of a per-app firewall block rule.</summary>
public enum FirewallDirection
{
    Inbound,
    Outbound,
}

/// <summary>
/// A single per-app firewall rule to create. Windows Firewall application rules are <b>full-path only</b>
/// (no wildcards), and an explicit Block always beats an Allow — so blocking an app both ways is exactly
/// two rules (one inbound, one outbound) keyed on the full exe path.
/// </summary>
/// <param name="AppPath">Full path to the exe the rule applies to.</param>
/// <param name="Direction">Inbound or outbound.</param>
/// <param name="RuleName">The Windows Firewall rule display name.</param>
public sealed record FirewallRuleSpec(string AppPath, FirewallDirection Direction, string RuleName);

/// <summary>Pure factory + naming for Warden's per-app firewall rules (unit-tested; no system change).</summary>
public static class FirewallRuleSpecs
{
    /// <summary>Prefix that identifies a rule Warden created (used to find/remove them).</summary>
    public const string NamePrefix = "Warden Block";

    /// <summary>The two block rules (inbound + outbound) for an app.</summary>
    public static ImmutableArray<FirewallRuleSpec> BlockBoth(string appPath)
    {
        return ImmutableArray.Create(
            new FirewallRuleSpec(appPath, FirewallDirection.Inbound, RuleName(appPath, FirewallDirection.Inbound)),
            new FirewallRuleSpec(appPath, FirewallDirection.Outbound, RuleName(appPath, FirewallDirection.Outbound)));
    }

    /// <summary>The display name for a rule, e.g. "Warden Block IN: chrome.exe".</summary>
    public static string RuleName(string appPath, FirewallDirection direction)
    {
        string image = string.IsNullOrEmpty(appPath) ? "app" : Path.GetFileName(appPath);
        string dir = direction == FirewallDirection.Inbound ? "IN" : "OUT";
        return $"{NamePrefix} {dir}: {image}";
    }

    /// <summary>The storage string for a direction, matching the firewall_rules schema.</summary>
    public static string DirectionToString(FirewallDirection direction) =>
        direction == FirewallDirection.Inbound ? "inbound" : "outbound";
}
