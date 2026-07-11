using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;

namespace Warden.Firewall;

/// <summary>
/// DI registration for the per-app firewall manager. Registration creates no rules — rules are created
/// only when <see cref="IFirewallRuleManager.BlockApp"/> is invoked (panel-driven, VM-validated).
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenFirewall(this IServiceCollection services)
    {
        services.AddSingleton<IFirewallRuleManager, FirewallRuleManager>();
        return services;
    }
}
