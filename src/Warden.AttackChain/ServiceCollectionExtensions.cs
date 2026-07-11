using Microsoft.Extensions.DependencyInjection;

namespace Warden.AttackChain;

/// <summary>DI registration for the Attack Chains subsystem.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenAttackChain(this IServiceCollection services)
    {
        services.AddSingleton<ChainSuspicionScorer>();
        services.AddSingleton<IProcessTreeBuilder, ProcessTreeBuilder>();
        return services;
    }
}
