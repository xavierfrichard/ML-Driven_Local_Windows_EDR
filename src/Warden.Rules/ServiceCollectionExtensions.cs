using Microsoft.Extensions.DependencyInjection;
using Warden.Core;

namespace Warden.Rules;

/// <summary>
/// Dependency-injection registration for the Warden.Rules tier.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the rules tiers — <see cref="RulesEngine"/> and <see cref="WhitelistVerdictSource"/> —
    /// as <see cref="IVerdictSource"/> implementations. The pipeline orders sources by
    /// <see cref="VerdictSourceKind"/>, so registration order here is not significant.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddWardenRules(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IVerdictSource, RulesEngine>();
        services.AddSingleton<IVerdictSource, WhitelistVerdictSource>();

        return services;
    }
}
