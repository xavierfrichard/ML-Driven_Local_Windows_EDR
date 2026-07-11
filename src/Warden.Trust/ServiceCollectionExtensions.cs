using Microsoft.Extensions.DependencyInjection;
using Warden.Core;

namespace Warden.Trust;

/// <summary>
/// Dependency-injection wiring for the Warden trust tier.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the trust tier: <see cref="IFileInspector"/>, the singleton
    /// <see cref="TrustGateOptions"/>, and the <see cref="AuthenticodeTrustGate"/> as an
    /// <see cref="IVerdictSource"/>.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Optional callback to customize the trust policy.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    public static IServiceCollection AddWardenTrust(
        this IServiceCollection services,
        Action<TrustGateOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new TrustGateOptions();
        configure?.Invoke(options);

        services.AddSingleton(options);
        services.AddSingleton<IFileInspector, FileInspector>();
        services.AddSingleton<IVerdictSource, AuthenticodeTrustGate>();

        return services;
    }
}
