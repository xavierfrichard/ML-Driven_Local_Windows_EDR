using Microsoft.Extensions.DependencyInjection;

namespace Warden.Ui;

/// <summary>Dependency-injection registration for the Warden tray UI components.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the tray-UI IPC components. Registers <see cref="PromptPipeClient"/> as a singleton;
    /// the composition root is expected to assign its
    /// <see cref="PromptPipeClient.PromptHandler"/> and call <see cref="PromptPipeClient.Start"/>.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddWardenUi(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<PromptPipeClient>();
        return services;
    }
}
