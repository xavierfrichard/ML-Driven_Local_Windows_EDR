using Microsoft.Extensions.DependencyInjection;

namespace Warden.Amsi;

/// <summary>DI registration for the AMSI scanner.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenAmsi(this IServiceCollection services)
    {
        services.AddSingleton<IAmsiScanner, AmsiScanner>();
        return services;
    }
}
