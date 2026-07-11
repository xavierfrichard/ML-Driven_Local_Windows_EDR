using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;

namespace Warden.WebApps;

/// <summary>DI registration for the Web Apps classifier (always-ON; no toggle).</summary>
[SupportedOSPlatform("windows")]
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenWebApps(this IServiceCollection services)
    {
        services.AddSingleton<IWebAppInputCollector, WebAppInputCollector>();
        services.AddSingleton<IWebAppRuntimeCollector, WebAppRuntimeCollector>();
        services.AddSingleton<WebAppClassifier>();
        return services;
    }
}
