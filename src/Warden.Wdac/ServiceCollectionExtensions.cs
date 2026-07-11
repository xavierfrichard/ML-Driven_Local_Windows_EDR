using Microsoft.Extensions.DependencyInjection;

namespace Warden.Wdac;

/// <summary>DI registration for the WDAC allow-list manager.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenWdac(this IServiceCollection services, Action<WdacOptions>? configure = null)
    {
        var options = new WdacOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton<ProcessRunner>();
        services.AddSingleton<IWdacAllowlistManager, WdacAllowlistManager>();
        return services;
    }
}
