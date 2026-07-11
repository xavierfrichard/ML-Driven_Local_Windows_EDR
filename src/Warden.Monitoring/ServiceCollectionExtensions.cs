using Microsoft.Extensions.DependencyInjection;

namespace Warden.Monitoring;

/// <summary>DI registration for the monitoring subsystem (command-line recorder + protected-folder monitor).</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenMonitoring(this IServiceCollection services)
    {
        services.AddSingleton<ICommandLineRecorder, CommandLineRecorder>();
        services.AddSingleton<IProtectedFolderMonitor, ProtectedFolderMonitor>();
        return services;
    }
}
