using Microsoft.Extensions.DependencyInjection;

namespace Warden.Etw;

/// <summary>DI registration for the ETW telemetry sources.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenEtw(this IServiceCollection services)
    {
        services.AddSingleton<IProcessStartSource, KernelProcessSession>();
        services.AddSingleton<ICodeIntegrityBlockSource, CodeIntegritySession>();
        return services;
    }
}
