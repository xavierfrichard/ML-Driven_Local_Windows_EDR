using Microsoft.Extensions.DependencyInjection;

namespace Warden.Quarantine;

/// <summary>DI registration for the quarantine store.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenQuarantine(
        this IServiceCollection services, Action<QuarantineOptions>? configure = null)
    {
        var options = new QuarantineOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton<IQuarantineStore, QuarantineStore>();
        return services;
    }
}
