using Microsoft.Extensions.DependencyInjection;
using Warden.Core;

namespace Warden.Reputation;

/// <summary>DI registration for the VirusTotal reputation tier.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenReputation(
        this IServiceCollection services, Action<ReputationOptions>? configure = null)
    {
        var options = new ReputationOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);

        services.AddHttpClient("virustotal", client =>
        {
            client.BaseAddress = options.BaseAddress;
            client.MaxResponseContentBufferSize = 4L * 1024 * 1024; // a hash report is a few KB
        });

        services.AddSingleton<VirusTotalClient>();
        services.AddSingleton<IVerdictSource>(sp => sp.GetRequiredService<VirusTotalClient>());
        return services;
    }
}
