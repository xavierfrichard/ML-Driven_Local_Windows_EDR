using Microsoft.Extensions.DependencyInjection;

namespace Warden.Storage;

/// <summary>DI registration for the Warden storage layer.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the SQLite database and repositories. The host calls
    /// <see cref="IWardenDatabase.Initialize"/> once at startup.
    /// </summary>
    public static IServiceCollection AddWardenStorage(this IServiceCollection services)
    {
        services.AddSingleton<IWardenDatabase, WardenDb>();
        services.AddSingleton<IWhitelistRepository, WhitelistRepository>();
        services.AddSingleton<IRulesRepository, RulesRepository>();
        return services;
    }
}
