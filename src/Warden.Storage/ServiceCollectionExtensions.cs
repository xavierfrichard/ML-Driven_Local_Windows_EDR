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
        services.AddSingleton<IAttackChainRepository, AttackChainRepository>();
        services.AddSingleton<ICommandLineRepository, CommandLineRepository>();
        services.AddSingleton<IQuarantineRepository, QuarantineRepository>();
        services.AddSingleton<IProtectedFolderRepository, ProtectedFolderRepository>();
        services.AddSingleton<IReputationCacheRepository, ReputationCacheRepository>();
        services.AddSingleton<IVulnerableAppRepository, VulnerableAppRepository>();
        services.AddSingleton<IMitigationProfileRepository, MitigationProfileRepository>();
        services.AddSingleton<IFirewallRuleRepository, FirewallRuleRepository>();
        services.AddSingleton<IWebAppClassificationRepository, WebAppClassificationRepository>();
        services.AddSingleton<ITamperLogRepository, TamperLogRepository>();
        return services;
    }
}
