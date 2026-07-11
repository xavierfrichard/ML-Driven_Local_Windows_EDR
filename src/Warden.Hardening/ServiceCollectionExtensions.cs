using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace Warden.Hardening;

/// <summary>DI registration for the hardening / self-protection layer and structured logging.</summary>
[SupportedOSPlatform("windows")]
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Register the hardening services. This registers only — it applies no ACL and changes nothing on
    /// the system. The data-directory lockdown runs on startup only when
    /// <see cref="HardeningOptions.EnforceOnStartup"/> is set (the installer turns it on).
    /// </summary>
    public static IServiceCollection AddWardenHardening(this IServiceCollection services, Action<HardeningOptions>? configure = null)
    {
        var options = new HardeningOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        services.AddSingleton<DataDirectoryHardener>();
        services.AddSingleton<ITamperLog, TamperLog>();
        return services;
    }

    /// <summary>
    /// Route Microsoft.Extensions.Logging through Serilog with a rolling daily file sink (retained 14
    /// days, shared so the service and the user-session UI can both write) plus a console sink for dev.
    /// </summary>
    public static IServiceCollection AddWardenLogging(this IServiceCollection services, string? logDirectory = null)
    {
        string dir = logDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Warden", "logs");
        try { Directory.CreateDirectory(dir); } catch { /* best effort; Serilog falls back gracefully */ }

        services.AddSerilog(lc => lc
            .MinimumLevel.Information()
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .WriteTo.File(
                Path.Combine(dir, "warden-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                shared: true));
        return services;
    }
}
