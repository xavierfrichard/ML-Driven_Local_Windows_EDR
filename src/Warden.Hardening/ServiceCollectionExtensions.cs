using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Core;

namespace Warden.Hardening;

/// <summary>DI registration for the hardening / self-protection layer and structured logging.</summary>
[SupportedOSPlatform("windows")]
public static class ServiceCollectionExtensions
{
    /// <summary>Size at which the day's log file rolls over to a new file (<c>warden-&lt;date&gt;_001.log</c>, …).</summary>
    public const long LogFileSizeLimitBytes = 50L * 1024 * 1024;

    /// <summary>Most log files kept. With rolling on size this caps the log at about 3 GB.</summary>
    public const int RetainedLogFileCount = 60;

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
    /// Route Microsoft.Extensions.Logging through Serilog with a rolling file sink plus a console sink for
    /// dev. The file rolls daily <b>and</b> at <see cref="LogFileSizeLimitBytes"/>, so flooding the log
    /// cannot stop it being written for the rest of the day (the old 1 GB/day cap without rolling did).
    /// Files older than 14 days, and beyond <see cref="RetainedLogFileCount"/>, are deleted.
    /// </summary>
    /// <remarks>
    /// The file sink is not added when the log directory, or a folder above it, is a junction or symbolic
    /// link: SYSTEM would otherwise create and append files wherever it points. The service's startup
    /// data-directory check then refuses to run and reports why.
    /// </remarks>
    public static IServiceCollection AddWardenLogging(this IServiceCollection services, string? logDirectory = null)
    {
        string dir = logDirectory ?? Warden.Core.WardenPaths.Under("logs");
        string? redirect = FindReparsePointOnPath(dir);
        if (redirect is null)
        {
            try { Directory.CreateDirectory(dir); } catch { /* best effort; Serilog falls back gracefully */ }
            redirect = FindReparsePointOnPath(dir); // created through a link swapped in meanwhile?
        }
        if (redirect is not null)
        {
            Console.Error.WriteLine($"Warden: not writing the log file: {redirect} is a junction or symbolic link.");
        }

        services.AddSerilog(lc =>
        {
            lc.MinimumLevel.Information()
              .Enrich.FromLogContext()
              // Attacker-controlled strings (paths, command lines, signer subjects) are logged constantly;
              // escape control and bidi characters so they cannot forge lines in the security audit log.
              .Enrich.With<ControlCharacterSanitizingEnricher>();

            // Exception text is escaped by a sink wrapper (an enricher cannot replace it).
            LoggerConfiguration sinks = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Console();
            if (redirect is null)
            {
                sinks = sinks.WriteTo.File(
                    Path.Combine(dir, "warden-.log"),
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: LogFileSizeLimitBytes,
                    rollOnFileSizeLimit: true,
                    retainedFileCountLimit: RetainedLogFileCount,
                    retainedFileTimeLimit: TimeSpan.FromDays(14),
                    shared: true);
            }
            Logger inner = sinks.CreateLogger();
            lc.WriteTo.Sink(new ExceptionSanitizingSink(inner));
        });
        return services;
    }

    /// <summary>The first existing folder on <paramref name="path"/> (itself or an ancestor) that is a reparse point, or null.</summary>
    internal static string? FindReparsePointOnPath(string path)
    {
        try
        {
            for (DirectoryInfo? d = new(Path.GetFullPath(path)); d is not null; d = d.Parent)
            {
                if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return d.FullName;
                }
            }
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return path; // cannot tell: treat as unsafe
        }
    }
}
