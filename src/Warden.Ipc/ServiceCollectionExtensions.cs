using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Warden.Ipc;

/// <summary>
/// Receives security-relevant IPC refusals (rejected peer image, non-admin Allow, squatted pipe name,
/// oversized frame). The service adapts this to its tamper log; if nothing is registered the events are
/// only written to the ordinary log.
/// </summary>
public interface IPipeSecurityEventSink
{
    void OnSecurityEvent(string message);
}

/// <summary>Dependency-injection registration for the service-side IPC channels.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="PromptPipeServer"/> as a singleton exposed as <see cref="IPromptPresenter"/>,
    /// and hosts it as an <see cref="IHostedService"/> so its named-pipe accept loop starts with the
    /// host and is disposed on shutdown.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="options">Peer policy for both channels; defaults to the strict production policy.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddWardenIpcServer(this IServiceCollection services, PipeServerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(options ?? new PipeServerOptions());

        // Single instance shared by the presenter contract and the hosted-service lifecycle.
        services.TryAddSingleton(sp =>
        {
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<PromptPipeServer>();
            return new PromptPipeServer(
                ex => logger.LogWarning(ex, "Prompt pipe error (connection dropped or malformed frame)."),
                sp.GetRequiredService<PipeServerOptions>(),
                SecuritySink(sp, logger));
        });
        services.TryAddSingleton<IPromptPresenter>(sp => sp.GetRequiredService<PromptPipeServer>());
        services.AddHostedService<PromptPipeServerHostedService>();

        return services;
    }

    /// <summary>
    /// Registers the management channel host. Requires an <see cref="IMgmtHandler"/> registration (the
    /// service supplies one over its repositories) and starts the pipe with the host.
    /// </summary>
    public static IServiceCollection AddWardenMgmtServer(this IServiceCollection services, PipeServerOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(options ?? new PipeServerOptions());

        services.TryAddSingleton(sp =>
        {
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<MgmtPipeServer>();
            return new MgmtPipeServer(
                sp.GetRequiredService<IMgmtHandler>(),
                ex => logger.LogWarning(ex, "Management pipe error (connection dropped or malformed frame)."),
                sp.GetRequiredService<PipeServerOptions>(),
                SecuritySink(sp, logger));
        });
        services.AddHostedService<MgmtPipeServerHostedService>();

        return services;
    }

    private static Action<string> SecuritySink(IServiceProvider sp, ILogger logger)
    {
        IPipeSecurityEventSink? sink = sp.GetService<IPipeSecurityEventSink>();
        return message =>
        {
            logger.LogWarning("IPC security event: {Message}", message);
            sink?.OnSecurityEvent(message);
        };
    }
}

/// <summary>Starts the management pipe with the host and disposes it on shutdown.</summary>
internal sealed class MgmtPipeServerHostedService : IHostedService
{
    private readonly MgmtPipeServer _server;

    public MgmtPipeServerHostedService(MgmtPipeServer server) => _server = server;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _server.Start();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _server.Dispose();
        return Task.CompletedTask;
    }
}

/// <summary>
/// Adapts <see cref="PromptPipeServer"/> to the host lifecycle: starts the accept loop on host
/// startup and disposes the server on shutdown.
/// </summary>
internal sealed class PromptPipeServerHostedService : IHostedService
{
    private readonly PromptPipeServer _server;

    public PromptPipeServerHostedService(PromptPipeServer server)
    {
        _server = server;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _server.Start();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _server.Dispose();
        return Task.CompletedTask;
    }
}
