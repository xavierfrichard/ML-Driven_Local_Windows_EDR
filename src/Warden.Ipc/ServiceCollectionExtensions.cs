using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Warden.Ipc;

/// <summary>Dependency-injection registration for the service-side IPC prompt channel.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="PromptPipeServer"/> as a singleton exposed as <see cref="IPromptPresenter"/>,
    /// and hosts it as an <see cref="IHostedService"/> so its named-pipe accept loop starts with the
    /// host and is disposed on shutdown.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddWardenIpcServer(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Single instance shared by the presenter contract and the hosted-service lifecycle.
        services.TryAddSingleton<PromptPipeServer>();
        services.TryAddSingleton<IPromptPresenter>(sp => sp.GetRequiredService<PromptPipeServer>());
        services.AddHostedService<PromptPipeServerHostedService>();

        return services;
    }

    /// <summary>
    /// Registers the management channel host. Requires an <see cref="IMgmtHandler"/> registration (the
    /// service supplies one over its repositories) and starts the pipe with the host.
    /// </summary>
    public static IServiceCollection AddWardenMgmtServer(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(sp => new MgmtPipeServer(
            sp.GetRequiredService<IMgmtHandler>(),
            ex => sp.GetRequiredService<ILoggerFactory>()
                .CreateLogger<MgmtPipeServer>()
                .LogWarning(ex, "Management pipe error (connection dropped or malformed frame).")));
        services.AddHostedService<MgmtPipeServerHostedService>();

        return services;
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
