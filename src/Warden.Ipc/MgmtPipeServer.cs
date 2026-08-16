using System.IO.Pipes;
using System.Text.Json;

namespace Warden.Ipc;

/// <summary>
/// Service-side host for the management channel: the tray UI asks for panel data and policy edits over
/// this pipe instead of opening the hardened SQLite file itself (the data directory is ACL-locked to
/// SYSTEM + Administrators, so a user-session UI cannot read or write it directly).
/// </summary>
/// <remarks>
/// <para><b>Authorization.</b> The pipe DACL (<see cref="PipeGuard.BuildServerSecurity"/>) admits only
/// SYSTEM, Administrators and the service's own account, so a non-elevated process cannot connect at
/// all — the panel data (whitelist, command lines, quarantine, tamper log) is not readable by every
/// local user. On top of that, after the first request has been read the server impersonates the caller
/// and resolves whether their token is a member of the local Administrators group; any operation in
/// <see cref="MgmtOperations.Mutations"/> is refused when it is not. Under UAC a non-elevated
/// administrator's token carries the Administrators SID as deny-only, so
/// <see cref="System.Security.Principal.WindowsPrincipal.IsInRole(System.Security.Principal.WindowsBuiltInRole)"/>
/// correctly reports false there. The membership check is deliberately deferred until a frame has been
/// read: Windows attaches the client's security context to the first message, and impersonating earlier
/// fails with ERROR_CANNOT_IMPERSONATE (which would silently refuse every mutation).</para>
/// <para><b>Fail-safe.</b> Every failure path returns an <see cref="MgmtResponse"/> with
/// <c>Ok = false</c> and a message. A malformed frame, a handler exception, or a dropped client never
/// tears down the server or mutates state. Frames are read through a <see cref="BoundedLineReader"/>;
/// an oversized frame or an idle connection drops that client only.</para>
/// </remarks>
public sealed class MgmtPipeServer : IDisposable
{
    /// <summary>Concurrent pipe instances. The UI uses one; the spare capacity absorbs reconnects.</summary>
    private const int MaxServerInstances = 8;

    private readonly IMgmtHandler _handler;
    private readonly Action<Exception>? _onError;
    private readonly Action<string>? _onSecurityEvent;
    private readonly PipeServerOptions _options;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _startGate = new();
    private readonly SemaphoreSlim _connectionSlots = new(MaxServerInstances, MaxServerInstances);

    private Task? _acceptLoop;
    private bool _started;
    private bool _disposed;
    private bool _createdFirstInstance;

    public MgmtPipeServer(
        IMgmtHandler handler,
        Action<Exception>? onError = null,
        PipeServerOptions? options = null,
        Action<string>? onSecurityEvent = null)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _onError = onError;
        _options = options ?? new PipeServerOptions();
        _onSecurityEvent = onSecurityEvent;
    }

    /// <summary>Starts accepting management clients. Idempotent; a no-op after <see cref="Dispose"/>.</summary>
    public void Start()
    {
        lock (_startGate)
        {
            if (_started || _disposed)
            {
                return;
            }

            _started = true;
            _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            bool slotTaken = false;
            try
            {
                // Bound the number of simultaneously served clients so nobody can hold every instance.
                await _connectionSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
                slotTaken = true;

                pipe = CreateServerStream();
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                if (!PeerAllowed(pipe))
                {
                    pipe.Dispose();
                    pipe = null;
                    ReleaseSlot();
                    slotTaken = false;
                    await Task.Delay(_options.RetryBackoff, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                // Serve this client on its own task so the loop can immediately host another instance.
                NamedPipeServerStream connected = pipe;
                pipe = null;
                slotTaken = false; // ownership of the slot moves to the serve task
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await ServeClientAsync(connected, cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        ReleaseSlot();
                    }
                }, CancellationToken.None);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (UnauthorizedAccessException ex)
            {
                // FirstPipeInstance: the name already exists and we did not create it → squatting attempt.
                _onSecurityEvent?.Invoke($"Management pipe '{_options.MgmtPipeName}' already exists and is not ours: {ex.Message}");
                _onError?.Invoke(ex);
                pipe?.Dispose();
                if (slotTaken) { ReleaseSlot(); }
                if (!await BackOffAsync(cancellationToken).ConfigureAwait(false)) { break; }
            }
            catch (Exception ex)
            {
                _onError?.Invoke(ex);
                pipe?.Dispose();
                if (slotTaken) { ReleaseSlot(); }
                if (!await BackOffAsync(cancellationToken).ConfigureAwait(false)) { break; }
            }
        }
    }

    private void ReleaseSlot()
    {
        try
        {
            _connectionSlots.Release();
        }
        catch (ObjectDisposedException)
        {
            // Server already disposed; the slot no longer matters.
        }
        catch (SemaphoreFullException)
        {
            // Defensive: never let slot accounting take a serve task down.
        }
    }

    private async Task<bool> BackOffAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_options.RetryBackoff, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>
    /// Creates a pipe instance with the Warden DACL. The very first instance is created with
    /// <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c> so a pre-created pipe of the same name (squatting) fails loudly
    /// instead of being joined; later instances co-exist with our own.
    /// </summary>
    private NamedPipeServerStream CreateServerStream()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Non-Windows hosts (unit tests on CI) get the default DACL; the product is Windows-only.
            return new NamedPipeServerStream(
                _options.MgmtPipeName,
                PipeDirection.InOut,
                MaxServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }

        bool first = !_createdFirstInstance;
        NamedPipeServerStream stream = PipeGuard.CreateServer(_options.MgmtPipeName, MaxServerInstances, firstInstance: first);
        _createdFirstInstance = true;
        return stream;
    }

    private bool PeerAllowed(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows() || _options.AllowedClientImageNames.Count == 0)
        {
            return true;
        }

        PipePeer peer = PipeGuard.ResolvePeer(pipe);
        if (PipeGuard.PeerImageAllowed(peer, (IReadOnlyCollection<string>)_options.AllowedClientImageNames))
        {
            return true;
        }

        _onSecurityEvent?.Invoke(
            $"Rejected management-pipe client pid {peer.ProcessId} image '{peer.ImagePath ?? "<unknown>"}' (not an allowed UI image).");
        return false;
    }

    private async Task ServeClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            var reader = new BoundedLineReader(pipe, _options.MaxFrameBytes);
            bool? callerIsAdmin = null;

            while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
            {
                string? line;
                using (var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    idle.CancelAfter(_options.IdleTimeout);
                    try
                    {
                        line = await reader.ReadLineAsync(idle.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                    {
                        // Idle client: free the instance for someone else.
                        break;
                    }
                    catch (IpcFrameTooLargeException ex)
                    {
                        _onSecurityEvent?.Invoke("Management-pipe client sent an oversized frame; connection dropped.");
                        _onError?.Invoke(ex);
                        break;
                    }
                }

                if (line is null)
                {
                    break;
                }

                if (line.Length == 0)
                {
                    continue;
                }

                // Now that a frame has been read, the client's token can be impersonated (see class remarks).
                callerIsAdmin ??= OperatingSystem.IsWindows() && PipeGuard.ClientIsAdministrator(pipe, _onError);

                MgmtResponse response = await DispatchAsync(line, callerIsAdmin.Value, cancellationToken).ConfigureAwait(false);
                await WriteResponseAsync(pipe, response, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        catch (Exception ex)
        {
            _onError?.Invoke(ex);
        }
        finally
        {
            try
            {
                if (pipe.IsConnected)
                {
                    pipe.Disconnect();
                }
            }
            catch (Exception ex)
            {
                _onError?.Invoke(ex);
            }

            pipe.Dispose();
        }
    }

    private async Task<MgmtResponse> DispatchAsync(string line, bool callerIsAdmin, CancellationToken cancellationToken)
    {
        MgmtRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<MgmtRequest>(line, IpcProtocol.Json);
        }
        catch (JsonException ex)
        {
            _onError?.Invoke(ex);
            return MgmtResponse.Fail(Guid.Empty, "Malformed request.");
        }

        if (request is null || string.IsNullOrWhiteSpace(request.Operation))
        {
            return MgmtResponse.Fail(request?.RequestId ?? Guid.Empty, "Malformed request.");
        }

        // Answered here so the UI can grey out mutation controls without a round-trip through the handler.
        if (string.Equals(request.Operation, MgmtOperations.WhoAmI, StringComparison.Ordinal))
        {
            return MgmtResponse.Success(request.RequestId, JsonSerializer.Serialize(new WhoAmIPayload(callerIsAdmin), IpcProtocol.Json));
        }

        // Authorization is enforced here, ahead of the handler, so a handler bug cannot bypass it.
        // Default-deny: anything not on the read allow-list is treated as a mutation.
        if (!MgmtOperations.IsRead(request.Operation) && !callerIsAdmin)
        {
            return MgmtResponse.Fail(request.RequestId, MgmtProtocol.ElevationRequired);
        }

        try
        {
            return await _handler.HandleAsync(request, callerIsAdmin, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Log the detail service-side; hand the client a generic message (no SQL/table/path leakage).
            _onError?.Invoke(ex);
            return MgmtResponse.Fail(request.RequestId, "The operation failed; see the agent log for details.");
        }
    }

    private static async Task WriteResponseAsync(
        NamedPipeServerStream pipe,
        MgmtResponse response,
        CancellationToken cancellationToken)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(response, IpcProtocol.Json);
        var frame = new byte[json.Length + 1];
        Buffer.BlockCopy(json, 0, frame, 0, json.Length);
        frame[json.Length] = (byte)'\n';

        await pipe.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        lock (_startGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        try
        {
            _cts.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already torn down.
        }

        try
        {
            _acceptLoop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception ex)
        {
            _onError?.Invoke(ex);
        }

        _cts.Dispose();
        _connectionSlots.Dispose();
    }
}
