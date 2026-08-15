using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Warden.Ipc;

/// <summary>
/// Service-side host for the management channel: the tray UI asks for panel data and policy edits over
/// this pipe instead of opening the hardened SQLite file itself (the data directory is ACL-locked to
/// SYSTEM + Administrators, so a user-session UI cannot read or write it directly).
/// </summary>
/// <remarks>
/// <para><b>Authorization.</b> The pipe's DACL lets any authenticated local user connect, so a
/// non-elevated UI can still browse every panel. Before dispatching, the server impersonates the
/// caller and resolves whether their token is a member of the local Administrators group; any
/// operation in <see cref="MgmtOperations.Mutations"/> is refused when it is not. Under UAC a
/// non-elevated administrator's token carries the Administrators SID as deny-only, so
/// <see cref="WindowsPrincipal.IsInRole(WindowsBuiltInRole)"/> correctly reports false there. This
/// keeps the security property the file ACL provided: code running as the user cannot whitelist
/// itself, which is the whole point of the agent.</para>
/// <para><b>Fail-safe.</b> Every failure path returns an <see cref="MgmtResponse"/> with
/// <c>Ok = false</c> and a message. A malformed frame, a handler exception, or a dropped client never
/// tears down the server or mutates state.</para>
/// </remarks>
public sealed class MgmtPipeServer : IDisposable
{
    /// <summary>Concurrent pipe instances. The UI uses one; the spare capacity absorbs reconnects.</summary>
    private const int MaxServerInstances = 8;

    private readonly IMgmtHandler _handler;
    private readonly Action<Exception>? _onError;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _startGate = new();

    private Task? _acceptLoop;
    private bool _started;
    private bool _disposed;

    public MgmtPipeServer(IMgmtHandler handler, Action<Exception>? onError = null)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _onError = onError;
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
            try
            {
                pipe = CreateServerStream();
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                // Serve this client on its own task so the loop can immediately host another instance.
                NamedPipeServerStream connected = pipe;
                pipe = null;
                _ = Task.Run(() => ServeClientAsync(connected, cancellationToken), CancellationToken.None);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _onError?.Invoke(ex);
                pipe?.Dispose();

                // All instances busy, or a transient pipe error: back off rather than spin.
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                continue;
            }

            pipe?.Dispose();
        }
    }

    /// <summary>
    /// Creates a pipe instance whose DACL grants SYSTEM and Administrators full control and lets
    /// authenticated users connect (read/write) so a non-elevated UI can still read panel data.
    /// </summary>
    private static NamedPipeServerStream CreateServerStream()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Non-Windows hosts (unit tests on CI) get the default DACL; the product is Windows-only.
            return new NamedPipeServerStream(
                MgmtProtocol.PipeName,
                PipeDirection.InOut,
                MaxServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }

        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            MgmtProtocol.PipeName,
            PipeDirection.InOut,
            MaxServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }

    private async Task ServeClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            bool callerIsAdmin = ResolveCallerIsAdmin(pipe);

            using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);

            while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
            {
                string? line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (line is null)
                {
                    break;
                }

                if (line.Length == 0)
                {
                    continue;
                }

                MgmtResponse response = await DispatchAsync(line, callerIsAdmin, cancellationToken).ConfigureAwait(false);
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

        // Authorization is enforced here, ahead of the handler, so a handler bug cannot bypass it.
        if (MgmtOperations.IsMutation(request.Operation) && !callerIsAdmin)
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
            _onError?.Invoke(ex);
            return MgmtResponse.Fail(request.RequestId, ex.Message);
        }
    }

    /// <summary>
    /// Impersonates the connected client and reports whether their token is an Administrators member.
    /// Any failure resolves to false (fail closed: the caller is treated as unprivileged).
    /// </summary>
    private bool ResolveCallerIsAdmin(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            return RunAsClientIsAdmin(pipe);
        }
        catch (Exception ex)
        {
            _onError?.Invoke(ex);
            return false;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool RunAsClientIsAdmin(NamedPipeServerStream pipe)
    {
        bool isAdmin = false;
        pipe.RunAsClient(() =>
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            isAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        });

        return isAdmin;
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
    }
}
