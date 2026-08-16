using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text.Json;

namespace Warden.Ipc;

/// <summary>
/// Service-side (session 0) named-pipe host for the block-prompt channel. Hosts a single
/// <see cref="NamedPipeServerStream"/> on <see cref="IpcProtocol.PipeName"/> and keeps at most one
/// connected tray-UI client, reconnecting automatically when the client drops.
/// </summary>
/// <remarks>
/// <para><b>Who may answer a prompt.</b> A prompt answer of <c>Allow</c> results in a persistent WDAC
/// allow rule, so the peer must be authenticated. Three layers: (1) the pipe DACL admits only SYSTEM,
/// Administrators and the service's own account (see <see cref="PipeGuard.BuildServerSecurity"/>), and
/// the instance is created with <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c> so a pre-created (squatted) pipe is
/// detected instead of joined; (2) the client image name must be on the allow-list (the tray UI);
/// (3) an <c>Allow</c> reply is honoured only when the impersonated client token is an Administrators
/// member — anything else is downgraded to KeepBlocked and reported.</para>
/// <para>The wire format is newline-delimited UTF-8 JSON (<see cref="IpcProtocol.Json"/>), read through
/// a <see cref="BoundedLineReader"/> so an oversized frame drops the connection instead of growing
/// memory. Each <see cref="PromptRequest"/> is one line and the UI replies with one
/// <see cref="PromptResponse"/> line carrying the same <see cref="PromptRequest.RequestId"/>.</para>
/// <para>The presenter is fail-safe by construction. If no UI is connected, the write fails, the
/// client disconnects, or the user does not answer within
/// <see cref="PromptRequest.AutoDismissSeconds"/> plus a small grace, <see cref="PromptAsync"/>
/// resolves to <see cref="PromptDecision.Timeout"/> — the OS-level block stays in place and nothing is
/// persisted, so the user is asked again next time. A broken, absent or unauthenticated UI can therefore
/// never turn a blocked launch into a silent allow.</para>
/// </remarks>
public sealed class PromptPipeServer : IPromptPresenter, IDisposable
{
    /// <summary>Extra seconds added to the client-side auto-dismiss to bound the service-side wait.</summary>
    private const int GraceSeconds = 5;

    private readonly Action<Exception>? _onError;
    private readonly Action<string>? _onSecurityEvent;
    private readonly PipeServerOptions _options;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // Pending prompts keyed by RequestId. The accept/read loop dispatches responses (and disconnect
    // notifications) into these, so concurrent PromptAsync calls are correlated by id and never
    // interleave their framing on the single pipe.
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<PromptResponse>> _pending = new();

    // The currently connected client stream, or null while waiting for a connection. Volatile so
    // PromptAsync sees connect/disconnect transitions published by the accept loop.
    private volatile NamedPipeServerStream? _currentPipe;

    private Task? _acceptLoop;
    private bool _started;
    private bool _disposed;
    private readonly object _startGate = new();

    /// <summary>Creates the server. Call <see cref="Start"/> to begin accepting connections.</summary>
    /// <param name="onError">
    /// Optional callback invoked when a background pipe error occurs. Use this to log; do not throw
    /// from it. Errors never surface to callers of <see cref="PromptAsync"/>, which fail safe.
    /// </param>
    /// <param name="options">Peer policy; defaults to the strict production policy.</param>
    /// <param name="onSecurityEvent">
    /// Optional callback for security-relevant refusals (rejected peer image, non-admin Allow, squatted
    /// pipe). The service routes these to the tamper log.
    /// </param>
    public PromptPipeServer(Action<Exception>? onError = null, PipeServerOptions? options = null, Action<string>? onSecurityEvent = null)
    {
        _onError = onError;
        _options = options ?? new PipeServerOptions();
        _onSecurityEvent = onSecurityEvent;
    }

    /// <summary>True while a tray-UI client is connected and able to receive prompts.</summary>
    public bool IsClientConnected
    {
        get
        {
            var pipe = _currentPipe;
            return pipe is not null && pipe.IsConnected;
        }
    }

    /// <summary>
    /// Launches the background accept loop that hosts the pipe and keeps one UI client connected.
    /// Idempotent and safe to call from host startup; a no-op after <see cref="Dispose"/>.
    /// </summary>
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

    /// <inheritdoc />
    /// <remarks>
    /// Returns <see cref="PromptDecision.Timeout"/> immediately if no client is connected, and on
    /// any write failure, disconnect, cancellation, or timeout while awaiting the reply.
    /// </remarks>
    public async Task<PromptResponse> PromptAsync(PromptRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var pipe = _currentPipe;
        if (_disposed || pipe is null || !pipe.IsConnected)
        {
            // Fail safe: nobody to ask. Unanswered, not "decided": the block stands but is not persisted.
            return Unanswered(request);
        }

        var tcs = new TaskCompletionSource<PromptResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(request.RequestId, tcs))
        {
            // Duplicate in-flight id (should not happen with Guids); fail safe rather than corrupt state.
            return Unanswered(request);
        }

        try
        {
            await WriteRequestAsync(pipe, request, cancellationToken).ConfigureAwait(false);

            var timeout = TimeSpan.FromSeconds(Math.Max(0, request.AutoDismissSeconds) + GraceSeconds);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);
            timeoutCts.CancelAfter(timeout);

            // On timeout, service shutdown, or caller cancellation, resolve to the safe default.
            await using var registration = timeoutCts.Token.Register(
                static state =>
                {
                    var (source, req) = ((TaskCompletionSource<PromptResponse>, PromptRequest))state!;
                    source.TrySetResult(new PromptResponse(req.RequestId, PromptDecision.Timeout));
                },
                (tcs, request)).ConfigureAwait(false);

            var response = await tcs.Task.ConfigureAwait(false);

            // Guard against a stray reply carrying the wrong id.
            return response.RequestId == request.RequestId ? response : Unanswered(request);
        }
        catch (Exception ex)
        {
            // Write failure, disconnect mid-flight, or serialization error: never throw out of the hot path.
            _onError?.Invoke(ex);
            return Unanswered(request);
        }
        finally
        {
            _pending.TryRemove(request.RequestId, out _);
        }
    }

    private async Task WriteRequestAsync(
        NamedPipeServerStream pipe,
        PromptRequest request,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(request, IpcProtocol.Json);
        var frame = new byte[json.Length + 1];
        Buffer.BlockCopy(json, 0, frame, 0, json.Length);
        frame[json.Length] = (byte)'\n';

        // Serialize writes so concurrent prompts cannot interleave their framing on the shared pipe.
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await pipe.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            bool backOff = false;
            try
            {
                // Max one instance and FirstPipeInstance on every create: our previous instance is always
                // disposed before the next create, so if the name already exists someone else owns it.
                pipe = CreateServerStream();

                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                if (!PeerAllowed(pipe))
                {
                    backOff = true; // don't let a rejected peer make us spin re-accepting it
                    continue;
                }

                _currentPipe = pipe;
                await ReadLoopAsync(pipe, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (UnauthorizedAccessException ex)
            {
                // FirstPipeInstance: the name already exists and we did not create it → squatting attempt
                // (or a second Warden instance). Report, back off, retry — never join it.
                _onSecurityEvent?.Invoke($"Prompt pipe '{_options.PromptPipeName}' already exists and is not ours: {ex.Message}");
                _onError?.Invoke(ex);
                backOff = true;
            }
            catch (Exception ex)
            {
                // A broken connection (client crash, pipe error) is expected; log and rebuild the pipe.
                _onError?.Invoke(ex);
                backOff = true;
            }
            finally
            {
                _currentPipe = null;
                FailPending();
                pipe?.Dispose();
            }

            if (backOff)
            {
                try
                {
                    await Task.Delay(_options.RetryBackoff, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private NamedPipeServerStream CreateServerStream()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Non-Windows hosts (unit tests on CI) get the default DACL; the product is Windows-only.
            return new NamedPipeServerStream(
                _options.PromptPipeName,
                PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
        }

        return PipeGuard.CreateServer(_options.PromptPipeName, maxInstances: 1, firstInstance: true);
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
            $"Rejected prompt-pipe client pid {peer.ProcessId} image '{peer.ImagePath ?? "<unknown>"}' (not an allowed UI image).");
        return false;
    }

    private async Task ReadLoopAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var reader = new BoundedLineReader(pipe, _options.MaxFrameBytes);
        bool? callerIsAdmin = null;

        while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (IpcFrameTooLargeException ex)
            {
                _onSecurityEvent?.Invoke("Prompt-pipe client sent an oversized frame; connection dropped.");
                _onError?.Invoke(ex);
                return;
            }

            if (line is null)
            {
                // Client closed the connection.
                break;
            }

            if (line.Length == 0)
            {
                continue;
            }

            // The client's security context is attached to the first message read; resolve it now, once.
            callerIsAdmin ??= OperatingSystem.IsWindows() && PipeGuard.ClientIsAdministrator(pipe, _onError);

            PromptResponse? response;
            try
            {
                response = JsonSerializer.Deserialize<PromptResponse>(line, IpcProtocol.Json);
            }
            catch (JsonException ex)
            {
                // Ignore malformed frames rather than tearing down the connection.
                _onError?.Invoke(ex);
                continue;
            }

            if (response is null)
            {
                continue;
            }

            if (response.Decision == PromptDecision.Allow
                && _options.RequireAdministratorForAllow
                && callerIsAdmin != true)
            {
                _onSecurityEvent?.Invoke(
                    $"Prompt {response.RequestId} answered Allow by a non-Administrator client; downgraded to KeepBlocked.");
                response = new PromptResponse(response.RequestId, PromptDecision.Timeout);
            }

            if (_pending.TryGetValue(response.RequestId, out var tcs))
            {
                tcs.TrySetResult(response);
            }
        }
    }

    // Resolve every in-flight prompt to the safe default when the client disconnects.
    private void FailPending()
    {
        foreach (var entry in _pending)
        {
            entry.Value.TrySetResult(new PromptResponse(entry.Key, PromptDecision.Timeout));
        }
    }

    private static PromptResponse Unanswered(PromptRequest request) =>
        new(request.RequestId, PromptDecision.Timeout);

    /// <summary>Stops the accept loop, disconnects any client, and releases all resources.</summary>
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

        // Unblock WaitForConnectionAsync / ReadLineAsync and resolve outstanding prompts.
        _currentPipe?.Dispose();
        _currentPipe = null;
        FailPending();

        try
        {
            _acceptLoop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception ex)
        {
            _onError?.Invoke(ex);
        }

        _cts.Dispose();
        _writeLock.Dispose();
    }
}
