using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text.Json;

namespace Warden.Ipc;

/// <summary>
/// Service-side (session 0) named-pipe host for the block-prompt channel. Serves at most one connected
/// tray-UI client on <see cref="IpcProtocol.PipeName"/>, reconnecting automatically when the client drops.
/// </summary>
/// <remarks>
/// <para><b>The name is never free.</b> Besides the connected instance the server always holds one
/// listening instance: the next instance is created before the current one is served or disposed, and
/// a failed connection does not leave a gap. Whenever the server holds no instance at all (start-up, or
/// after a create failed) it creates with <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c>, so a pre-created
/// (squatted) pipe is detected and reported instead of joined (see <see cref="PipeInstanceSet{T}"/>).
/// A second client that connects while one is being served waits on the listener and takes over when the
/// first one leaves.</para>
/// <para><b>Who may answer a prompt.</b> A prompt answer of <c>Allow</c> results in a persistent WDAC
/// allow rule, so the peer must be authenticated. Three layers: (1) the pipe DACL admits only SYSTEM,
/// Administrators and the service's own account (see <see cref="PipeGuard.BuildServerSecurity"/>);
/// (2) the client's full image path must be the installed tray UI (<see cref="PipeGuard.PeerAllowed"/>);
/// (3) an <c>Allow</c> reply is honoured only when the impersonated client token is an Administrators
/// member — anything else is downgraded to KeepBlocked and reported. Security events are rate-limited per
/// category (<see cref="PipeServerOptions.SecurityEventInterval"/>).</para>
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

    /// <summary>One connected instance plus the listening one.</summary>
    private const int MaxServerInstances = 2;

    private readonly Action<Exception>? _onError;
    private readonly Action<string>? _onSecurityEvent;
    private readonly PipeServerOptions _options;
    private readonly SecurityEventThrottle _throttle;
    private readonly PipeInstanceSet<NamedPipeServerStream> _instances = new();
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
        _throttle = new SecurityEventThrottle(_options.SecurityEventInterval);
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
        // The instance waiting for the next client. Kept across iterations so the name is always held.
        NamedPipeServerStream? listener = null;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                NamedPipeServerStream? connected = null;
                bool backOff = false;
                try
                {
                    listener ??= TryCreateInstance();
                    if (listener is null)
                    {
                        backOff = true; // squatted or failed create: retry later, never join someone else's pipe
                    }
                    else if (!await TryAcceptAsync(listener, cancellationToken).ConfigureAwait(false))
                    {
                        // The instance broke before a client was accepted: replace it, creating the new one
                        // before releasing the old so the name stays held.
                        NamedPipeServerStream broken = listener;
                        listener = TryCreateInstance();
                        _instances.Release(broken);
                        backOff = listener is null;
                    }
                    else
                    {
                        connected = listener;

                        // Create the next listener before this connection is served or disposed, so the name
                        // is never free. If that fails, the loop retries once this client is done.
                        listener = TryCreateInstance();

                        if (!PeerAllowed(connected))
                        {
                            backOff = true; // don't let a rejected peer make us spin re-accepting it
                        }
                        else
                        {
                            _currentPipe = connected;
                            await ReadLoopAsync(connected, cancellationToken).ConfigureAwait(false);
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // A broken connection (client crash, pipe error) is expected; log it. The listener (if
                    // any) is still up, so the next client is accepted without a gap.
                    _onError?.Invoke(ex);
                    backOff = listener is null;
                }
                finally
                {
                    if (connected is not null)
                    {
                        _currentPipe = null;
                        FailPending();
                        _instances.Release(connected);
                    }
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
        finally
        {
            _instances.Release(listener);
        }
    }

    /// <summary>Waits for a client. False when the instance broke (e.g. a client connected and left at once).</summary>
    private async Task<bool> TryAcceptAsync(NamedPipeServerStream instance, CancellationToken cancellationToken)
    {
        try
        {
            await instance.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (IOException ex)
        {
            _onError?.Invoke(ex);
            return false;
        }
    }

    /// <summary>
    /// Creates a tracked instance, with <c>FILE_FLAG_FIRST_PIPE_INSTANCE</c> when the server holds none.
    /// Returns null (after reporting) if the name is taken by someone else or the create fails.
    /// </summary>
    private NamedPipeServerStream? TryCreateInstance()
    {
        bool firstInstance = false;
        try
        {
            return _instances.Create(first =>
            {
                firstInstance = first;
                return CreateServerStream(first);
            });
        }
        catch (ObjectDisposedException) when (_cts.IsCancellationRequested)
        {
            return null; // shutting down
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException || (firstInstance && ex is IOException))
        {
            // We held no instance, so the name already exists and is someone else's → squatting attempt
            // (or a second Warden instance). FirstPipeInstance reports ACCESS_DENIED, or PIPE_BUSY when the
            // squatter capped its instance count. Report (rate-limited), retry later — never join it.
            ReportSecurityEvent(
                PipeSecurityCategory.Squat,
                $"Prompt pipe '{_options.PromptPipeName}' already exists and is not ours: {ex.Message}",
                ex);
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _onError?.Invoke(ex);
            return null;
        }
    }

    private NamedPipeServerStream CreateServerStream(bool firstInstance)
    {
        if (!OperatingSystem.IsWindows())
        {
            // Non-Windows hosts (unit tests on CI) get the default DACL; the product is Windows-only.
            return new NamedPipeServerStream(
                _options.PromptPipeName,
                PipeDirection.InOut,
                MaxServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None));
        }

        return PipeGuard.CreateServer(_options.PromptPipeName, MaxServerInstances, firstInstance);
    }

    private bool PeerAllowed(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows()
            || (_options.AllowedClientImagePaths.Count == 0 && string.IsNullOrEmpty(_options.DevUiImageName)))
        {
            return true;
        }

        PipePeer peer = PipeGuard.ResolvePeer(pipe);
        if (PipeGuard.PeerAllowed(peer, _options))
        {
            return true;
        }

        ReportSecurityEvent(
            PipeSecurityCategory.PeerRejected,
            $"Rejected prompt-pipe client pid {peer.ProcessId} image '{peer.ImagePath ?? "<unknown>"}' (not the installed UI).");
        return false;
    }

    /// <summary>Reports a security event, at most once per category per <see cref="PipeServerOptions.SecurityEventInterval"/>.</summary>
    private void ReportSecurityEvent(string category, string message, Exception? error = null)
    {
        string? text = _throttle.Filter(category, message);
        if (text is null)
        {
            return;
        }

        _onSecurityEvent?.Invoke(text);
        if (error is not null)
        {
            _onError?.Invoke(error);
        }
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
                ReportSecurityEvent(PipeSecurityCategory.OversizedFrame, "Prompt-pipe client sent an oversized frame; connection dropped.", ex);
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
                ReportSecurityEvent(
                    PipeSecurityCategory.NonAdminAllow,
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

        // Unblock WaitForConnectionAsync / ReadLineAsync (listener and connected instance) and resolve
        // outstanding prompts.
        _instances.Close();
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
