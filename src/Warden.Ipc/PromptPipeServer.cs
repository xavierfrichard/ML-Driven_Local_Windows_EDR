using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Warden.Ipc;

/// <summary>
/// Service-side (session 0) named-pipe host for the block-prompt channel. Hosts a single
/// <see cref="NamedPipeServerStream"/> on <see cref="IpcProtocol.PipeName"/> and keeps at most one
/// connected tray-UI client, reconnecting automatically when the client drops.
/// </summary>
/// <remarks>
/// <para>The wire format is newline-delimited UTF-8 JSON (<see cref="IpcProtocol.Json"/>): each
/// <see cref="PromptRequest"/> is written as one line and the UI replies with one
/// <see cref="PromptResponse"/> line carrying the same <see cref="PromptRequest.RequestId"/>.</para>
/// <para>The presenter is fail-safe by construction. If no UI is connected, the write fails, the
/// client disconnects, or the user does not answer within
/// <see cref="PromptRequest.AutoDismissSeconds"/> plus a small grace, <see cref="PromptAsync"/>
/// resolves to <see cref="PromptDecision.KeepBlocked"/> so the OS-level block stays in place. A
/// broken or absent UI can therefore never turn a blocked launch into a silent allow.</para>
/// </remarks>
public sealed class PromptPipeServer : IPromptPresenter, IDisposable
{
    /// <summary>Extra seconds added to the client-side auto-dismiss to bound the service-side wait.</summary>
    private const int GraceSeconds = 5;

    private readonly Action<Exception>? _onError;
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
    public PromptPipeServer(Action<Exception>? onError = null)
    {
        _onError = onError;
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
    /// Returns <see cref="PromptDecision.KeepBlocked"/> immediately if no client is connected, and on
    /// any write failure, disconnect, cancellation, or timeout while awaiting the reply.
    /// </remarks>
    public async Task<PromptResponse> PromptAsync(PromptRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var pipe = _currentPipe;
        if (_disposed || pipe is null || !pipe.IsConnected)
        {
            // Fail safe: nobody to ask.
            return KeepBlocked(request);
        }

        var tcs = new TaskCompletionSource<PromptResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(request.RequestId, tcs))
        {
            // Duplicate in-flight id (should not happen with Guids); fail safe rather than corrupt state.
            return KeepBlocked(request);
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
                    source.TrySetResult(new PromptResponse(req.RequestId, PromptDecision.KeepBlocked));
                },
                (tcs, request)).ConfigureAwait(false);

            var response = await tcs.Task.ConfigureAwait(false);

            // Guard against a stray reply carrying the wrong id.
            return response.RequestId == request.RequestId ? response : KeepBlocked(request);
        }
        catch (Exception ex)
        {
            // Write failure, disconnect mid-flight, or serialization error: never throw out of the hot path.
            _onError?.Invoke(ex);
            return KeepBlocked(request);
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
            try
            {
                pipe = new NamedPipeServerStream(
                    IpcProtocol.PipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                _currentPipe = pipe;
                await ReadLoopAsync(pipe, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // A broken connection (client crash, pipe error) is expected; log and rebuild the pipe.
                _onError?.Invoke(ex);
            }
            finally
            {
                _currentPipe = null;
                FailPending();
                pipe?.Dispose();
            }
        }
    }

    private async Task ReadLoopAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        // Leave the pipe open; the accept loop owns its lifetime.
        using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);

        while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
        {
            var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                // Client closed the connection.
                break;
            }

            if (line.Length == 0)
            {
                continue;
            }

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

            if (response is not null && _pending.TryGetValue(response.RequestId, out var tcs))
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
            entry.Value.TrySetResult(new PromptResponse(entry.Key, PromptDecision.KeepBlocked));
        }
    }

    private static PromptResponse KeepBlocked(PromptRequest request) =>
        new(request.RequestId, PromptDecision.KeepBlocked);

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
