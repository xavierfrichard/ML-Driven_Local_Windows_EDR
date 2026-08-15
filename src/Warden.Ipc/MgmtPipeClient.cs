using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Warden.Ipc;

/// <summary>Thrown when the service answers a management request with <c>Ok = false</c>.</summary>
public sealed class MgmtException : Exception
{
    public MgmtException(string message) : base(message)
    {
    }

    public MgmtException(string message, Exception inner) : base(message, inner)
    {
    }

    public MgmtException()
    {
    }
}

/// <summary>
/// Tray-UI side of the management channel. Keeps one connection to the service and issues
/// request/response calls over it, reconnecting transparently if the service restarts.
/// </summary>
/// <remarks>
/// Calls are serialized by a semaphore: the wire protocol is one newline-delimited JSON request
/// followed by one response, so overlapping calls on a single pipe would interleave their framing.
/// The UI's panel loads are short and sequential, so this costs nothing in practice.
/// </remarks>
public sealed class MgmtPipeClient : IDisposable
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private bool _disposed;

    /// <summary>True while a connection to the service is established.</summary>
    public bool IsConnected => _pipe is { IsConnected: true };

    /// <summary>Issues a read operation and deserializes the reply into a list of <typeparamref name="T"/>.</summary>
    public async Task<IReadOnlyList<T>> ListAsync<T>(string operation, CancellationToken cancellationToken = default)
    {
        MgmtResponse response = await SendAsync(operation, payload: null, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(response.PayloadJson))
        {
            return Array.Empty<T>();
        }

        try
        {
            return JsonSerializer.Deserialize<List<T>>(response.PayloadJson, IpcProtocol.Json) ?? new List<T>();
        }
        catch (JsonException ex)
        {
            throw new MgmtException($"Could not read the '{operation}' reply: {ex.Message}", ex);
        }
    }

    /// <summary>Issues a mutating operation. Throws <see cref="MgmtException"/> if the service refuses it.</summary>
    public async Task InvokeAsync(string operation, object? payload, CancellationToken cancellationToken = default)
    {
        await SendAsync(operation, payload, cancellationToken).ConfigureAwait(false);
    }

    private async Task<MgmtResponse> SendAsync(string operation, object? payload, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var request = new MgmtRequest(
            Guid.NewGuid(),
            operation,
            payload is null ? null : JsonSerializer.Serialize(payload, payload.GetType(), IpcProtocol.Json));

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // One transparent retry: the service may have restarted since the last call.
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
                    MgmtResponse response = await ExchangeAsync(request, cancellationToken).ConfigureAwait(false);

                    return response.Ok
                        ? response
                        : throw new MgmtException(response.Error ?? "The Warden service refused the request.");
                }
                catch (Exception ex) when (attempt == 0 && ex is IOException or InvalidOperationException or TimeoutException)
                {
                    DropConnection();
                }
            }

            throw new MgmtException("Lost the connection to the Warden service.");
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        if (_pipe is { IsConnected: true } && _reader is not null)
        {
            return;
        }

        DropConnection();

        var pipe = new NamedPipeClientStream(
            ".",
            MgmtProtocol.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        try
        {
            await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            pipe.Dispose();
            throw new MgmtException(
                "The Warden service is not reachable. Is the WardenAgent service running?");
        }
        catch (Exception)
        {
            pipe.Dispose();
            throw;
        }

        _pipe = pipe;
        _reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
    }

    private async Task<MgmtResponse> ExchangeAsync(MgmtRequest request, CancellationToken cancellationToken)
    {
        NamedPipeClientStream pipe = _pipe ?? throw new InvalidOperationException("Not connected.");
        StreamReader reader = _reader ?? throw new InvalidOperationException("Not connected.");

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(request, IpcProtocol.Json);
        var frame = new byte[json.Length + 1];
        Buffer.BlockCopy(json, 0, frame, 0, json.Length);
        frame[json.Length] = (byte)'\n';

        await pipe.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);

        string? line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new IOException("The Warden service closed the management connection.");

        MgmtResponse? response;
        try
        {
            response = JsonSerializer.Deserialize<MgmtResponse>(line, IpcProtocol.Json);
        }
        catch (JsonException ex)
        {
            throw new MgmtException($"Malformed reply from the Warden service: {ex.Message}", ex);
        }

        return response ?? throw new MgmtException("Empty reply from the Warden service.");
    }

    private void DropConnection()
    {
        _reader?.Dispose();
        _reader = null;
        _pipe?.Dispose();
        _pipe = null;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        DropConnection();
        _gate.Dispose();
    }
}
