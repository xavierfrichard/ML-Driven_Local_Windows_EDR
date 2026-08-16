using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Warden.Ipc;

namespace Warden.Ui;

/// <summary>
/// Client side of the service &lt;-&gt; tray IPC channel. Connects to <see cref="IpcProtocol.PipeName"/>,
/// reads newline-delimited <see cref="PromptRequest"/> JSON, resolves each via <see cref="PromptHandler"/>,
/// and writes back a <see cref="PromptResponse"/>. The service may start after the UI, so the client
/// reconnects with capped exponential backoff and survives pipe drops.
/// </summary>
/// <remarks>
/// Connects at <see cref="TokenImpersonationLevel.Identification"/> (the service only needs to <i>identify</i>
/// the caller for its Administrators check; a rogue server must never be able to impersonate the elevated
/// UI) and refuses a pipe whose owner is not SYSTEM/Administrators/the current user.
/// </remarks>
public sealed class PromptPipeClient : IAsyncDisposable
{
    private static readonly TimeSpan InitialBackoff = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    /// <summary>
    /// Handler invoked (off the pipe thread) for each request. Implementations should marshal to the
    /// UI thread and return the user's decision. If null, the client answers
    /// <see cref="PromptDecision.Timeout"/> so the service still fails safe.
    /// </summary>
    public Func<PromptRequest, CancellationToken, Task<PromptDecision>>? PromptHandler { get; set; }

    /// <summary>Starts the background connect/read loop. Idempotent.</summary>
    public void Start() => _loop ??= Task.Run(() => RunAsync(_cts.Token));

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        var backoff = InitialBackoff;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ServeConnectionAsync(cancellationToken).ConfigureAwait(false);
                // Clean disconnect: reset backoff before the next attempt.
                backoff = InitialBackoff;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (TimeoutException)
            {
                // Service not up yet; keep waiting quietly.
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"[Warden.Ui] Pipe connection error: {ex.Message}");
            }

            try
            {
                await Task.Delay(backoff, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            backoff = TimeSpan.FromMilliseconds(Math.Min(backoff.TotalMilliseconds * 2, MaxBackoff.TotalMilliseconds));
        }
    }

    /// <summary>Connects once and serves requests until the pipe closes or cancellation is requested.</summary>
    private async Task ServeConnectionAsync(CancellationToken cancellationToken)
    {
        using var pipe = new NamedPipeClientStream(
            ".",
            IpcProtocol.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);

        // Bounded connect so a squatted/hung pipe cannot park the client forever; the outer loop retries.
        await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds, cancellationToken).ConfigureAwait(false);

        if (OperatingSystem.IsWindows() && !PipeGuard.ServerLooksLegitimate(pipe))
        {
            Trace.TraceWarning("[Warden.Ui] Prompt pipe is not owned by the Warden service; refusing to answer prompts on it.");
            return;
        }

        var reader = new BoundedLineReader(pipe);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true)
        {
            AutoFlush = true,
        };

        while (!cancellationToken.IsCancellationRequested)
        {
            string? line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                // Pipe closed by the server; return so the outer loop reconnects.
                return;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            PromptRequest? request = TryDeserialize(line);
            if (request is null)
            {
                continue;
            }

            PromptDecision decision = await ResolveAsync(request, cancellationToken).ConfigureAwait(false);
            var response = new PromptResponse(request.RequestId, decision);
            string payload = JsonSerializer.Serialize(response, IpcProtocol.Json);

            await writer.WriteLineAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<PromptDecision> ResolveAsync(PromptRequest request, CancellationToken cancellationToken)
    {
        Func<PromptRequest, CancellationToken, Task<PromptDecision>>? handler = PromptHandler;
        if (handler is null)
        {
            return PromptDecision.Timeout;
        }

        try
        {
            return await handler(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Never let a UI failure propagate onto the pipe loop; fail safe (unanswered).
            Trace.TraceWarning($"[Warden.Ui] Prompt handler failed: {ex.Message}");
            return PromptDecision.Timeout;
        }
    }

    private static PromptRequest? TryDeserialize(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<PromptRequest>(line, IpcProtocol.Json);
        }
        catch (JsonException ex)
        {
            Trace.TraceWarning($"[Warden.Ui] Malformed prompt request ignored: {ex.Message}");
            return null;
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (!_cts.IsCancellationRequested)
        {
            _cts.Cancel();
        }

        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch
            {
                // ignored — teardown is best-effort.
            }
        }

        _cts.Dispose();
    }
}
