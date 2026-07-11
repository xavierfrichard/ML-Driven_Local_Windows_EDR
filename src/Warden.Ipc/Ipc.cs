using System.Text.Json;
using System.Text.Json.Serialization;

namespace Warden.Ipc;

/// <summary>The decision a user (or the auto-dismiss timeout) made at a prompt.</summary>
public enum PromptDecision
{
    /// <summary>Default / timeout: leave the launch blocked (zero-trust safe default).</summary>
    KeepBlocked = 0,

    /// <summary>Allow the file: add a persistent WDAC allow rule so it runs on relaunch.</summary>
    Allow,

    /// <summary>Quarantine the file.</summary>
    Quarantine,
}

/// <summary>
/// A request from the service (session 0) to the tray UI (user session) to prompt the user about a
/// blocked launch. Primitive-only so the JSON wire format is stable and UI-friendly.
/// </summary>
public sealed record PromptRequest(
    Guid RequestId,
    string Sha256,
    string ImagePath,
    string FileName,
    string CommandLine,
    string ParentPath,
    string SignerSummary,
    int MotwZone,
    string Reason,
    string BlockMode,
    double? MlScore,
    string? LlmVerdict,
    DateTimeOffset Timestamp,
    int AutoDismissSeconds);

/// <summary>The user's answer to a <see cref="PromptRequest"/>.</summary>
public sealed record PromptResponse(Guid RequestId, PromptDecision Decision);

/// <summary>
/// Abstraction the enforcement controller depends on to ask the user about a blocked launch. The
/// concrete implementation is the named-pipe server (<see cref="PromptPipeServer"/>); the tray UI
/// runs the client side. If no UI is connected or the user does not answer in time, implementations
/// MUST resolve to <see cref="PromptDecision.KeepBlocked"/> (fail safe).
/// </summary>
public interface IPromptPresenter
{
    Task<PromptResponse> PromptAsync(PromptRequest request, CancellationToken cancellationToken);
}

/// <summary>Shared IPC constants and JSON settings for the service &lt;-&gt; tray-UI channel.</summary>
public static class IpcProtocol
{
    /// <summary>Named pipe both sides use. The service hosts it; the UI connects.</summary>
    public const string PipeName = "WardenAgent.Prompt.v1";

    /// <summary>Messages are newline-delimited UTF-8 JSON. This is the shared serializer config.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.General)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };
}
