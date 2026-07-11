using System.Collections.Immutable;
using System.Text.Json;
using Warden.Core;
using Warden.Llm;

namespace Warden.Tests;

/// <summary>Shared HTTP stubs, context builders, canned responses, and a fake provider for the LLM tier tests.</summary>
internal static class LlmTest
{
    public static readonly Uri AnthropicBase = new("https://api.anthropic.com/");
    public static readonly Uri LocalBase = new("http://localhost:11434/");

    /// <summary>Builds a <see cref="VerdictContext"/> with overridable fields the LLM tier cares about.</summary>
    public static VerdictContext Context(
        string commandLine = "\"C:\\Temp\\unknown.exe\"",
        string imagePath = @"C:\Temp\unknown.exe",
        int motwZone = VerdictContext.NoMotw,
        SignerInfo? signer = null,
        PeFeatures? pe = null) => new(
        Sha256: "ABCDEF",
        ImagePath: imagePath,
        CommandLine: commandLine,
        Pid: 4321,
        ParentPid: 1234,
        ParentPath: @"C:\Windows\explorer.exe",
        ParentSha256: null,
        Signer: signer ?? SignerInfo.Unsigned,
        MotwZone: motwZone,
        Pe: new Lazy<PeFeatures>(() => pe ?? PeFeatures.NotPortableExecutable),
        Chain: AttackChainNode.None,
        Timestamp: DateTimeOffset.UnixEpoch,
        CorrelationId: 1);

    public static Dossier Dossier(LlmOptions options, VerdictContext? context = null) =>
        new DossierBuilder(options).Build(context ?? Context());

    // ---- canned provider responses ----------------------------------------------------------------

    public static string AnthropicToolUse(
        string verdict, double confidence, string action = "block",
        string[]? evidence = null, string[]? mitre = null)
    {
        var body = new
        {
            id = "msg_1",
            type = "message",
            role = "assistant",
            model = "claude-haiku-4-5",
            stop_reason = "tool_use",
            content = new object[]
            {
                new
                {
                    type = "tool_use",
                    id = "toolu_1",
                    name = "submit_verdict",
                    input = new
                    {
                        verdict,
                        confidence,
                        evidence = evidence ?? Array.Empty<string>(),
                        mitre_attack = mitre ?? Array.Empty<string>(),
                        suggested_action = action,
                    },
                },
            },
        };
        return JsonSerializer.Serialize(body);
    }

    public static string AnthropicRefusal()
    {
        var body = new
        {
            id = "msg_2",
            type = "message",
            role = "assistant",
            stop_reason = "refusal",
            content = new object[] { new { type = "text", text = "" } },
        };
        return JsonSerializer.Serialize(body);
    }

    public static string OpenAiToolCall(string verdict, double confidence, string action = "block")
    {
        string args = JsonSerializer.Serialize(new
        {
            verdict,
            confidence,
            evidence = Array.Empty<string>(),
            mitre_attack = Array.Empty<string>(),
            suggested_action = action,
        });
        var body = new
        {
            choices = new object[]
            {
                new
                {
                    message = new
                    {
                        role = "assistant",
                        content = (string?)null,
                        tool_calls = new object[]
                        {
                            new { id = "call_1", type = "function", function = new { name = "submit_verdict", arguments = args } },
                        },
                    },
                },
            },
        };
        return JsonSerializer.Serialize(body);
    }

    public static string OpenAiContentJson(string verdict, double confidence)
    {
        string inner = JsonSerializer.Serialize(new
        {
            verdict,
            confidence,
            evidence = Array.Empty<string>(),
            mitre_attack = Array.Empty<string>(),
            suggested_action = "allow",
        });
        var body = new
        {
            choices = new object[]
            {
                new { message = new { role = "assistant", content = "Here is my verdict: " + inner } },
            },
        };
        return JsonSerializer.Serialize(body);
    }
}

/// <summary>Records the last request (URI, headers, body) and returns a canned response.</summary>
internal sealed class RecordingHandler : HttpMessageHandler
{
    private readonly Func<string, HttpResponseMessage> _responder;

    public RecordingHandler(Func<string, HttpResponseMessage> responder) => _responder = responder;

    public int CallCount { get; private set; }
    public HttpRequestMessage? LastRequest { get; private set; }
    public string LastBody { get; private set; } = string.Empty;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        LastRequest = request;
        LastBody = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        return _responder(LastBody);
    }

    public static HttpResponseMessage Ok(string json) =>
        new(System.Net.HttpStatusCode.OK) { Content = new StringContent(json) };
}

/// <summary>Delays before responding, so tests can exercise the request-timeout vs caller-cancel split.</summary>
internal sealed class DelayingHandler : HttpMessageHandler
{
    private readonly TimeSpan _delay;
    private readonly string _json;

    public DelayingHandler(TimeSpan delay, string json)
    {
        _delay = delay;
        _json = json;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await Task.Delay(_delay, cancellationToken);
        return RecordingHandler.Ok(_json);
    }
}

/// <summary>An <see cref="IHttpClientFactory"/> that hands out clients backed by one handler + base address.</summary>
internal sealed class StubHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler;
    private readonly Uri _baseAddress;

    public StubHttpClientFactory(HttpMessageHandler handler, Uri baseAddress)
    {
        _handler = handler;
        _baseAddress = baseAddress;
    }

    public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false) { BaseAddress = _baseAddress };
}

/// <summary>A configurable fake LLM provider for verdict-source tests.</summary>
internal sealed class FakeLlmProvider : IVerdictLlmProvider
{
    public string Name { get; init; } = "fake";
    public int Priority { get; init; }
    public bool IsEnabled { get; init; } = true;
    public LlmVerdict? Result { get; init; }

    public int Calls { get; private set; }
    public bool? LastEscalate { get; private set; }

    public Task<LlmVerdict?> AnalyzeAsync(Dossier dossier, bool escalate, CancellationToken cancellationToken)
    {
        Calls++;
        LastEscalate = escalate;
        return Task.FromResult(Result);
    }

    public static LlmVerdict Verdict(LlmDisposition disposition, double confidence) =>
        new(disposition, confidence, ImmutableArray<string>.Empty, ImmutableArray<string>.Empty, "block");
}
