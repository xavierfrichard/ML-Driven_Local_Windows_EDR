using Microsoft.Extensions.Logging;

namespace Warden.Llm.Providers;

/// <summary>
/// The supported production backend: the Anthropic Messages API authenticated with a pay-per-token API
/// key (<c>x-api-key</c>). Enabled whenever an API key is configured; highest priority.
/// </summary>
public sealed class AnthropicApiProvider : AnthropicMessagesProviderBase
{
    /// <summary>The DI-registered named <see cref="HttpClient"/> for the Anthropic API.</summary>
    public const string HttpClient = "warden-anthropic";

    public AnthropicApiProvider(IHttpClientFactory httpFactory, LlmOptions options, ILogger<AnthropicApiProvider> logger)
        : base(httpFactory, options, logger)
    {
    }

    public override string Name => "anthropic";

    public override int Priority => 0;

    public override bool IsEnabled => !string.IsNullOrWhiteSpace(Options.AnthropicApiKey);

    protected override string HttpClientName => HttpClient;

    protected override void Authenticate(HttpRequestMessage request) =>
        request.Headers.Add("x-api-key", Options.AnthropicApiKey);
}
