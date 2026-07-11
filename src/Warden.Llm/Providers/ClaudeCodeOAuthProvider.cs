using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Warden.Llm.Providers;

/// <summary>
/// PERSONAL-MACHINE-ONLY provider that authenticates to the Anthropic Messages API with a Claude
/// Pro/Max subscription OAuth token (<c>Authorization: Bearer</c> + the OAuth beta header) instead of an
/// API key.
/// <para>
/// Using a subscription OAuth token as an application/backend is <b>against Anthropic's terms</b> (see
/// this project's <c>src/Warden.Llm/README.md</c>). This provider is therefore <b>disabled by default</b>,
/// gated behind <see cref="LlmOptions.EnableClaudeCodeOAuth"/>, given the lowest priority, and must
/// never be the default in a distributed build — those use the API key or a local model.
/// </para>
/// </summary>
public sealed class ClaudeCodeOAuthProvider : AnthropicMessagesProviderBase
{
    /// <summary>The DI-registered named <see cref="HttpClient"/> for the OAuth path (shares the Anthropic base).</summary>
    public const string HttpClient = "warden-anthropic-oauth";

    // Required alongside a subscription OAuth bearer token on the Messages API.
    private const string OAuthBetaHeader = "oauth-2025-04-20";

    public ClaudeCodeOAuthProvider(IHttpClientFactory httpFactory, LlmOptions options, ILogger<ClaudeCodeOAuthProvider> logger)
        : base(httpFactory, options, logger)
    {
    }

    public override string Name => "claude-code-oauth";

    public override int Priority => 20;

    public override bool IsEnabled =>
        Options.EnableClaudeCodeOAuth && !string.IsNullOrWhiteSpace(Options.ClaudeCodeOAuthToken);

    protected override string HttpClientName => HttpClient;

    protected override void Authenticate(HttpRequestMessage request)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Options.ClaudeCodeOAuthToken);
        request.Headers.Add("anthropic-beta", OAuthBetaHeader);
    }
}
