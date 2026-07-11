using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Warden.Llm.Providers;

/// <summary>
/// Shared implementation for providers that talk to the Anthropic Messages API. The API-key and the
/// Claude Code OAuth providers differ only in how they authenticate and whether they are enabled; the
/// request shape (forced <c>submit_verdict</c> tool call, prompt-cached system prompt) is identical.
/// </summary>
public abstract class AnthropicMessagesProviderBase : IVerdictLlmProvider
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly LlmOptions _options;
    private readonly ILogger _logger;

    protected AnthropicMessagesProviderBase(IHttpClientFactory httpFactory, LlmOptions options, ILogger logger)
    {
        _httpFactory = httpFactory;
        _options = options;
        _logger = logger;
    }

    /// <summary>The shared options, for derived providers to read credentials from.</summary>
    protected LlmOptions Options => _options;

    /// <inheritdoc/>
    public abstract string Name { get; }

    /// <inheritdoc/>
    public abstract int Priority { get; }

    /// <inheritdoc/>
    public abstract bool IsEnabled { get; }

    /// <summary>Named <see cref="HttpClient"/> to use.</summary>
    protected abstract string HttpClientName { get; }

    /// <summary>Add provider-specific authentication headers to the outgoing request.</summary>
    protected abstract void Authenticate(HttpRequestMessage request);

    /// <inheritdoc/>
    public async Task<LlmVerdict?> AnalyzeAsync(Dossier dossier, bool escalate, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            return null;
        }

        string model = escalate ? _options.EscalationModel : _options.Model;
        string body = BuildRequestBody(model, dossier);

        try
        {
            using HttpClient http = _httpFactory.CreateClient(HttpClientName);
            if (http.BaseAddress is null)
            {
                http.BaseAddress = _options.AnthropicBaseAddress;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "v1/messages")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            request.Headers.Add("anthropic-version", _options.AnthropicVersion);
            Authenticate(request);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.RequestTimeout);

            using HttpResponseMessage response = await http.SendAsync(request, cts.Token).ConfigureAwait(false);
            string responseJson = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("LLM provider {Provider} returned {Status} for {File}.",
                    Name, response.StatusCode, dossier.ImageName);
                return null;
            }

            LlmVerdict? verdict = LlmAnalystPrompt.ParseAnthropicResponse(responseJson, _options.MaxVerdictListItems);
            if (verdict is null)
            {
                _logger.LogWarning("LLM provider {Provider} produced no usable verdict for {File}.", Name, dossier.ImageName);
                return null;
            }
            return verdict with { Model = model };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw; // caller asked to cancel — propagate
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("LLM provider {Provider} timed out for {File}.", Name, dossier.ImageName);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "LLM provider {Provider} failed for {File}.", Name, dossier.ImageName);
            return null;
        }
    }

    private string BuildRequestBody(string model, Dossier dossier)
    {
        var body = new
        {
            model,
            max_tokens = _options.MaxTokens,
            system = new object[]
            {
                new { type = "text", text = LlmAnalystPrompt.SystemPrompt, cache_control = new { type = "ephemeral" } },
            },
            tools = new object[] { LlmAnalystPrompt.BuildAnthropicTool(_options.UseStrictToolSchema) },
            tool_choice = new { type = "tool", name = LlmAnalystPrompt.ToolName },
            messages = new object[]
            {
                new { role = "user", content = LlmAnalystPrompt.UserContent(dossier.ToJson()) },
            },
        };
        return JsonSerializer.Serialize(body);
    }
}
