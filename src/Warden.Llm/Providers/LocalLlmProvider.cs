using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Warden.Llm.Providers;

/// <summary>
/// Fully-offline provider that targets a local OpenAI-compatible chat-completions endpoint
/// (Ollama / llama.cpp). Same forced <c>submit_verdict</c> tool schema; the verdict is read from the
/// tool call, or from a JSON object embedded in the message content if the local model does not emit
/// tool calls. Priority sits between the Anthropic API and the OAuth provider.
/// </summary>
public sealed class LocalLlmProvider : IVerdictLlmProvider
{
    /// <summary>The DI-registered named <see cref="HttpClient"/> for the local endpoint.</summary>
    public const string HttpClient = "warden-local-llm";

    private readonly IHttpClientFactory _httpFactory;
    private readonly LlmOptions _options;
    private readonly ILogger<LocalLlmProvider> _logger;

    public LocalLlmProvider(IHttpClientFactory httpFactory, LlmOptions options, ILogger<LocalLlmProvider> logger)
    {
        _httpFactory = httpFactory;
        _options = options;
        _logger = logger;
    }

    public string Name => "local";

    public int Priority => 10;

    // Refuses a remote plain-http endpoint: the dossier and the bearer key would travel in clear text.
    public bool IsEnabled => _options.EnableLocal && _options.LocalBaseAddressIsAcceptable;

    public async Task<LlmVerdict?> AnalyzeAsync(Dossier dossier, bool escalate, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
        {
            return null;
        }

        string body = BuildRequestBody(dossier);

        try
        {
            using System.Net.Http.HttpClient http = _httpFactory.CreateClient(HttpClient);
            if (http.BaseAddress is null)
            {
                http.BaseAddress = _options.LocalBaseAddress;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "v1/chat/completions")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            if (!string.IsNullOrWhiteSpace(_options.LocalApiKey))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.LocalApiKey);
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.RequestTimeout);

            using HttpResponseMessage response = await http.SendAsync(request, cts.Token).ConfigureAwait(false);
            string responseJson = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Local LLM returned {Status} for {File}.", response.StatusCode, dossier.ImageName);
                return null;
            }

            LlmVerdict? verdict = LlmAnalystPrompt.ParseOpenAiResponse(responseJson, _options.MaxVerdictListItems);
            if (verdict is null)
            {
                _logger.LogWarning("Local LLM produced no usable verdict for {File}.", dossier.ImageName);
                return null;
            }
            return verdict with { Model = _options.LocalModel };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Local LLM timed out for {File}.", dossier.ImageName);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Local LLM failed for {File}.", dossier.ImageName);
            return null;
        }
    }

    private string BuildRequestBody(Dossier dossier)
    {
        var body = new
        {
            model = _options.LocalModel,
            messages = new object[]
            {
                new { role = "system", content = LlmAnalystPrompt.SystemPrompt },
                new { role = "user", content = LlmAnalystPrompt.UserContent(dossier.ToJson()) },
            },
            tools = new object[] { LlmAnalystPrompt.BuildOpenAiTool() },
            tool_choice = new { type = "function", function = new { name = LlmAnalystPrompt.ToolName } },
            temperature = 0,
            stream = false,
        };
        return JsonSerializer.Serialize(body);
    }
}
