using Microsoft.Extensions.DependencyInjection;
using Warden.Core;
using Warden.Llm.Providers;

namespace Warden.Llm;

/// <summary>DI registration for the LLM analyst tier and its providers.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddWardenLlm(this IServiceCollection services, Action<LlmOptions>? configure = null)
    {
        var options = new LlmOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);

        // Named HTTP clients. The two Anthropic-wire providers share the Anthropic base address; the
        // local provider targets the OpenAI-compatible endpoint.
        services.AddHttpClient(AnthropicApiProvider.HttpClient, c => c.BaseAddress = options.AnthropicBaseAddress);
        services.AddHttpClient(ClaudeCodeOAuthProvider.HttpClient, c => c.BaseAddress = options.AnthropicBaseAddress);
        services.AddHttpClient(LocalLlmProvider.HttpClient, c => c.BaseAddress = options.LocalBaseAddress);

        services.AddSingleton<DossierBuilder>();

        // The claude CLI provider shells out to a process; it needs a runner, not an HttpClient.
        services.AddSingleton<IClaudeCliRunner, ClaudeCliRunner>();

        // Providers, in priority order. All are always registered; each self-reports IsEnabled from
        // config. Anthropic API (0) < claude CLI (5) < local (10) < Claude Code OAuth (20). The CLI and
        // OAuth providers stay disabled unless explicitly turned on.
        services.AddSingleton<IVerdictLlmProvider, AnthropicApiProvider>();
        services.AddSingleton<IVerdictLlmProvider, ClaudeCliProvider>();
        services.AddSingleton<IVerdictLlmProvider, LocalLlmProvider>();
        services.AddSingleton<IVerdictLlmProvider, ClaudeCodeOAuthProvider>();

        services.AddSingleton<LlmVerdictSource>();
        services.AddSingleton<IVerdictSource>(sp => sp.GetRequiredService<LlmVerdictSource>());
        return services;
    }
}
