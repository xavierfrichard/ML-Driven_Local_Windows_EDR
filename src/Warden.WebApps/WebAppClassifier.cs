using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Warden.Storage;

namespace Warden.WebApps;

/// <summary>
/// The always-ON Web Apps classifier. Collects an app's static signals, scores them, and caches the
/// classification by path. Unlike CyberLock's browser-name list, this recognizes modern JavaScript /
/// WebView apps (Electron, WebView2, CEF) by their engine — so Claude.exe, Slack, Discord, and VS Code
/// are correctly flagged web-facing. There is deliberately no ON/OFF toggle: zero-trust is always on.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WebAppClassifier
{
    private readonly IWebAppInputCollector _collector;
    private readonly IWebAppClassificationRepository _repo;
    private readonly ILogger<WebAppClassifier> _logger;

    public WebAppClassifier(
        IWebAppInputCollector collector,
        IWebAppClassificationRepository repo,
        ILogger<WebAppClassifier> logger)
    {
        _collector = collector;
        _repo = repo;
        _logger = logger;
    }

    /// <summary>Classify an app from its static signals and cache the result (idempotent by path).</summary>
    public async Task<WebAppClassification> ClassifyAsync(string appPath, CancellationToken cancellationToken = default)
    {
        WebAppStaticInput input = _collector.CollectStatic(appPath);
        WebAppClassification result = WebAppScorer.ClassifyStatic(appPath, input, DateTimeOffset.UtcNow);
        await PersistAsync(result, cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Re-classify with runtime signals (upgrades the verdict once the app is running) and update the
    /// cache. Callers that already have child-process facts (the enforcement path, from the ETW attack
    /// chain) pass them in via <paramref name="runtimeInput"/>.
    /// </summary>
    public async Task<WebAppClassification> ConfirmRuntimeAsync(
        string appPath, WebAppRuntimeInput runtimeInput, CancellationToken cancellationToken = default)
    {
        WebAppStaticInput staticInput = _collector.CollectStatic(appPath);
        WebAppClassification result = WebAppScorer.ClassifyWithRuntime(appPath, staticInput, runtimeInput, DateTimeOffset.UtcNow);
        await PersistAsync(result, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private async Task PersistAsync(WebAppClassification c, CancellationToken cancellationToken)
    {
        try
        {
            await _repo.UpsertAsync(new WebAppClassificationRecord
            {
                AppPath = c.AppPath,
                Engine = c.Engine.ToString().ToLowerInvariant(),
                StaticScore = c.StaticScore,
                RuntimeConfirmed = c.RuntimeScore > 0,
                SignalsJson = JsonSerializer.Serialize(c.Signals),
                Ts = c.Timestamp,
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist web-app classification for {App}.", c.AppPath);
        }
    }
}
