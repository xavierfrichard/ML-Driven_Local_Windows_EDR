using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Warden.Core;
using Warden.Storage;

namespace Warden.Reputation;

/// <summary>
/// VirusTotal reputation tier of the decision pipeline. Hash-only (never uploads a file), SQLite-cached,
/// and offline-tolerant: a network failure falls back to any cached verdict and otherwise declines, so
/// the pipeline stays fully functional with no network. Decisive only at the extremes (enough engines
/// flag it → block; optionally, well-known clean → allow); everything else defers to ML/LLM/prompt.
/// </summary>
public sealed class VirusTotalClient : IVerdictSource
{
    private const string HttpClientName = "virustotal";

    private readonly IHttpClientFactory _httpFactory;
    private readonly IReputationCacheRepository _cache;
    private readonly ReputationOptions _options;
    private readonly ILogger<VirusTotalClient> _logger;

    private readonly object _budgetGate = new();
    private int _requestsToday;
    private DateOnly _budgetDay;

    public VirusTotalClient(
        IHttpClientFactory httpFactory,
        IReputationCacheRepository cache,
        ReputationOptions options,
        ILogger<VirusTotalClient> logger)
    {
        _httpFactory = httpFactory;
        _cache = cache;
        _options = options;
        _logger = logger;
    }

    public VerdictSourceKind Kind => VerdictSourceKind.VirusTotal;

    public async ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiKey) || string.IsNullOrEmpty(context.Sha256))
        {
            return VerdictResult.Undecided(Kind, "VirusTotal disabled or no hash.");
        }

        ReputationRecord? record = null;
        try
        {
            record = await _cache.GetAsync(context.Sha256, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // cache unavailable; fall through to network
        }

        var now = DateTimeOffset.UtcNow;
        if (record is null || !record.IsFresh(now))
        {
            ReputationRecord? fetched = await TryFetchAsync(context.Sha256, cancellationToken).ConfigureAwait(false);
            if (fetched is not null)
            {
                record = fetched;
                try { await _cache.UpsertAsync(record, cancellationToken).ConfigureAwait(false); }
                catch { /* cache write best-effort */ }
            }
            // else keep the stale record if we had one (offline tolerance)
        }

        if (record is null)
        {
            return VerdictResult.Undecided(Kind, "No reputation available (offline / not cached).");
        }

        if (record.VtTotal > 0 && record.VtPositives >= _options.BlockThreshold)
        {
            return new VerdictResult(Verdict.Block, Kind, Confidence(record),
                $"VirusTotal: {record.VtPositives}/{record.VtTotal} engines flagged this file.");
        }

        if (_options.AllowKnownClean && record.VtPositives == 0 && record.VtTotal >= _options.CleanMinEngines)
        {
            return new VerdictResult(Verdict.Allow, Kind, 0.9,
                $"VirusTotal: clean across {record.VtTotal} engines.");
        }

        return VerdictResult.Undecided(Kind, record.VtTotal > 0
            ? $"VirusTotal: {record.VtPositives}/{record.VtTotal}, not decisive."
            : "Not present in VirusTotal.");
    }

    private async Task<ReputationRecord?> TryFetchAsync(string sha256, CancellationToken cancellationToken)
    {
        if (!TryConsumeBudget())
        {
            _logger.LogWarning("VirusTotal daily request budget exhausted; using cache only.");
            return null;
        }

        try
        {
            using HttpClient http = _httpFactory.CreateClient(HttpClientName);
            if (http.BaseAddress is null)
            {
                http.BaseAddress = _options.BaseAddress;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, $"files/{sha256}");
            request.Headers.Add("x-apikey", _options.ApiKey);

            using HttpResponseMessage response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            long ttl = (long)_options.CacheTtl.TotalSeconds;

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                // Not in VirusTotal — cache as "unknown" (total 0) so we do not re-query constantly.
                return new ReputationRecord
                {
                    Sha256 = sha256, VtPositives = 0, VtTotal = 0,
                    CachedTs = DateTimeOffset.UtcNow, TtlSecs = ttl,
                };
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("VirusTotal returned {Status} for {Sha}.", response.StatusCode, sha256);
                return null;
            }

            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using JsonDocument doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return ParseRecord(sha256, doc.RootElement, ttl);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "VirusTotal fetch failed for {Sha} (staying offline-tolerant).", sha256);
            return null;
        }
    }

    private static ReputationRecord ParseRecord(string sha256, JsonElement root, long ttl)
    {
        int malicious = 0, total = 0;
        DateTimeOffset? firstSeen = null;

        if (root.TryGetProperty("data", out JsonElement data) &&
            data.TryGetProperty("attributes", out JsonElement attr))
        {
            if (attr.TryGetProperty("last_analysis_stats", out JsonElement stats))
            {
                foreach (JsonProperty p in stats.EnumerateObject())
                {
                    if (p.Value.ValueKind == JsonValueKind.Number)
                    {
                        int value = p.Value.GetInt32();
                        total += value;
                        if (p.Name == "malicious")
                        {
                            malicious = value;
                        }
                    }
                }
            }

            if (attr.TryGetProperty("first_submission_date", out JsonElement fsd) && fsd.ValueKind == JsonValueKind.Number)
            {
                firstSeen = DateTimeOffset.FromUnixTimeSeconds(fsd.GetInt64());
            }
        }

        return new ReputationRecord
        {
            Sha256 = sha256, VtPositives = malicious, VtTotal = total, VtFirstSeen = firstSeen,
            CachedTs = DateTimeOffset.UtcNow, TtlSecs = ttl,
        };
    }

    private static double Confidence(ReputationRecord r) =>
        r.VtTotal == 0 ? 0.5 : Math.Min(1.0, (double)r.VtPositives / Math.Max(1, r.VtTotal) + 0.5);

    private bool TryConsumeBudget()
    {
        if (_options.DailyRequestBudget <= 0)
        {
            return true;
        }
        lock (_budgetGate)
        {
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            if (today != _budgetDay)
            {
                _budgetDay = today;
                _requestsToday = 0;
            }
            if (_requestsToday >= _options.DailyRequestBudget)
            {
                return false;
            }
            _requestsToday++;
            return true;
        }
    }
}
