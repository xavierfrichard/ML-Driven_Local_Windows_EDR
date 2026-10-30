using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Core;
using Warden.Reputation;
using Warden.Storage;

namespace Warden.Tests;

public sealed class VirusTotalClientTests
{
    // A well-formed SHA-256: the client refuses to query anything else.
    private const string Sha = "ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCA";

    private static string StatsJson(int malicious, int harmless, int undetected) =>
        "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":" + malicious
        + ",\"harmless\":" + harmless + ",\"undetected\":" + undetected
        + "},\"first_submission_date\":1600000000}}}";

    [Fact]
    public async Task Enough_detections_blocks()
    {
        var handler = new StubHandler(_ => Ok(StatsJson(12, 50, 8)));
        var cache = new FakeCache();
        var client = Build(handler, cache, new ReputationOptions { ApiKey = "k", BlockThreshold = 5 });

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Block, result.Verdict);
        Assert.Equal(VerdictSourceKind.VirusTotal, result.Source);
        Assert.NotNull(cache.Stored); // cached for next time
    }

    [Fact]
    public async Task Not_found_is_undecided_and_cached_as_unknown()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var cache = new FakeCache();
        var client = Build(handler, cache, new ReputationOptions { ApiKey = "k" });

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.Equal(0, cache.Stored!.VtTotal);
    }

    [Fact]
    public async Task No_api_key_is_undecided_without_calling_the_network()
    {
        var handler = new StubHandler(_ => Ok(StatsJson(99, 0, 0)));
        var client = Build(handler, new FakeCache(), new ReputationOptions { ApiKey = null });

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.Equal(0, handler.CallCount); // disabled -> no request
    }

    [Fact]
    public async Task Offline_falls_back_to_a_stale_cached_verdict()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("network down"));
        var stale = new ReputationRecord
        {
            Sha256 = Sha, VtPositives = 12, VtTotal = 70,
            CachedTs = DateTimeOffset.UtcNow.AddDays(-2), TtlSecs = 86400, // expired -> triggers a fetch
        };
        var cache = new FakeCache { Stored = stale };
        var client = Build(handler, cache, new ReputationOptions { ApiKey = "k", BlockThreshold = 5 });

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Block, result.Verdict); // used the stale record despite the network failure
    }

    [Fact]
    public async Task Known_clean_allows_only_when_configured()
    {
        var handler = new StubHandler(_ => Ok(StatsJson(0, 60, 5))); // 65 engines, 0 detections
        var options = new ReputationOptions { ApiKey = "k", AllowKnownClean = true, CleanMinEngines = 40 };
        var client = Build(handler, new FakeCache(), options);

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Allow, result.Verdict);
    }

    [Fact]
    public async Task Clean_count_excludes_non_scan_outcomes()
    {
        // 35 real verdicts (harmless 30 + undetected 5) but 60 timeout/failure that must NOT count.
        const string json = "{\"data\":{\"attributes\":{\"last_analysis_stats\":"
            + "{\"malicious\":0,\"harmless\":30,\"undetected\":5,\"timeout\":50,\"failure\":10}}}}";
        var options = new ReputationOptions { ApiKey = "k", AllowKnownClean = true, CleanMinEngines = 40 };
        var client = Build(new StubHandler(_ => Ok(json)), new FakeCache(), options);

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Unknown, result.Verdict); // 35 real engines < 40 -> not auto-allowed
    }

    [Fact]
    public async Task Given_a_suspicious_vote_When_otherwise_clean_Then_the_file_is_not_auto_allowed()
    {
        // 64 engines say clean, one says "suspicious": that file is not clean.
        const string json = "{\"data\":{\"attributes\":{\"last_analysis_stats\":"
            + "{\"malicious\":0,\"suspicious\":1,\"harmless\":60,\"undetected\":4}}}}";
        var options = new ReputationOptions { ApiKey = "k", AllowKnownClean = true, CleanMinEngines = 40 };
        var cache = new FakeCache();
        var client = Build(new StubHandler(_ => Ok(json)), cache, options);

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.Equal(1, cache.Stored!.VtPositives); // the suspicious vote is recorded as flagged
        Assert.Equal(65, cache.Stored.VtTotal);
    }

    [Fact]
    public async Task Given_enough_suspicious_votes_When_evaluated_Then_the_file_stays_blocked()
    {
        const string json = "{\"data\":{\"attributes\":{\"last_analysis_stats\":"
            + "{\"malicious\":2,\"suspicious\":3,\"harmless\":40,\"undetected\":20}}}}";
        var client = Build(new StubHandler(_ => Ok(json)), new FakeCache(), new ReputationOptions { ApiKey = "k", BlockThreshold = 5 });

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Block, result.Verdict);
    }

    [Fact]
    public async Task Given_hostile_negative_counts_When_parsed_Then_they_cannot_cancel_a_detection()
    {
        const string json = "{\"data\":{\"attributes\":{\"last_analysis_stats\":"
            + "{\"malicious\":1,\"suspicious\":-1,\"harmless\":60,\"undetected\":4}}}}";
        var options = new ReputationOptions { ApiKey = "k", AllowKnownClean = true, CleanMinEngines = 40 };
        var client = Build(new StubHandler(_ => Ok(json)), new FakeCache(), options);

        var result = await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(Verdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task Given_a_404_When_cached_Then_it_expires_after_an_hour_not_a_day()
    {
        var cache = new FakeCache();
        var client = Build(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)), cache,
            new ReputationOptions { ApiKey = "k" });

        await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal(3600, cache.Stored!.TtlSecs);
        Assert.Equal(TimeSpan.FromHours(1), new ReputationOptions().NotFoundCacheTtl);
    }

    [Fact]
    public async Task Given_a_found_file_When_cached_Then_it_keeps_the_normal_ttl()
    {
        var cache = new FakeCache();
        var client = Build(new StubHandler(_ => Ok(StatsJson(0, 60, 5))), cache, new ReputationOptions { ApiKey = "k" });

        await client.EvaluateAsync(TestData.Context(sha256: Sha), default);

        Assert.Equal((long)TimeSpan.FromDays(1).TotalSeconds, cache.Stored!.TtlSecs);
    }

    private static VirusTotalClient Build(StubHandler handler, FakeCache cache, ReputationOptions options) =>
        new(new StubFactory(handler), cache, options, NullLogger<VirusTotalClient>.Instance);

    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json) };

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        public int CallCount;
        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(_responder(request));
        }
    }

    private sealed class StubFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri("https://vt.test/api/v3/") };
    }

    private sealed class FakeCache : IReputationCacheRepository
    {
        public ReputationRecord? Stored { get; set; }
        public Task<ReputationRecord?> GetAsync(string sha256, CancellationToken ct = default) => Task.FromResult(Stored);
        public Task UpsertAsync(ReputationRecord record, CancellationToken ct = default)
        {
            Stored = record;
            return Task.CompletedTask;
        }
    }
}
