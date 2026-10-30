using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Warden.Core;
using Warden.Ml;

namespace Warden.Tests;

/// <summary>
/// Audit M5 (the model pin could not be configured, so any model.onnx loaded) and the ML half of M6
/// (size check and read on two different opens).
/// </summary>
public sealed class OnnxScorerPinTests : IDisposable
{
    private readonly string _dir;
    private readonly string _modelPath;

    public OnnxScorerPinTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "warden-ml-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _modelPath = Path.Combine(_dir, "model.onnx");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private byte[] WriteModel()
    {
        // Not a real ONNX graph: a load that gets past every gate fails inside ONNX Runtime, with its own reason.
        byte[] bytes = "not really onnx"u8.ToArray();
        File.WriteAllBytes(_modelPath, bytes);
        return bytes;
    }

    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    private (OnnxScorer Scorer, ListLogger<OnnxScorer> Log) Scorer(MlOptions options)
    {
        options.ModelPath = _modelPath;
        var log = new ListLogger<OnnxScorer>();
        return (new OnnxScorer(new NoFeatures(), options, log), log);
    }

    private static async Task<VerdictResult> Evaluate(OnnxScorer scorer) =>
        await scorer.EvaluateAsync(TestData.Context(), default);

    [Fact]
    public async Task Given_no_model_file_When_evaluated_Then_the_tier_is_silently_disabled()
    {
        var (scorer, log) = Scorer(new MlOptions { ModelFileTrustCheck = _ => null });

        VerdictResult result = await Evaluate(scorer);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.DoesNotContain(log.Entries, e => e.Level >= LogLevel.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc123")]                                                              // too short
    [InlineData("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")]   // not hex
    public async Task Given_a_model_without_a_valid_pin_When_evaluated_Then_it_is_refused_with_a_critical_log(string? pin)
    {
        WriteModel();
        var (scorer, log) = Scorer(new MlOptions { ModelSha256 = pin, ModelFileTrustCheck = _ => null });

        VerdictResult result = await Evaluate(scorer);

        Assert.Equal(Verdict.Unknown, result.Verdict);
        Assert.Contains("no SHA-256 pin", result.Reason, StringComparison.Ordinal);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Given_a_model_that_does_not_match_the_pin_When_evaluated_Then_it_is_refused()
    {
        WriteModel();
        var (scorer, log) = Scorer(new MlOptions { ModelSha256 = new string('A', 64), ModelFileTrustCheck = _ => null });

        VerdictResult result = await Evaluate(scorer);

        Assert.Contains("does not match the pinned SHA-256", result.Reason, StringComparison.Ordinal);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Given_a_model_whose_owner_is_not_privileged_When_evaluated_Then_it_is_refused_even_with_a_matching_pin()
    {
        byte[] bytes = WriteModel();
        string? checkedPath = null;
        var (scorer, log) = Scorer(new MlOptions
        {
            ModelSha256 = Sha(bytes),
            ModelFileTrustCheck = p => { checkedPath = p; return $"{p} is owned by DESKTOP\\mallory."; },
        });

        VerdictResult result = await Evaluate(scorer);

        Assert.Equal(_modelPath, checkedPath);
        Assert.Contains("not owned and controlled by SYSTEM/Administrators", result.Reason, StringComparison.Ordinal);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Given_no_ownership_check_When_evaluated_Then_the_model_is_refused()
    {
        byte[] bytes = WriteModel();
        var (scorer, _) = Scorer(new MlOptions { ModelSha256 = Sha(bytes) }); // ModelFileTrustCheck = null

        VerdictResult result = await Evaluate(scorer);

        Assert.Contains("ownership cannot be verified", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Given_a_pinned_trusted_model_When_evaluated_Then_every_gate_passes_and_onnx_runtime_gets_the_bytes()
    {
        byte[] bytes = WriteModel();
        var (scorer, log) = Scorer(new MlOptions { ModelSha256 = Sha(bytes).ToLowerInvariant(), ModelFileTrustCheck = _ => null });

        VerdictResult result = await Evaluate(scorer);

        // Past the pin and owner gates: the only remaining failure is ONNX Runtime rejecting the fake graph.
        Assert.Equal("ML model failed to load.", result.Reason);
        Assert.DoesNotContain(log.Entries, e => e.Level == LogLevel.Critical);
    }

    [Fact]
    public async Task Given_a_model_above_the_size_cap_When_evaluated_Then_it_is_not_read_into_memory()
    {
        byte[] bytes = WriteModel();
        var (scorer, _) = Scorer(new MlOptions { ModelSha256 = Sha(bytes), ModelFileTrustCheck = _ => null, MaxModelBytes = 4 });

        VerdictResult result = await Evaluate(scorer);

        Assert.Contains("too large", result.Reason, StringComparison.Ordinal);
    }

    // ---- M6: one handle, bounded read ---------------------------------------------------------------

    [Fact]
    public void Given_a_file_over_the_cap_When_read_Then_null_is_returned_with_its_length()
    {
        string path = Path.Combine(_dir, "big.bin");
        File.WriteAllBytes(path, new byte[1000]);

        byte[]? bytes = BoundedFile.ReadAll(path, 999, out long length);

        Assert.Null(bytes);
        Assert.Equal(1000, length);
    }

    [Fact]
    public void Given_a_file_at_the_cap_When_read_Then_all_of_it_is_returned()
    {
        string path = Path.Combine(_dir, "exact.bin");
        byte[] content = RandomNumberGenerator.GetBytes(1000);
        File.WriteAllBytes(path, content);

        Assert.Equal(content, BoundedFile.ReadAll(path, 1000, out _));
    }

    [Fact]
    public void Given_an_open_read_When_someone_tries_to_rewrite_the_file_Then_the_write_is_refused()
    {
        // The single handle shuts writers out for the duration of the read (FileShare.Read).
        string path = Path.Combine(_dir, "locked.bin");
        File.WriteAllBytes(path, new byte[16]);
        using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        Assert.Throws<IOException>(() => new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite).Dispose());
    }

    [Fact]
    public void Given_an_image_over_the_cap_When_the_pe_reader_parses_it_Then_it_reports_not_a_pe()
    {
        string path = Path.Combine(_dir, "huge.exe");
        File.WriteAllBytes(path, new byte[2048]);
        var reader = new PeFeaturesReader(new MlOptions { MaxImageBytes = 1024 }, NullLogger<PeFeaturesReader>.Instance);

        Assert.False(reader.Read(path).IsPortableExecutable);
    }

    private sealed class NoFeatures : IPeFeatureExtractor
    {
        public int Dimension => 2381;

        public float[] Extract(ReadOnlySpan<byte> bytes) => new float[Dimension];
    }
}

/// <summary>Captures log entries so tests can assert on levels.</summary>
internal sealed class ListLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message)> Entries { get; } = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Entries.Add((logLevel, formatter(state, exception)));
}
