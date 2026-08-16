using Microsoft.Extensions.Logging;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Warden.Core;

namespace Warden.Ml;

/// <summary>
/// ML verdict tier: extracts the EMBER feature vector and scores it with a local ONNX model
/// (LightGBM exported via onnxmltools). Disabled (always undecided) when no model file is present, so
/// the pipeline runs unchanged until a model is deployed. Decisive only at the ends of the score band.
/// </summary>
public sealed class OnnxScorer : IVerdictSource, IDisposable
{
    private readonly IPeFeatureExtractor _extractor;
    private readonly MlOptions _options;
    private readonly ILogger<OnnxScorer> _logger;
    private readonly Lazy<InferenceSession?> _session;

    public OnnxScorer(IPeFeatureExtractor extractor, MlOptions options, ILogger<OnnxScorer> logger)
    {
        _extractor = extractor;
        _options = options;
        _logger = logger;
        _session = new Lazy<InferenceSession?>(LoadModel);
    }

    public VerdictSourceKind Kind => VerdictSourceKind.Ml;

    public ValueTask<VerdictResult> EvaluateAsync(VerdictContext context, CancellationToken cancellationToken)
    {
        InferenceSession? session = _session.Value;
        if (session is null)
        {
            return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, "ML model not loaded."));
        }

        double score;
        try
        {
            string path = context.BytesPath;
            long length = new FileInfo(path).Length;
            if (length > _options.MaxImageBytes)
            {
                // Refuse to load an attacker-sized file into memory (the extractor copies it again).
                return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, $"Image is {length} bytes; above the ML size cap."));
            }

            byte[] bytes = File.ReadAllBytes(path);
            if (!PeNet.PeFile.IsPeFile(bytes))
            {
                return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, "Not a PE image."));
            }
            float[] features = _extractor.Extract(bytes);
            double? scored = Score(session, features);
            if (scored is null)
            {
                // Unrecognized model output shape: say so — never fall back to a "most benign" 0.0.
                _logger.LogWarning("ML model produced no recognizable probability output for {File}.", context.ImageName);
                return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, "ML model output not understood."));
            }
            score = Math.Clamp(scored.Value, 0d, 1d);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ML scoring failed for {File}.", context.ImageName);
            return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, "ML scoring error."));
        }

        if (score >= _options.HighThreshold)
        {
            return new ValueTask<VerdictResult>(new VerdictResult(
                Verdict.Block, Kind, score,
                $"ML score {score:F3} >= {_options.HighThreshold:F2} (model {_options.ModelVersion})."));
        }

        if (_options.AllowOnLowScore && score <= _options.LowThreshold)
        {
            return new ValueTask<VerdictResult>(new VerdictResult(
                Verdict.Allow, Kind, 1d - score,
                $"ML score {score:F3} <= {_options.LowThreshold:F2} (model {_options.ModelVersion})."));
        }

        return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, $"ML score {score:F3} in mid-band; deferring."));
    }

    /// <summary>The model's P(malicious), or null when no output of a known shape is present.</summary>
    private static double? Score(InferenceSession session, float[] features)
    {
        string inputName = session.InputMetadata.Keys.First();
        var tensor = new DenseTensor<float>(features, new[] { 1, features.Length });
        using IDisposableReadOnlyCollection<DisposableNamedOnnxValue> results =
            session.Run(new[] { NamedOnnxValue.CreateFromTensor(inputName, tensor) });

        // Preferred: a float probabilities tensor [1,2] = [benign, malicious].
        foreach (var r in results)
        {
            if (r.Value is Tensor<float> t)
            {
                float[] arr = t.ToArray();
                if (arr.Length == 0 || float.IsNaN(arr[^1]))
                {
                    return null;
                }
                return arr.Length >= 2 ? arr[^1] : arr[0];
            }
        }

        // Fallback: zipmap output (sequence of {classLabel -> prob}).
        foreach (var r in results)
        {
            if (r.Value is IEnumerable<IDictionary<long, float>> seq)
            {
                IDictionary<long, float>? first = seq.FirstOrDefault();
                if (first is not null && first.TryGetValue(1, out float p) && !float.IsNaN(p))
                {
                    return p;
                }
            }
        }

        return null;
    }

    private InferenceSession? LoadModel()
    {
        try
        {
            if (!File.Exists(_options.ModelPath))
            {
                _logger.LogInformation("ML model not found at {Path}; ML tier disabled.", _options.ModelPath);
                return null;
            }

            if (!string.IsNullOrWhiteSpace(_options.ModelSha256))
            {
                string actual;
                using (FileStream fs = File.OpenRead(_options.ModelPath))
                {
                    actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
                }
                if (!string.Equals(actual, _options.ModelSha256.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError("ML model {Path} does not match the pinned SHA-256; ML tier disabled.", _options.ModelPath);
                    return null;
                }
            }

            var session = new InferenceSession(_options.ModelPath);
            _logger.LogInformation("Loaded ML model {Path} (version {Version}).", _options.ModelPath, _options.ModelVersion);
            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load ML model {Path}.", _options.ModelPath);
            return null;
        }
    }

    public void Dispose()
    {
        if (_session.IsValueCreated)
        {
            _session.Value?.Dispose();
        }
    }
}
