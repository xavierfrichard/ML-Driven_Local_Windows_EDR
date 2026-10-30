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
    private string _notLoadedReason = "ML model not loaded.";

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
            return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, _notLoadedReason));
        }

        double score;
        try
        {
            // One handle for the size check and the read: the file cannot be swapped or grown in between.
            byte[]? bytes = BoundedFile.ReadAll(context.BytesPath, _options.MaxImageBytes, out long length);
            if (bytes is null)
            {
                // Refuse to load an attacker-sized file into memory (the extractor copies it again).
                return new ValueTask<VerdictResult>(VerdictResult.Undecided(Kind, $"Image is {length} bytes; above the ML size cap."));
            }

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
        string path = _options.ModelPath;
        try
        {
            if (!File.Exists(path))
            {
                _logger.LogInformation("ML model not found at {Path}; ML tier disabled.", path);
                return Refuse("ML model not present.");
            }

            // A model file exists. From here on every failure is critical: someone deployed (or planted) a
            // model, and the tier refuses to run it rather than run one it cannot vouch for.
            string? pin = NormalizePin(_options.ModelSha256);
            if (pin is null)
            {
                _logger.LogCritical(
                    "ML model {Path} exists but no valid SHA-256 pin is configured; refusing to load it. "
                    + "Store the model's hash with installer\\Set-WardenSecret.ps1 -Name MlModelSha256.", path);
                return Refuse("ML model refused: no SHA-256 pin is configured.");
            }

            Func<string, string?>? trustCheck = _options.ModelFileTrustCheck;
            if (trustCheck is null)
            {
                _logger.LogCritical("ML model {Path} not loaded: no file-ownership check is configured.", path);
                return Refuse("ML model refused: its ownership cannot be verified.");
            }
            if (trustCheck(path) is { } untrusted)
            {
                _logger.LogCritical("ML model {Path} not loaded: {Problem}", path, untrusted);
                return Refuse("ML model refused: its file or folder is not owned and controlled by SYSTEM/Administrators.");
            }

            // Read once, hash those bytes, and load those same bytes: no second open that could see other content.
            byte[]? model = BoundedFile.ReadAll(path, _options.MaxModelBytes, out long length);
            if (model is null)
            {
                _logger.LogCritical("ML model {Path} is {Size} bytes, above the {Cap}-byte cap; not loaded.", path, length, _options.MaxModelBytes);
                return Refuse("ML model refused: file too large.");
            }

            string actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(model));
            if (!string.Equals(actual, pin, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogCritical("ML model {Path} does not match the pinned SHA-256 (found {Actual}); ML tier disabled.", path, actual);
                return Refuse("ML model refused: it does not match the pinned SHA-256.");
            }

            var session = new InferenceSession(model);
            _logger.LogInformation("Loaded ML model {Path} (version {Version}, SHA-256 {Sha}).", path, _options.ModelVersion, actual);
            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load ML model {Path}.", path);
            return Refuse("ML model failed to load.");
        }
    }

    private InferenceSession? Refuse(string reason)
    {
        _notLoadedReason = reason;
        return null;
    }

    /// <summary>A pin is exactly 64 hex characters (optionally with surrounding whitespace); anything else is no pin.</summary>
    internal static string? NormalizePin(string? pin)
    {
        string? trimmed = pin?.Trim();
        if (trimmed is null || trimmed.Length != 64)
        {
            return null;
        }
        foreach (char c in trimmed)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return null;
            }
        }
        return trimmed.ToUpperInvariant();
    }

    public void Dispose()
    {
        if (_session.IsValueCreated)
        {
            _session.Value?.Dispose();
        }
    }
}
