# LightGBM → ONNX → ONNX Runtime (C#) for a Warden EMBER‑v2 classifier

Scope note up front: your `[None, 2381]` input width **is** EMBER feature **version 2** (the default). Version 2 = the 8 v1 extractors (2,351 dims) + `DataDirectories` (30 dims = size+VA of the first 15 data directories). Confirmed extractor breakdown from `ember/features.py`: ByteHistogram 256, ByteEntropyHistogram 256, StringExtractor 104, GeneralFileInfo 10, HeaderFileInfo 62, SectionInfo 255, ImportsInfo 1280, ExportsInfo 128, DataDirectories 30 → **2,381**. `PEFeatureExtractor(feature_version=2)` is the default. Keep the model's `initial_types` width, your C# tensor width, and your C# extractor output all pinned to 2381 or inference silently corrupts.

---

## 1) Exporting the trained LightGBM model to ONNX

### The two source objects you may have

- `ember.train_model(...)` returns a **`lightgbm.Booster`** (native API, `objective="binary"`). This is what the EMBER repo produces.
- If you retrain via the sklearn wrapper you have an **`LGBMClassifier`**.

Both convert through **onnxmltools** (which internally emits an `ai.onnx.ml` `TreeEnsembleClassifier`). The `LGBMClassifier` path is the best‑documented; the `Booster` path is one call.

### Path A — `LGBMClassifier` via skl2onnx (recommended, cleanest control of outputs)

This is the canonical pattern from the sklearn‑onnx LightGBM tutorial ([onnx.ai/sklearn-onnx/auto_tutorial/plot_gexternal_lightgbm.html](https://onnx.ai/sklearn-onnx/auto_tutorial/plot_gexternal_lightgbm.html)):

```python
from skl2onnx import convert_sklearn, update_registered_converter
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm
from skl2onnx.common.data_types import FloatTensorType
from lightgbm import LGBMClassifier

update_registered_converter(
    LGBMClassifier,
    "LightGbmLGBMClassifier",
    calculate_linear_classifier_output_shapes,
    convert_lightgbm,
    options={"nocl": [True, False], "zipmap": [True, False, "columns"]},
)

initial_types = [("input", FloatTensorType([None, 2381]))]

onnx_model = convert_sklearn(
    clf,                                   # trained LGBMClassifier
    "warden_ember_lgbm",
    initial_types,
    target_opset={"": 12, "ai.onnx.ml": 2},
    options={id(clf): {"zipmap": False}},   # <-- kills ZipMap; clean float probs
)
with open("warden_ember.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())
```

`options={id(clf): {"zipmap": False}}` is the switch that turns the second output from a `Sequence<Map<int64,float>>` (ZipMap) into a plain `float[N,2]` tensor — exactly what you want in C#. (See the ZipMap explainer: [plot_convert_zipmap.html](http://onnx.ai/sklearn-onnx/auto_examples/plot_convert_zipmap.html).)

### Path B — native `Booster` via onnxmltools directly

```python
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType

initial_types = [("input", FloatTensorType([None, 2381]))]
onnx_model = convert_lightgbm(
    booster,                          # lightgbm.Booster, objective="binary"
    initial_types=initial_types,
    target_opset=12,
    zipmap=False,                     # top-level convert_lightgbm supports this
)
```

Top-level `convert_lightgbm` signature and options live in [onnxmltools/convert/lightgbm/convert.py](https://github.com/onnx/onnxmltools/blob/main/onnxmltools/convert/lightgbm/convert.py); the tree emitter is [operator_converters/LightGbm.py](https://github.com/onnx/onnxmltools/blob/main/onnxmltools/convert/lightgbm/operator_converters/LightGbm.py). For a `binary` Booster this still emits a 2‑class classifier (label + `[N,2]` probabilities). **Verify the probability tensor is width‑2, not width‑1**, right after conversion (some Booster metadata edge cases collapse it).

### Resulting graph: input/output names & shapes

- **Input**: name `"input"` (whatever string you put in `initial_types`), type `float32`, shape `[N, 2381]`.
- **Outputs with `zipmap=False`**:
  - `"label"` → `int64` `[N]` (argmax hard label; ignore it for scoring)
  - `"probabilities"` → `float32` `[N, 2]`
- **Malicious probability = column index 1.** EMBER labels malware `y=1`, benign `y=0`; class order is ascending, so `probabilities[:, 1]` is P(malicious). Confirm once with a known‑malicious sample rather than trusting the ordering blindly.

Do not rely on the *names* `"label"`/`"probabilities"` being universal — read them from the model at load time (C# `session.OutputMetadata.Keys`, or `netron`), because skl2onnx versions have used `"output_label"`/`"output_probability"`.

### Opset considerations

- The tree op is `ai.onnx.ml.TreeEnsembleClassifier`. Use **`ai.onnx.ml` opset 2** (`target_opset={"": 12, "ai.onnx.ml": 2}`); it's the long‑stable, widely‑supported version. Main‑domain opset 12+ is fine — pick something your `Microsoft.ML.OnnxRuntime` version supports (any recent 1.16–1.20 ORT covers opset 12/ml‑2 comfortably).
- **Parity caveat (this matters for your load‑bearing risk).** `TreeEnsembleClassifier` at ml‑opset ≤2 stores split thresholds as **float32**, while LightGBM compares in **float64**. Samples whose feature value sits within ~1e‑7 of a split threshold can flip class between native LightGBM and ONNX. This is a known onnxmltools/skl2onnx issue, not a bug in your extractor. Mitigations, in order:
  1. After export, run the ONNX model and native LightGBM over your **entire validation set** and assert `max |p_onnx − p_native|` is below tolerance (expect ≤1e‑5 for the vast majority, with a handful of boundary flips).
  2. If any flip lands above your decision threshold, this is real. Newer `ai.onnx.ml` opset 3 added double support for tree ensembles — bumping `target_opset={"ai.onnx.ml": 3}` (with a recent ORT) reduces threshold quantization error. Validate that ORT build accepts ml‑3 before committing.
  3. Persist your decision threshold from the **ONNX** scores, not the native ones (see §3), so the threshold absorbs any residual quantization.

---

## 2) Running it in C# with `Microsoft.ML.OnnxRuntime`

### Package

- **`Microsoft.ML.OnnxRuntime`** (CPU). Confirmed on the official C# get‑started page: [onnxruntime.ai/docs/get-started/with-csharp.html](https://onnxruntime.ai/docs/get-started/with-csharp.html). `dotnet add package Microsoft.ML.OnnxRuntime`.
- Tensor types (`DenseTensor<T>`) come from **`Microsoft.ML.OnnxRuntime.Tensors`** (bundled in that package on 1.16+; on some versions you also reference `System.Numerics.Tensors`).
- For AVX/GPU variants there are `Microsoft.ML.OnnxRuntime.Gpu` etc., but for an EDR classifier the CPU package is correct.

### Minimal, load‑bearing code sketch

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

public sealed class EmberOnnxScorer : IDisposable
{
    private readonly InferenceSession _session;
    private readonly string _inputName;
    private readonly string _probName;

    public EmberOnnxScorer(string modelPath)
    {
        var so = new SessionOptions
        {
            IntraOpNumThreads = 1,                       // deterministic, low-jitter
            GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL
        };
        _session = new InferenceSession(modelPath, so);

        // Read names from the model — do NOT hard-code "input"/"probabilities".
        _inputName = _session.InputMetadata.Keys.First();
        _probName  = _session.OutputMetadata
                             .First(kv => kv.Value.Dimensions.Length == 2).Key; // [N,2]
    }

    /// <summary>Returns P(malicious) for one 2381-dim EMBER v2 vector.</summary>
    public float ScoreMalicious(float[] features)   // features.Length == 2381
    {
        if (features.Length != 2381)
            throw new ArgumentException("EMBER v2 vector must be 2381-dim.");

        var input = new DenseTensor<float>(features, new[] { 1, 2381 });

        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor(_inputName, input)
        };

        using IDisposableReadOnlyCollection<DisposableNamedOnnxValue> results =
            _session.Run(inputs);

        // probabilities: float[1,2]; column 1 == malicious
        var probs = results.First(r => r.Name == _probName)
                           .AsTensor<float>();
        return probs[0, 1];
    }

    public void Dispose() => _session.Dispose();
}
```

Notes that bite people:
- **Create the `InferenceSession` once** (it's heavy — loads/optimizes the graph) and reuse it; it's thread‑safe for concurrent `Run` calls.
- **Always `using`/dispose the `Run` results** (`IDisposableReadOnlyCollection<DisposableNamedOnnxValue>`) — they hold native memory. Leaking them is the #1 ORT C# memory bug.
- `AsTensor<float>()` gives you a `DenseTensor<float>` you index as `[row, col]`.
- The `"label"` int64 output is present but ignore it; you make the decision from `probs[0,1]` vs your persisted threshold, not from ORT's argmax.

### Latency expectations

A 100‑tree / 31‑leaf EMBER LightGBM (the paper's baseline is <10k parameters) as a `TreeEnsembleClassifier` scores a single 2381‑vector in roughly **tens of microseconds to a few hundred µs** on a modern desktop CPU, single‑threaded. Feature **extraction** (LIEF parse + hashing) dominates end‑to‑end cost by orders of magnitude (milliseconds+), so ONNX inference is not your latency budget concern. Set `IntraOpNumThreads = 1` for a single‑sample hot path — thread pool spin‑up costs more than it saves at batch size 1.

Sources: C# API surface in [InferenceTest.cs](https://github.com/microsoft/onnxruntime/blob/main/csharp/test/Microsoft.ML.OnnxRuntime.Tests.Common/InferenceTest.cs); [C# API reference](https://lenisha.github.io/onnxruntime/docs/reference/api/csharp-api.html).

---

## 3) Threshold tuning at ~1% FPR + persistence

### Baseline you're targeting

The EMBER paper (Anderson & Roth 2018, [arxiv 1804.04637](https://arxiv.org/pdf/1804.04637)) reports the LightGBM baseline: **ROC AUC = 0.99911**, with **TPR ≈ 98.2% at FPR = 1%** on EMBER‑2017. EMBER‑2018 is deliberately harder (AUC ≈ 0.997). Use these only as sanity anchors; your own validation ROC governs the threshold.

### Picking the threshold from a validation ROC

```python
import numpy as np
from sklearn.metrics import roc_curve, roc_auc_score

# scores must come from the ONNX model (P(malicious)), not native LightGBM,
# so the threshold absorbs float32 tree quantization.
scores = onnx_scores_val          # shape [N]
y      = y_val                     # 1=malware, 0=benign

fpr, tpr, thr = roc_curve(y, scores)
target_fpr = 0.01
i = np.searchsorted(fpr, target_fpr, side="right") - 1   # last point with fpr <= 1%
threshold = float(thr[i])
print("AUC", roc_auc_score(y, scores),
      "thr", threshold, "tpr@1%fpr", tpr[i])
```

For an EDR you almost certainly want an even stricter operating point (0.1% or 0.01% FPR) because false positives block user binaries via WDAC. Compute several: pick the threshold at the largest FPR you can tolerate operationally, and hold the corresponding TPR as your documented detection rate. Because your WDAC layer is the hard floor, the ML threshold can be tuned conservatively (high precision) and let WDAC + the LLM tier catch the rest.

### Persist threshold + model version alongside the `.onnx`

Ship a sidecar JSON next to the model so C# loads model and policy atomically:

```json
{
  "model_file": "warden_ember.onnx",
  "sha256": "<hash of the .onnx bytes>",
  "ember_feature_version": 2,
  "input_dim": 2381,
  "input_name": "input",
  "prob_output_name": "probabilities",
  "malicious_index": 1,
  "opset": {"": 12, "ai.onnx.ml": 2},
  "threshold": 0.8734,
  "operating_point": {"target_fpr": 0.001, "val_tpr": 0.961},
  "trained_on": "ember2018_v2",
  "trained_utc": "2026-07-11T00:00:00Z",
  "model_version": "warden-lgbm-2381-v1"
}
```

In C#, verify `input_dim == 2381` and the `.onnx` SHA‑256 at startup and refuse to run on mismatch — a silent model/feature‑version drift is exactly the parity failure you're guarding against. Version the threshold *with* the model file (same `model_version`): a retrain shifts the score distribution and invalidates the old threshold.

---

## 4) EMBER dataset options — train without raw PEs

You do **not** need raw PE files to train; EMBER ships pre‑extracted features. Two tiers:

### EMBER 2017/2018 (feature version 1 & 2) — `elastic/ember`

Repo: [github.com/elastic/ember](https://github.com/elastic/ember) · README: [ember/blob/master/README.md](https://github.com/elastic/ember/blob/master/README.md).

Downloadable tarballs:
- EMBER 2017 v1 — `ember_dataset.tar.bz2` (2,351‑dim)
- EMBER 2017 v2 — `ember_dataset_2017_2.tar.bz2` (**2,381‑dim**)
- EMBER 2018 v2 — `ember_dataset_2018_2.tar.bz2` (**2,381‑dim** — use this one)

Each tarball contains `train_features_*.jsonl` (raw feature JSON) and, after one vectorization pass, `.dat` memmap files. Workflow:

```python
import ember

# One-time: turn the JSONL raw features into X.dat / y.dat memmaps (2381-wide)
ember.create_vectorized_features("/data/ember2018/", feature_version=2)

# Load the numeric matrices — no PEs, no LIEF needed
X_train, y_train, X_test, y_test = ember.read_vectorized_features("/data/ember2018/")
# X_train: memmap float32 [900000, 2381]; unlabeled rows have y == -1

# Train the paper's LightGBM baseline (returns a lightgbm.Booster)
booster = ember.train_model("/data/ember2018/", feature_version=2)
```

Important: EMBER‑2018 training set includes **~300k unlabeled rows (`y == −1`)**. For a supervised binary model, filter them:
```python
mask = y_train != -1
X_train, y_train = X_train[mask], y_train[mask]
```
That leaves 600k labeled train / 200k test. `read_vectorized_features` usage and `train_model` are documented in the README; note the README calls it `ember.train_model(...)`, not `train_ember_model`.

### EMBER 2024 (feature version 3, 2,568‑dim) — `FutureComputing4AI/EMBER2024`

Repo: [github.com/FutureComputing4AI/EMBER2024](https://github.com/FutureComputing4AI/EMBER2024). Newer samples (VirusTotal uploads Sep‑2023 → Dec‑2024), multi‑format, and a **different 2,568‑dim** vector via the `thrember` package (`thrember.create_vectorized_features()`). **Do not mix this with your 2381 pipeline** — v3 width ≠ v2 width and your C# extractor targets v2. Treat EMBER2024 as a future upgrade requiring a matching C# v3 extractor + a new 2568‑input model, not a drop‑in.

### Recommended concrete setup for Warden

Train on **EMBER 2018 v2** (`ember_dataset_2018_2.tar.bz2`, `feature_version=2`, filter `y==−1`), because it pins you to the exact 2,381‑dim vector your C# extractor must reproduce byte‑for‑byte. Keep the Python `ember`/LIEF version fixed and record it (LIEF 0.9.0 was the v2 reference; LIEF version drift is a known source of feature parity breaks — pin it in both your training env and your parity test harness).

---

### Sources
- [sklearn-onnx: convert a pipeline with a LightGBM classifier](https://onnx.ai/sklearn-onnx/auto_tutorial/plot_gexternal_lightgbm.html)
- [sklearn-onnx: probabilities as vector vs ZipMap](http://onnx.ai/sklearn-onnx/auto_examples/plot_convert_zipmap.html)
- [onnxmltools convert/lightgbm/convert.py](https://github.com/onnx/onnxmltools/blob/main/onnxmltools/convert/lightgbm/convert.py) · [operator_converters/LightGbm.py](https://github.com/onnx/onnxmltools/blob/main/onnxmltools/convert/lightgbm/operator_converters/LightGbm.py)
- [ONNX Runtime C# get-started](https://onnxruntime.ai/docs/get-started/with-csharp.html) · [C# API reference](https://lenisha.github.io/onnxruntime/docs/reference/api/csharp-api.html) · [InferenceTest.cs](https://github.com/microsoft/onnxruntime/blob/main/csharp/test/Microsoft.ML.OnnxRuntime.Tests.Common/InferenceTest.cs)
- [EMBER paper (arXiv 1804.04637)](https://arxiv.org/pdf/1804.04637) — AUC 0.99911, TPR≈98.2%@1%FPR
- [elastic/ember](https://github.com/elastic/ember) · [README](https://github.com/elastic/ember/blob/master/README.md) · [features.py](https://raw.githubusercontent.com/elastic/ember/master/ember/features.py) (2381 = v2 breakdown)
- [FutureComputing4AI/EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) (v3, 2568-dim — not for your v2 pipeline)

Key parity flags for you: (a) pin input width 2381 across model/JSON/C#; (b) don't trust output tensor *names* — read them from `OutputMetadata`; (c) malicious = `probabilities[:,1]`, verify once; (d) validate ONNX vs native LightGBM over the whole val set to catch float32 tree‑threshold flips, and derive the threshold from ONNX scores; (e) pin LIEF/ember versions.