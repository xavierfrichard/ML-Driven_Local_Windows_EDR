# Warden ML training + parity (Phase 3)

The ML tier scores unknown PEs with a **LightGBM** model over the **EMBER v2** (2381-dim) feature
vector, exported to **ONNX** and run in-process by `Warden.Ml.OnnxScorer`. The load-bearing risk is
that the C# feature extractor (`Warden.Ml.EmberFeatureExtractor`) must produce the **same** vector as
the Python extractor that trained the model. This folder is the Python reference + training pipeline.

## Files
- `ember_features.py` — the reference EMBER v2 extractor. Byte-only groups (histogram, byte-entropy,
  strings = 616 dims) are written to match the C# port **byte-for-byte**; PE-parsed groups use LIEF; the
  hashing trick uses sklearn `FeatureHasher` (which `Warden.Ml.Hashing` reproduces exactly).
- `gen_byte_parity.py` — emits `tests/Warden.Tests/parity/byte_groups.json`, the golden byte-group
  vectors the C# `EmberByteParityTests` validates against.
- `train.py` — trains LightGBM and exports `artifacts/model.onnx` + `metadata.json` (dim, threshold,
  version). Modes: `--smoke` (synthetic), `--ember-dir DIR` (pre-vectorized EMBER features), or
  `--pe-dir DIR --labels labels.csv` (extract from raw PEs).

## Setup
```
python -m pip install -r ml-training/requirements.txt
```

## What is validated (automated tests)
- `MlHashingTests` — C# MurmurHash3 + FeatureHasher match scikit-learn exactly (reference values).
- `EmberByteParityTests` — C# byte-only groups (616 dims) match `ember_features.py` byte-for-byte.
- `OnnxScorerSmokeTests` — C# ONNX Runtime loads + scores an onnxmltools LightGBM export.

Regenerate parity fixtures after any change to the byte-group logic:
```
python ml-training/gen_byte_parity.py
```

## Training a real model
1. Get a labeled dataset. Easiest: EMBER 2018/2024 **pre-vectorized** features (no raw PEs needed):
   `python ml-training/train.py --ember-dir /path/to/ember2018 --version 1`
2. Or extract from your own PEs: `--pe-dir /path/to/pes --labels labels.csv` (CSV rows: `filename,label`).
3. Deploy `artifacts/model.onnx` to the agent's model path (default `%ProgramData%\Warden\ml\model.onnx`)
   and set `MlOptions.HighThreshold` from the tuned `metadata.json.threshold`.

## Parity status
- **Exact (tested):** hashing primitive, and the 616 byte-only dims.
- **Pending full validation:** the PE-parsed groups (general/header/section/imports/exports/data-dirs =
  1765 dims) use PeNet in C# vs LIEF in Python. Their byte-for-byte parity depends on the two parsers
  agreeing on enum spellings, section entropy, import ordering, etc. Validate on the training box by
  extracting a corpus with both `ember_features.feature_vector` (Python) and a C# feature dump, and
  diffing per group — see `docs/phase3-research/ember-v2-spec.md` §"C# parity checklist".
