"""
Train the Warden malware classifier (LightGBM over the EMBER v2 feature vector) and export it to ONNX
for the C# Warden.Ml.OnnxScorer.

Modes:
  --smoke                 Train a tiny model on synthetic data and export+verify ONNX (plumbing check).
  --ember-dir DIR         Use EMBER pre-vectorized features (X_train.dat / y_train.dat via the `ember`
                          package's read_vectorized_features) — no raw PEs needed.
  --pe-dir DIR --labels L Extract features (ember_features.feature_vector) from a folder of PEs + a CSV
                          of sha/label, then train.

Output (in --out, default ml-training/artifacts): model.onnx + metadata.json (dim, threshold, version).

Requires: numpy, lightgbm, scikit-learn, onnxmltools, skl2onnx, onnxruntime.
"""
import argparse
import json
import os

import numpy as np

DIM = 2381


def tune_threshold(y_true, scores, target_fpr=0.01):
    """Pick the smallest threshold whose false-positive rate is <= target_fpr on the validation set."""
    order = np.argsort(-scores)
    neg = (y_true == 0).sum()
    if neg == 0:
        return 0.5
    best = 1.0
    for t in np.unique(scores)[::-1]:
        pred = scores >= t
        fp = np.logical_and(pred, y_true == 0).sum()
        if fp / neg <= target_fpr:
            best = float(t)
        else:
            break
    return best


def export_onnx(booster, out_path):
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    onx = convert_lightgbm(
        booster,
        initial_types=[("input", FloatTensorType([None, DIM]))],
        zipmap=False,           # emit a clean float probabilities tensor, not a map
        target_opset=13,
    )
    with open(out_path, "wb") as f:
        f.write(onx.SerializeToString())


def malicious_prob(session, X):
    import onnxruntime as ort  # noqa: F401
    name = session.get_inputs()[0].name
    outputs = session.run(None, {name: X.astype(np.float32)})
    for o in outputs:
        arr = np.asarray(o)
        if arr.dtype.kind == "f" and arr.ndim == 2 and arr.shape[1] >= 2:
            return arr[:, -1]
    # fall back to the last float output
    return np.asarray(outputs[-1]).reshape(len(X), -1)[:, -1]


def train_lightgbm(X, y):
    import lightgbm as lgb
    params = dict(objective="binary", num_leaves=64, learning_rate=0.05, n_estimators=200,
                  min_child_samples=20, verbose=-1)
    model = lgb.LGBMClassifier(**params)
    model.fit(X, y)
    return model.booster_


def run(X, y, out_dir, version):
    import onnxruntime as ort
    os.makedirs(out_dir, exist_ok=True)
    n = len(X)
    split = int(n * 0.8)
    booster = train_lightgbm(X[:split], y[:split])

    onnx_path = os.path.join(out_dir, "model.onnx")
    export_onnx(booster, onnx_path)

    session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    val_scores = malicious_prob(session, X[split:])
    threshold = tune_threshold(y[split:], val_scores, target_fpr=0.01)

    meta = {"dim": DIM, "threshold": threshold, "version": version,
            "train_samples": int(split), "val_samples": int(n - split)}
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"exported {onnx_path}")
    print(f"metadata: {meta}")
    print(f"onnxruntime scored {len(val_scores)} validation samples "
          f"(min {val_scores.min():.3f}, max {val_scores.max():.3f}) — export verified.")


def smoke(out_dir):
    rng = np.random.RandomState(42)
    n = 800
    X = rng.rand(n, DIM).astype(np.float32)
    # learnable signal: label depends on the mean of the first 50 features
    y = (X[:, :50].mean(axis=1) > 0.5).astype(np.int32)
    run(X, y, out_dir, version="smoke-synthetic")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--ember-dir")
    ap.add_argument("--pe-dir")
    ap.add_argument("--labels")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "artifacts"))
    ap.add_argument("--version", default="1")
    args = ap.parse_args()

    if args.smoke:
        smoke(args.out)
    elif args.ember_dir:
        import ember
        X, y = ember.read_vectorized_features(args.ember_dir, subset="train")
        mask = y != -1  # drop unlabeled
        run(X[mask], y[mask], args.out, args.version)
    elif args.pe_dir and args.labels:
        import csv
        import ember_features as ef
        labels = {}
        with open(args.labels, newline="") as f:
            for row in csv.reader(f):
                labels[row[0]] = int(row[1])
        X, y = [], []
        for name, label in labels.items():
            path = os.path.join(args.pe_dir, name)
            if os.path.exists(path):
                X.append(ef.feature_vector(open(path, "rb").read()))
                y.append(label)
        run(np.array(X, dtype=np.float32), np.array(y), args.out, args.version)
    else:
        ap.error("choose one of --smoke, --ember-dir, or --pe-dir/--labels")


if __name__ == "__main__":
    main()
