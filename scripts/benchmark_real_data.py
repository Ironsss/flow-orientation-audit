#!/usr/bin/env python3
"""
First supervised classification benchmark against real CICIDS-2018 data.

Everything measured so far against real data was either a single isolated
feature (scripts/analyze_real_data.py's per-flow asymmetry AUC) or unsupervised
clustering (scripts/explore_real_data_structure.py) -- never an actual
classifier. src/models/benchmark.py already has five fully-implemented,
imbalance-aware models (RandomForest, XGBoost, IsolationForest, OneClassSVM,
Autoencoder) with SHAP support, and they were never run against real data.

Crucially, those model runners are agnostic to whether the feature matrix came
from graph windows or raw flows -- they only need feature columns plus
`has_attack` (and `window_start` for the temporal split). So this script skips
graph construction and IAG entirely (unlike experiments/02_benchmark.py, which
is legacy and tied to that retired pipeline) and classifies at flow level,
using all available real flows -- which also sidesteps the window-count power
problem that gated the Phase 0 / H2 analysis (docs/datos-reales/): a flow-level
classifier on the DDoS file sees 7.9M rows, not 63-719 windows.

Reused, not reimplemented: src.ingest.loader.load_csv, CLASSIC_FEATURES,
src.models.benchmark.{temporal_split, _prepare_features, run_random_forest,
run_xgboost, run_isolation_forest, run_one_class_svm, run_autoencoder,
compute_shap_values}, src.viz.plots.{plot_feature_importance, plot_shap_summary,
plot_pr_roc_curves}.

Reports attack-class precision/recall/F1 and the actual PR/ROC curves, not just
the scalar PR-AUC/ROC-AUC: under class imbalance (7.2% attack in the DDoS
file), f1_macro folds in the much easier benign class and a single AUC number
can look strong while precision or recall on the attack class specifically is
mediocre. src.models.benchmark.BenchmarkResult now also carries precision_attack
and the raw y_score needed to plot the curves (added alongside this script).

Usage
-----
    python scripts/benchmark_real_data.py data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
    python scripts/benchmark_real_data.py data/raw/  # both files found in the directory
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ingest.loader import CLASSIC_FEATURES, load_csv  # noqa: E402
from src.models.benchmark import (  # noqa: E402
    _prepare_features,
    run_autoencoder,
    run_isolation_forest,
    run_one_class_svm,
    run_random_forest,
    run_xgboost,
    temporal_split,
)
from src.viz.plots import (  # noqa: E402
    plot_feature_importance,
    plot_pr_roc_curves,
    plot_shap_summary,
)

RESULTS_DIR = Path("results")
FIGURES_DIR = RESULTS_DIR / "figures"
METRICS_DIR = RESULTS_DIR / "metrics"

GREEN, BLUE, BOLD, NC = "\033[0;32m", "\033[0;34m", "\033[1m", "\033[0m"

ONE_CLASS_SVM_MAX_BENIGN = 50_000


def _log(msg: str) -> None:
    print(f"{BLUE}[INFO]{NC} {msg}")


def _header(msg: str) -> None:
    print(f"\n{BOLD}{msg}{NC}\n{'-' * len(msg)}")


def build_flow_feature_matrix(path: Path) -> tuple[pl.DataFrame, list[str]]:
    """Flow-level feature matrix: CLASSIC_FEATURES (non-degenerate) + labels.

    No graph, no window, no IAG -- classification only needs the features
    themselves. `window_start` is added (epoch seconds of `timestamp`) purely
    so `temporal_split` sorts chronologically before splitting: row order is
    not reliable after `_clean_data()`'s `.unique()` (documented in
    src/ingest/loader.py), so without an explicit sort key the split would not
    actually be temporal.
    """
    lf = load_csv(path)
    names = lf.collect_schema().names()
    candidate_cols = [c for c in CLASSIC_FEATURES if c in names]

    stats = lf.select(
        [pl.col(c).std().alias(c) for c in candidate_cols]
    ).collect().row(0, named=True)
    feature_cols = [c for c in candidate_cols if stats[c] and stats[c] > 0]

    df = (
        lf.select([*feature_cols, "is_attack", "timestamp"])
        .drop_nulls()
        .with_columns(
            pl.col("is_attack").alias("has_attack"),
            pl.col("timestamp").dt.epoch("s").alias("window_start"),
        )
        .collect()
    )
    return df, feature_cols


def _systematic_subsample(
    X: np.ndarray, y: np.ndarray, max_n: int
) -> tuple[np.ndarray, np.ndarray]:
    """Deterministic every-k-th-row subsample -- same no-RNG discipline as
    scripts/analyze_real_data.py::sampled_classic_matrix."""
    n = len(X)
    if n <= max_n:
        return X, y
    stride = n // max_n
    idx = np.arange(0, n, stride)[:max_n]
    return X[idx], y[idx]


def benchmark_file(path: Path) -> dict:
    _header(f"Benchmarking {path.name}")
    t0 = time.time()

    df, feature_cols = build_flow_feature_matrix(path)
    _log(f"{len(df):,} flows, {len(feature_cols)} non-degenerate CLASSIC_FEATURES")

    train_df, test_df = temporal_split(df, train_ratio=0.7)
    X_train, X_test, y_train, y_test = _prepare_features(train_df, test_df, feature_cols)
    _log(
        f"train={len(y_train):,} ({y_train.mean():.1%} attack), "
        f"test={len(y_test):,} ({y_test.mean():.1%} attack)"
    )

    results: dict[str, dict] = {}

    for name, runner, kwargs in (
        ("RandomForest", run_random_forest, {"compute_shap": True}),
        ("XGBoost", run_xgboost, {"compute_shap": True}),
        ("IsolationForest", run_isolation_forest, {}),
        ("Autoencoder", run_autoencoder, {}),
    ):
        t_model = time.time()
        r = runner(X_train, X_test, y_train, y_test, "classic", feature_cols, **kwargs)
        elapsed = time.time() - t_model
        _log(
            f"{name}: PR-AUC={r.pr_auc:.4f} ROC-AUC={r.roc_auc:.4f} "
            f"precision(attack)={r.precision_attack:.4f} recall(attack)={r.recall_attack:.4f} "
            f"F1(attack)={r.f1_per_class['attack']:.4f} fpr={r.fpr:.4f} ({elapsed:.1f}s)"
        )
        results[name] = {
            "pr_auc": r.pr_auc, "roc_auc": r.roc_auc, "f1_macro": r.f1_macro,
            "precision_attack": r.precision_attack, "recall_attack": r.recall_attack,
            "f1_attack": r.f1_per_class["attack"], "fpr": r.fpr,
            "elapsed_seconds": round(elapsed, 1),
        }
        if r.y_score is not None:
            FIGURES_DIR.mkdir(parents=True, exist_ok=True)
            plot_pr_roc_curves(
                y_test, r.y_score, model_name=name,
                save_path=FIGURES_DIR / f"real_data_benchmark_{path.stem}_{name}_pr_roc.png",
            )
        if r.feature_importances:
            top_names = list(r.feature_importances.keys())
            top_vals = list(r.feature_importances.values())
            FIGURES_DIR.mkdir(parents=True, exist_ok=True)
            plot_feature_importance(
                top_names, top_vals, top_k=min(20, len(top_names)),
                save_path=FIGURES_DIR / f"real_data_benchmark_{path.stem}_{name}_importance.png",
            )
        if r.shap_summary:
            plot_shap_summary(
                r.shap_summary["feature_names"], r.shap_summary["mean_abs_shap"],
                top_k=min(20, len(feature_cols)),
                save_path=FIGURES_DIR / f"real_data_benchmark_{path.stem}_{name}_shap.png",
            )

    # OneClassSVM: O(n^2)-O(n^3) per its own docstring -- bound the benign
    # training subset explicitly rather than let it run unbounded on millions
    # of rows. Subsample the benign rows specifically (not X_train as a
    # whole): the function trains only on y_train==0 internally, so
    # subsampling before that filter would leave the post-filter benign count
    # dependent on this file's attack rate instead of a fixed, known bound.
    t_model = time.time()
    benign_mask = y_train == 0
    X_train_svm, y_train_svm = _systematic_subsample(
        X_train[benign_mask], y_train[benign_mask], ONE_CLASS_SVM_MAX_BENIGN
    )
    r = run_one_class_svm(X_train_svm, X_test, y_train_svm, y_test, "classic", feature_cols)
    elapsed = time.time() - t_model
    _log(
        f"OneClassSVM (subsampled to {len(y_train_svm):,} train rows): "
        f"PR-AUC={r.pr_auc:.4f} ROC-AUC={r.roc_auc:.4f} "
        f"precision(attack)={r.precision_attack:.4f} recall(attack)={r.recall_attack:.4f} "
        f"F1(attack)={r.f1_per_class['attack']:.4f} ({elapsed:.1f}s)"
    )
    results["OneClassSVM"] = {
        "pr_auc": r.pr_auc, "roc_auc": r.roc_auc, "f1_macro": r.f1_macro,
        "precision_attack": r.precision_attack, "recall_attack": r.recall_attack,
        "f1_attack": r.f1_per_class["attack"], "fpr": r.fpr, "elapsed_seconds": round(elapsed, 1),
        "note": f"trained on a {len(y_train_svm):,}-row systematic subsample, not the full set",
    }
    if r.y_score is not None:
        FIGURES_DIR.mkdir(parents=True, exist_ok=True)
        plot_pr_roc_curves(
            y_test, r.y_score, model_name="OneClassSVM",
            save_path=FIGURES_DIR / f"real_data_benchmark_{path.stem}_OneClassSVM_pr_roc.png",
        )

    return {
        "file": path.name,
        "n_flows": len(df),
        "n_features": len(feature_cols),
        "feature_cols": feature_cols,
        "n_train": len(y_train),
        "n_test": len(y_test),
        "train_attack_rate": float(y_train.mean()),
        "test_attack_rate": float(y_test.mean()),
        "models": results,
        "elapsed_seconds": round(time.time() - t0, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("path", type=Path, help="CSV file or directory of CSVs (data/raw/)")
    args = ap.parse_args()

    paths = sorted(args.path.glob("*.csv")) if args.path.is_dir() else [args.path]
    if not paths:
        print(f"no CSV files found under {args.path}")
        return 2

    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = METRICS_DIR / "real_data_benchmark.json"

    # Resume support: a run over 10 files takes long enough that a killed
    # process should not lose already-computed files. Written after every
    # file, not just at the end, for the same reason.
    all_results = json.loads(out_path.read_text()) if out_path.exists() else []
    done = {r["file"] for r in all_results}

    for p in paths:
        if p.name in done:
            _log(f"skipping {p.name}, already in {out_path}")
            continue
        all_results.append(benchmark_file(p))
        out_path.write_text(json.dumps(all_results, indent=2, default=str))

    _header("Done")
    print(f"{GREEN}Written to {out_path}{NC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
