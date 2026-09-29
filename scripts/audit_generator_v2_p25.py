#!/usr/bin/env python3
"""P2.5 -- model-based diagnostics against Generator v2 (post-Validation, per
docs/methodology/P2_GENERATOR_V2_DESIGN_FREEZE.md SS15 / SS17 roadmap order).

Answers the question Validation's own AC1/AC2 (overlap coefficient,
threshold-split accuracy) only proxy for: does a real classifier, fit on
Generator v1's exact failure mode -- raw size (C1), per-flow asymmetry
(Flow), and topology (Topology) -- actually saturate on Generator v2? P1
found C1 size-only AUC=1.0000 on Generator v1; that is the concrete number
this script tries to reproduce or rule out on v2, not merely a proxy target.

Uses the 30 Candidate v2 Validation runs (recomputed deterministically from
their seeds -- same runs `scripts/audit_generator_v2_validation.py` used and
passed), never new simulations: per SS15, "to run after implementation,
never to shape it" -- this is diagnostic, not a tuning objective, and per
the design freeze's own SS13, generative parameters are not touched here
regardless of what these numbers show.

Train/test split is by RUN (the statistical unit, SS9), stratified by
severity_regime: the first ~70% of each regime's seeds (in seed order) train,
the rest test -- mirroring `src/models/benchmark.py::temporal_split`'s
leakage discipline (split by run, not by pooling all windows and shuffling)
without needing within-run temporal ordering, since C2 (same-run positives
and negatives) is already satisfied per-run.

Usage
-----
    .venv/Scripts/python.exe scripts/audit_generator_v2_p25.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import polars as pl

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.audit.canonical import build_canonical_windowing, canonical_window_features  # noqa: E402
from src.features import InfoTier  # noqa: E402
from src.features.extractors import PERFLOW_FEATURES, SIZE_FEATURES, TOPOLOGY_FEATURES  # noqa: E402
from src.simulator.v2 import (  # noqa: E402
    WINDOW_SECONDS,
    SeverityRegime,
    SimulationConfigV2,
    run_simulation_v2,
)

TAU = 0.01
MIN_FLOWS = 10

#: Candidate v2 Validation seeds, reproduced verbatim from
#: scripts/audit_generator_v2_validation.py -- same 30 runs that passed
#: Validation, recomputed deterministically rather than re-read from the
#: gitignored JSON artifact.
VAL_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: (40001, 40002, 40003, 40004, 40005),
    SeverityRegime.MEDIUM: (40011, 40012, 40013, 40014, 40015),
    SeverityRegime.HIGH: (40021, 40022, 40023, 40024, 40025),
    SeverityRegime.LOW_SIGNAL: tuple(range(40031, 40046)),
}
TRAIN_FRACTION = 0.70


def split_seeds(seeds: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n_train = max(1, round(len(seeds) * TRAIN_FRACTION))
    n_train = min(n_train, len(seeds) - 1)  # keep >=1 test seed per regime
    return seeds[:n_train], seeds[n_train:]


def build_features(seed: int, regime: SeverityRegime) -> pl.DataFrame:
    cfg = SimulationConfigV2(simulation_seed=seed, severity_regime=regime)
    df = run_simulation_v2(cfg)
    cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=TAU)
    feat = canonical_window_features(df, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)
    return feat.filter(pl.col("feature_available")).with_columns(
        pl.lit(seed).alias("seed"), pl.lit(regime.value).alias("regime"),
    )


def arm_auc(train: pl.DataFrame, test: pl.DataFrame, cols: list[str]) -> dict:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import average_precision_score, roc_auc_score

    cols = [c for c in cols if c in train.columns]
    ytr, yte = train["y_gt"].to_numpy(), test["y_gt"].to_numpy()
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return {
            "roc_auc": float("nan"), "pr_auc": float("nan"),
            "n_train": len(train), "n_test": len(test),
        }
    model = RandomForestClassifier(
        n_estimators=300, random_state=0, class_weight="balanced"
    ).fit(train[cols].to_numpy(), ytr)
    score = model.predict_proba(test[cols].to_numpy())[:, 1]
    return {
        "roc_auc": float(roc_auc_score(yte, score)),
        "pr_auc": float(average_precision_score(yte, score)),
        "n_train": len(train), "n_test": len(test),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--json", type=Path, default=REPO_ROOT / "results/metrics/p2_generator_v2_p25.json",
    )
    args = ap.parse_args()

    print("=" * 90)
    print("P2.5 -- model-based diagnostics on Generator v2 (Candidate v2, Validation seeds)")
    print("=" * 90)

    train_frames, test_frames = [], []
    for regime, seeds in VAL_SEEDS.items():
        train_seeds, test_seeds = split_seeds(seeds)
        print(f"{regime.value}: train_seeds={train_seeds} test_seeds={test_seeds}")
        for seed in train_seeds:
            train_frames.append(build_features(seed, regime))
        for seed in test_seeds:
            test_frames.append(build_features(seed, regime))

    train = pl.concat(train_frames)
    test = pl.concat(test_frames)
    print(f"\ntrain windows (feature_available): {len(train)}  "
          f"(benign={int((train['y_gt']==0).sum())}, attack={int((train['y_gt']==1).sum())})")
    print(f"test windows (feature_available):  {len(test)}  "
          f"(benign={int((test['y_gt']==0).sum())}, attack={int((test['y_gt']==1).sum())})")

    out: dict = {}
    for name, cols in (
        ("C1_size_only", list(SIZE_FEATURES)),
        ("Flow_baseline", list(PERFLOW_FEATURES)),
        ("Topology_baseline", list(TOPOLOGY_FEATURES)),
        ("Combined", list(SIZE_FEATURES) + list(PERFLOW_FEATURES) + list(TOPOLOGY_FEATURES)),
    ):
        result = arm_auc(train, test, cols)
        print(f"\n{name} (features={cols}):")
        print(f"  ROC-AUC={result['roc_auc']:.4f}  PR-AUC={result['pr_auc']:.4f}  "
              f"n_train={result['n_train']} n_test={result['n_test']}")
        out[name] = result

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nJSON written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
