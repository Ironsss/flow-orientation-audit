#!/usr/bin/env python3
"""Phase 0 revalidation -- does the per-flow baseline saturate under
restriction, for Generator v2? (docs/methodology/P2_GENERATOR_V2_DESIGN_FREEZE.md
SS17: "Phase 0 revalidation", the step between P2.5 and Final Freeze.)

`experiments/04_restriction.py` is the pre-registered H2 experiment and its
Phase 0 gate (MIN_WINDOWS_PER_CLASS=250, SATURATION_LIMIT=0.90 on the
per-flow baseline) is what "the instrument has blocked six measurements"
(CLAUDE.md) refers to -- but that script only knows how to simulate with
Generator v1 (`src.simulator.agents.run_simulation`) or load a real CICIDS
file; it has no Generator v2 code path. This script asks the same Phase 0
question against Generator v2 (Candidate v2) WITHOUT editing the
pre-registered experiment file -- SS17 puts this revalidation before Final
Freeze, i.e. before H2 itself is meant to run, so wiring Generator v2 into
`experiments/04_restriction.py` for real belongs to that later step, not this
diagnostic one.

Unlike `experiments/04_restriction.py` (which re-derives window boundaries
from each restricted frame's own `ts.min()` -- the exact anchor-drift bug
P0.5 fixed), this script builds the canonical window grid ONCE from each
run's full trace and reads every restriction level off that same frozen grid
(`src.audit.canonical`), so a result here does not inherit P0's pre-P0.5 bug.

Train/test split: by run (statistical unit, SS9), stratified per
severity_regime, same 30 Candidate v2 Validation seeds and ~70/30 split as
`scripts/audit_generator_v2_p25.py` -- restriction is applied per level to
the SAME full traces already built for P2.5, not a fresh simulation.

Usage
-----
    .venv/Scripts/python.exe scripts/audit_generator_v2_restriction.py --axis sampling
    .venv/Scripts/python.exe scripts/audit_generator_v2_restriction.py --axis truncation
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.audit.canonical import build_canonical_windowing, canonical_window_features  # noqa: E402
from src.features import InfoTier  # noqa: E402
from src.features.extractors import PERFLOW_FEATURES, SIZE_FEATURES, TOPOLOGY_FEATURES  # noqa: E402
from src.restriction import sample, truncate  # noqa: E402
from src.simulator.v2 import (  # noqa: E402
    WINDOW_SECONDS,
    SeverityRegime,
    SimulationConfigV2,
    run_simulation_v2,
)

TAU = 0.01
MIN_FLOWS = 10
MIN_WINDOWS_PER_CLASS = 250  # same power requirement as experiments/04_restriction.py
SATURATION_LIMIT = 0.90  # same gate

#: Same 30 Candidate v2 Validation seeds as scripts/audit_generator_v2_validation.py
#: and scripts/audit_generator_v2_p25.py.
VAL_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: (40001, 40002, 40003, 40004, 40005),
    SeverityRegime.MEDIUM: (40011, 40012, 40013, 40014, 40015),
    SeverityRegime.HIGH: (40021, 40022, 40023, 40024, 40025),
    SeverityRegime.LOW_SIGNAL: tuple(range(40031, 40046)),
}
TRAIN_FRACTION = 0.70


def split_seeds(seeds: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n_train = max(1, round(len(seeds) * TRAIN_FRACTION))
    n_train = min(n_train, len(seeds) - 1)
    return seeds[:n_train], seeds[n_train:]


def build_full(seed: int, regime: SeverityRegime) -> pl.DataFrame:
    return run_simulation_v2(SimulationConfigV2(simulation_seed=seed, severity_regime=regime))


def arm_auc(train: pl.DataFrame, test: pl.DataFrame, cols: list[str]) -> float:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score

    cols = [c for c in cols if c in train.columns]
    ytr, yte = train["y_gt"].to_numpy(), test["y_gt"].to_numpy()
    if len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return float("nan")
    model = RandomForestClassifier(
        n_estimators=300, random_state=0, class_weight="balanced"
    ).fit(train[cols].to_numpy(), ytr)
    return float(roc_auc_score(yte, model.predict_proba(test[cols].to_numpy())[:, 1]))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--axis", choices=("sampling", "truncation"), default="sampling")
    ap.add_argument(
        "--stratum", choices=("all", "main"), default="all",
        help="'main' excludes Low-signal runs entirely (low/low_signal both run "
             "at ~100-120 flows/window -- see P2_PHASE0_REVALIDATION_FINDINGS.md's "
             "note that this is a volume property, not exactly the Main/Low-signal "
             "split; 'main' here still includes the 'low' severity_regime)",
    )
    ap.add_argument(
        "--json", type=Path, default=None,
        help="defaults to results/metrics/p2_phase0_revalidation_<axis>_<stratum>.json",
    )
    args = ap.parse_args()
    json_path = args.json or (
        REPO_ROOT / f"results/metrics/p2_phase0_revalidation_{args.axis}_{args.stratum}.json"
    )
    seed_plan = (
        VAL_SEEDS if args.stratum == "all"
        else {r: s for r, s in VAL_SEEDS.items() if r is not SeverityRegime.LOW_SIGNAL}
    )

    levels = (
        [(1, "1:1"), (10, "1:10"), (100, "1:100"), (1000, "1:1000")]
        if args.axis == "sampling"
        else [(1 / 60, "1s"), (5 / 60, "5s"), (10 / 60, "10s"), (1.0, "60s")]
    )

    print("=" * 90)
    print(f"PHASE 0 REVALIDATION -- Generator v2 (Candidate v2), axis={args.axis}, tau={TAU}")
    print("=" * 90)

    print("\nBuilding full traces + canonical windowing (once per run) ...")
    train_runs, test_runs = [], []
    for regime, seeds in seed_plan.items():
        train_seeds, test_seeds = split_seeds(seeds)
        for seed in train_seeds:
            full = build_full(seed, regime)
            cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
            train_runs.append({"seed": seed, "regime": regime, "full": full, "cw": cw})
        for seed in test_seeds:
            full = build_full(seed, regime)
            cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
            test_runs.append({"seed": seed, "regime": regime, "full": full, "cw": cw})
    print(f"{len(train_runs)} train runs, {len(test_runs)} test runs.")

    print(
        f"\n{'level':>10}{'topology':>11}{'per-flow':>11}"
        f"{'combined':>11}{'C1 size':>10}{'n+/n-':>12}"
    )
    print("-" * 65)

    rows, gate_failures = [], []
    for level, label in levels:
        def _restrict_and_featurize(r: dict) -> pl.DataFrame:
            restricted = (
                sample(r["full"], rate=int(level), seed=r["seed"])
                if args.axis == "sampling"
                else truncate(r["full"], window_seconds=WINDOW_SECONDS, observed_fraction=level)
            )
            return canonical_window_features(
                restricted, r["cw"], tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS
            ).filter(pl.col("feature_available"))

        train = pl.concat([_restrict_and_featurize(r) for r in train_runs])
        test = pl.concat([_restrict_and_featurize(r) for r in test_runs])

        if len(train) == 0 or len(test) == 0:
            print(f"{label:>10}  no usable windows at this level")
            gate_failures.append(f"{label}: no usable windows")
            continue

        n_pos = int(test["y_gt"].sum())
        n_neg = len(test) - n_pos
        aucs = {
            "topology": arm_auc(train, test, list(TOPOLOGY_FEATURES)),
            "perflow": arm_auc(train, test, list(PERFLOW_FEATURES)),
            "combined": arm_auc(train, test, list(TOPOLOGY_FEATURES) + list(PERFLOW_FEATURES)),
            "size": arm_auc(train, test, list(SIZE_FEATURES)),
        }
        print(
            f"{label:>10}{aucs['topology']:>11.4f}{aucs['perflow']:>11.4f}"
            f"{aucs['combined']:>11.4f}{aucs['size']:>10.4f}{f'{n_pos}/{n_neg}':>12}"
        )
        rows.append({"level": label, "n_pos": n_pos, "n_neg": n_neg, **aucs})

        if min(n_pos, n_neg) < MIN_WINDOWS_PER_CLASS:
            gate_failures.append(
                f"{label}: {min(n_pos, n_neg)} windows in the smaller class, "
                f"need {MIN_WINDOWS_PER_CLASS}"
            )
        if np.isfinite(aucs["perflow"]) and aucs["perflow"] > SATURATION_LIMIT:
            gate_failures.append(
                f"{label}: per-flow baseline at {aucs['perflow']:.4f} "
                f"> {SATURATION_LIMIT} (saturated)"
            )

    print("\n" + "=" * 65)
    if gate_failures:
        print("PHASE 0 GATE: FAIL\n")
        for f in dict.fromkeys(gate_failures):
            print(f"  - {f}")
    else:
        print("PHASE 0 GATE: PASS -- every level has >=250 windows/class and "
              "per-flow baseline <=0.90")

    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps({
        "axis": args.axis, "tau": TAU, "window_seconds": WINDOW_SECONDS,
        "data_source": "generator_v2_candidate_v2", "rows": rows,
        "gate_failures": gate_failures, "gate_verdict": "FAIL" if gate_failures else "PASS",
    }, indent=2, default=str))
    print(f"\nResults written to {json_path}")
    return 0 if not gate_failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
