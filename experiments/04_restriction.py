#!/usr/bin/env python3
"""
Experiment 04 -- H2: does topology survive information restriction better?

The pre-registered experiment (docs/metodologia/REPLANTEO-OPERACIONAL.md). It
does not run to completion on the current simulator and is not supposed to: the
per-flow baseline saturates at AUC 1.0000, so no comparison is possible. The
script exists so that the moment Phase 0 delivers a generator meeting its
acceptance criteria, or real data arrives, the experiment runs unchanged rather
than being designed after the data is in hand.

It refuses to report a comparison it cannot defend. `--force` overrides that
for debugging, and says so in the output.

H2
--
Under information restriction, topology degrades LESS than per-flow asymmetry,
and the gap widens with restriction.

    supported  delta >= 0.05 at some restriction level, CI excludes 0, and the
               C1 size-only arm explains less than half the treatment lift
    rejected   delta < 0.05 everywhere, or the CI includes 0
    confounded C1 explains most of the lift -- redesign, do not report

Arms, every level, always all four
----------------------------------
    topology     TUPLES        the treatment
    per-flow     DIRECTIONAL   the baseline, which wins on clean data
    combined     DIRECTIONAL   both, to see whether they are complementary
    size-only    TUPLES        control C1 -- the arm that caught a false 1.0000

Controls
--------
    C1  size-only reported in every cell
    C2  positives and negatives from the SAME run
    C3  combined arm separates "asymmetry helps" from "more features help"
    C4  degenerate windows dropped (min_flows)
    C5  label threshold explicit, sensitivity reportable via --tau

Usage
-----
    python experiments/04_restriction.py --axis sampling
    python experiments/04_restriction.py --axis truncation --tau 0.05
    python experiments/04_restriction.py --axis sampling --force   # ignore gate
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

import numpy as np
import polars as pl

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.features import InfoTier, window_features  # noqa: E402
from src.features.extractors import (  # noqa: E402
    PERFLOW_FEATURES,
    SIZE_FEATURES,
    TOPOLOGY_FEATURES,
)
from src.restriction import sample, truncate  # noqa: E402

RESULTS = Path("results/metrics")
MIN_WINDOWS_PER_CLASS = 250  # power requirement from the pre-registration
SATURATION_LIMIT = 0.90  # baseline above this means the instrument cannot discriminate
DELTA_THRESHOLD = 0.05  # declared before running


def _simulate(seed: int, duration: int) -> pl.DataFrame:
    from src.simulator.agents import AttackType, SimulationConfig, run_simulation

    return run_simulation(
        SimulationConfig(
            attack_type=AttackType.DDOS,
            asymmetry_level=0.8,
            duration_seconds=duration,
            seed=seed,
        )
    )


def _load_real(path: Path) -> pl.DataFrame:
    """Real flows, only the columns window_features actually touches.

    Same six-column selection already used in scripts/explore_real_data_structure.py
    and scripts/benchmark_real_data.py -- only the file with Src IP/Dst IP
    (Thuesday-20-02-2018 in the current bucket) can produce a graph/topology tier.
    """
    from src.ingest.loader import load_csv

    cols = ["timestamp", "src_ip", "dst_ip", "is_attack", "totlen_fwd_pkts", "totlen_bwd_pkts"]
    return load_csv(path).select(cols).drop_nulls().collect()


def _arm_auc(train: pl.DataFrame, test: pl.DataFrame, cols: list[str]) -> float:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score

    cols = [c for c in cols if c in train.columns]
    if not cols:
        return float("nan")
    ytr, yte = train["y"].to_numpy(), test["y"].to_numpy()
    if len(set(ytr)) < 2 or len(set(yte)) < 2:
        return float("nan")
    model = RandomForestClassifier(
        n_estimators=300, random_state=0, class_weight="balanced"
    ).fit(train[cols].to_numpy(), ytr)
    return float(roc_auc_score(yte, model.predict_proba(test[cols].to_numpy())[:, 1]))


def _build(df: pl.DataFrame, tau: float, window_seconds: int = 60) -> pl.DataFrame:
    """Both tiers on the same restricted frame, so arms are strictly comparable."""
    topo = window_features(df, tier=InfoTier.TUPLES, tau=tau, window_seconds=window_seconds)
    flow = window_features(df, tier=InfoTier.DIRECTIONAL, tau=tau, window_seconds=window_seconds)
    if len(topo) == 0 or len(flow) == 0:
        return pl.DataFrame()
    extra = [c for c in flow.columns if c not in topo.columns]
    return topo.hstack(flow.select(extra)) if extra else topo


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--axis", choices=("sampling", "truncation"), default="sampling")
    ap.add_argument("--tau", type=float, default=0.01, help="label threshold (C5)")
    ap.add_argument("--duration", type=int, default=2400, help="simulated seconds per run")
    ap.add_argument("--force", action="store_true", help="report even if the gate fails")
    ap.add_argument(
        "--data-path", type=Path, default=None,
        help="real CICIDS-2018 file with Src IP/Dst IP; omit to use the simulator",
    )
    ap.add_argument(
        "--window-seconds", type=int, default=60,
        help="window size for both the topology/per-flow build and truncation's boundary",
    )
    args = ap.parse_args()

    levels = (
        [(1, "1:1"), (10, "1:10"), (100, "1:100"), (1000, "1:1000")]
        if args.axis == "sampling"
        else [(1 / 60, "1s"), (5 / 60, "5s"), (10 / 60, "10s"), (1.0, "60s")]
    )

    print(f"H2 -- information restriction, axis = {args.axis}, tau = {args.tau}")

    real_train, real_test = None, None
    if args.data_path:
        from src.models.benchmark import temporal_split

        real_df = _load_real(args.data_path).with_columns(
            pl.col("timestamp").dt.epoch("s").alias("window_start")
        )
        real_train, real_test = temporal_split(real_df, train_ratio=0.7)
        print(f"real data: {args.data_path.name} ({len(real_df):,} flows), "
              f"window = {args.window_seconds}s")
    print("positives and negatives from the same run (C2)\n")
    print(
        f"{'level':>10}{'topology':>11}{'per-flow':>11}"
        f"{'combined':>11}{'C1 size':>10}{'n+/n-':>12}"
    )
    print("-" * 65)

    rows, gate_failures = [], []
    for level, label in levels:
        frames = {}
        if real_train is not None:
            for split, (source, seed) in (("train", (real_train, 1)), ("test", (real_test, 11))):
                restricted = (
                    sample(source, rate=int(level), seed=seed)
                    if args.axis == "sampling"
                    else truncate(
                        source, window_seconds=args.window_seconds, observed_fraction=level
                    )
                )
                built = _build(restricted, args.tau, window_seconds=args.window_seconds)
                frames[split] = built if len(built) else pl.DataFrame()
        else:
            for split, seeds in (("train", (1, 2)), ("test", (11,))):
                parts = []
                for seed in seeds:
                    df = _simulate(seed, args.duration)
                    df = (
                        sample(df, rate=int(level), seed=seed)
                        if args.axis == "sampling"
                        else truncate(df, window_seconds=60, observed_fraction=level)
                    )
                    built = _build(df, args.tau)
                    if len(built):
                        parts.append(built)
                frames[split] = pl.concat(parts) if parts else pl.DataFrame()

        train, test = frames["train"], frames["test"]
        if len(train) == 0 or len(test) == 0 or "y" not in test.columns:
            print(f"{label:>10}  no usable windows at this level")
            gate_failures.append(f"{label}: no usable windows")
            continue

        n_pos = int(test["y"].sum())
        n_neg = len(test) - n_pos
        aucs = {
            "topology": _arm_auc(train, test, list(TOPOLOGY_FEATURES)),
            "perflow": _arm_auc(train, test, list(PERFLOW_FEATURES)),
            "combined": _arm_auc(train, test, list(TOPOLOGY_FEATURES) + list(PERFLOW_FEATURES)),
            "size": _arm_auc(train, test, list(SIZE_FEATURES)),
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

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"h2_restriction_{args.axis}_w{args.window_seconds}.json"
    out.write_text(json.dumps({
        "axis": args.axis, "tau": args.tau, "window_seconds": args.window_seconds,
        "data_source": str(args.data_path) if args.data_path else "simulator",
        "rows": rows, "gate_failures": gate_failures,
    }, indent=2))

    print("\n" + "=" * 65)
    if gate_failures:
        print("GATE FAILED -- no verdict on H2 will be reported.\n")
        for f in dict.fromkeys(gate_failures):
            print(f"  - {f}")
        print(
            "\nThese are the Phase 0 acceptance criteria from docs/metodologia/. A"
            "\nbaseline that already scores near 1.0 leaves no headroom for any"
            "\ntreatment to win in, so a comparison here would measure nothing. This"
            "\nis the sixth time this instrument has blocked a measurement; the fix"
            "\nis the generator, not the experiment."
        )
        if not args.force:
            print(f"\nRaw numbers written to {out} for inspection.")
            return 1
        print("\n--force given: verdict below is NOT defensible, shown for debugging only.")

    valid = [r for r in rows if np.isfinite(r["topology"]) and np.isfinite(r["perflow"])]
    if not valid:
        print("no level produced a usable comparison")
        return 1

    best = max(valid, key=lambda r: r["topology"] - r["perflow"])
    delta = best["topology"] - best["perflow"]
    size_lift = best["size"] - 0.5
    topo_lift = best["topology"] - 0.5

    print(f"\nlargest delta (topology - per-flow): {delta:+.4f} at {best['level']}")
    if delta < DELTA_THRESHOLD:
        print(f"H2 REJECTED: delta < {DELTA_THRESHOLD} at every level.")
        print("Topology does not survive restriction better. The honest project is per-flow.")
    elif size_lift > 0.5 * topo_lift:
        share = size_lift / max(topo_lift, 1e-9)
        print(f"CONFOUNDED: C1 size-only explains {share:.0%} of the lift.")
        print("Redesign; do not report.")
    else:
        print(
            f"H2 SUPPORTED at {best['level']} "
            "-- pending a bootstrap CI on the paired difference."
        )
    print(f"\nResults written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
