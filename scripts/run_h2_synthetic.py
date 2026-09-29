#!/usr/bin/env python3
"""H2 synthetic -- the actual pre-registered comparison, on Generator v2's
frozen Final Test data (docs/methodology/P2_FINAL_FREEZE.md), scoped to the
restriction levels Phase 0 revalidation cleared
(docs/methodology/P2_PHASE0_REVALIDATION_FINDINGS.md, option (a)): 1:1 and
1:10 sampling; 5s, 10s and 60s truncation. 1:100/1:1000 sampling and 1s
truncation are out of scope by the recorded decision -- they cannot produce
a two-class comparison at Candidate v2 for a structural reason unrelated to
run count.

H2 (docs/metodologia/REPLANTEO-OPERACIONAL.md)
-----------------------------------------------
Under information restriction, topology degrades LESS than per-flow
directional asymmetry, and the gap widens with restriction.

    supported   delta >= 0.05 at some in-scope level, bootstrap 95% CI on
                the paired difference excludes 0, and C1 size-only explains
                less than half the topology lift
    rejected    delta < 0.05 everywhere in scope, or every CI includes 0
    confounded  C1 explains most of the topology lift -- redesign, do not
                report

Implements the bootstrap CI experiments/04_restriction.py's own decision
rule references but never implemented ("pending a bootstrap CI on the
paired difference"). Bootstraps the TEST set's rows (paired: the same
resampled indices score both arms), not model refits -- 2000 resamples on
already-computed per-row scores, so this is a resampling of the AUC
estimate's sampling distribution, not of training variability.

Uses the 49 frozen Final Test runs (21 Main, 28 Low-signal; seeds
50001-50058), split by run (statistical unit, SS9) ~70/30 stratified per
severity_regime, and `src.audit.canonical` throughout (P0.5's anchor-fixed
windowing) -- never `experiments/04_restriction.py`'s own windowing, and
never touches that file.

Usage
-----
    .venv/Scripts/python.exe scripts/run_h2_synthetic.py
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
DELTA_THRESHOLD = 0.05  # declared before running, matches experiments/04_restriction.py
N_BOOTSTRAP = 2000
BOOTSTRAP_SEED = 0

FINAL_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: tuple(range(50001, 50008)),
    SeverityRegime.MEDIUM: tuple(range(50011, 50018)),
    SeverityRegime.HIGH: tuple(range(50021, 50028)),
    SeverityRegime.LOW_SIGNAL: tuple(range(50031, 50059)),
}
TRAIN_FRACTION = 0.70

#: In scope per the recorded Phase 0 decision (option (a)).
SAMPLING_LEVELS = [(1, "1:1"), (10, "1:10")]
TRUNCATION_LEVELS = [(5 / 60, "5s"), (10 / 60, "10s"), (1.0, "60s")]


def split_seeds(seeds: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n_train = max(1, round(len(seeds) * TRAIN_FRACTION))
    n_train = min(n_train, len(seeds) - 1)
    return seeds[:n_train], seeds[n_train:]


def build_full(seed: int, regime: SeverityRegime) -> pl.DataFrame:
    return run_simulation_v2(SimulationConfigV2(simulation_seed=seed, severity_regime=regime))


def fit_and_score(train: pl.DataFrame, test: pl.DataFrame, cols: list[str]):
    from sklearn.ensemble import RandomForestClassifier

    cols = [c for c in cols if c in train.columns]
    ytr, yte = train["y_gt"].to_numpy(), test["y_gt"].to_numpy()
    if not cols or len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return None, yte
    model = RandomForestClassifier(
        n_estimators=300, random_state=0, class_weight="balanced"
    ).fit(train[cols].to_numpy(), ytr)
    return model.predict_proba(test[cols].to_numpy())[:, 1], yte


def auc(y: np.ndarray, score: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score

    if score is None or len(set(y.tolist())) < 2:
        return float("nan")
    return float(roc_auc_score(y, score))


def bootstrap_ci_delta(
    y: np.ndarray, score_a: np.ndarray, score_b: np.ndarray, *, n: int = N_BOOTSTRAP,
) -> tuple[float, float]:
    """95% CI on AUC(a) - AUC(b), resampling (y, score_a, score_b) triples
    together with replacement -- paired, so both arms see the same resampled
    windows each iteration."""
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    n_rows = len(y)
    deltas = np.empty(n)
    for i in range(n):
        idx = rng.integers(0, n_rows, size=n_rows)
        yb = y[idx]
        if len(set(yb.tolist())) < 2:
            deltas[i] = np.nan
            continue
        deltas[i] = auc(yb, score_a[idx]) - auc(yb, score_b[idx])
    deltas = deltas[np.isfinite(deltas)]
    if deltas.size == 0:
        return float("nan"), float("nan")
    return float(np.percentile(deltas, 2.5)), float(np.percentile(deltas, 97.5))


def run_axis(axis: str, train_runs: list[dict], test_runs: list[dict]) -> list[dict]:
    levels = SAMPLING_LEVELS if axis == "sampling" else TRUNCATION_LEVELS
    print(f"\n{'='*90}\nAXIS = {axis}\n{'='*90}")
    print(
        f"{'level':>10}{'topology':>11}{'per-flow':>11}"
        f"{'combined':>11}{'C1 size':>10}{'n_atk/n_ben':>14}"
    )
    print("-" * 68)

    rows = []
    for level, label in levels:
        def _feat(r: dict) -> pl.DataFrame:
            restricted = (
                sample(r["full"], rate=int(level), seed=r["seed"])
                if axis == "sampling"
                else truncate(r["full"], window_seconds=WINDOW_SECONDS, observed_fraction=level)
            )
            return canonical_window_features(
                restricted, r["cw"], tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS
            ).filter(pl.col("feature_available"))

        train = pl.concat([_feat(r) for r in train_runs])
        test = pl.concat([_feat(r) for r in test_runs])
        n_atk, n_ben = int(test["y_gt"].sum()), len(test) - int(test["y_gt"].sum())

        score_topo, y_topo = fit_and_score(train, test, list(TOPOLOGY_FEATURES))
        score_flow, y_flow = fit_and_score(train, test, list(PERFLOW_FEATURES))
        score_comb, _ = fit_and_score(
            train, test, list(TOPOLOGY_FEATURES) + list(PERFLOW_FEATURES)
        )
        score_size, _ = fit_and_score(train, test, list(SIZE_FEATURES))

        auc_topo, auc_flow = auc(y_topo, score_topo), auc(y_flow, score_flow)
        auc_comb, auc_size = auc(y_topo, score_comb), auc(y_topo, score_size)
        print(f"{label:>10}{auc_topo:>11.4f}{auc_flow:>11.4f}{auc_comb:>11.4f}"
              f"{auc_size:>10.4f}{f'{n_atk}/{n_ben}':>14}")

        ci_lo = ci_hi = float("nan")
        if score_topo is not None and score_flow is not None:
            ci_lo, ci_hi = bootstrap_ci_delta(y_topo, score_topo, score_flow)

        # Exploratory only (post-hoc, not part of the pre-registered H2 decision
        # rule, which is topology-vs-perflow alone): does adding topology to
        # per-flow features help beyond per-flow alone? Same paired-bootstrap
        # method, applied to a different pair.
        ci_comb_lo = ci_comb_hi = float("nan")
        if score_comb is not None and score_flow is not None:
            ci_comb_lo, ci_comb_hi = bootstrap_ci_delta(y_topo, score_comb, score_flow)

        rows.append({
            "axis": axis, "level": label, "n_attack": n_atk, "n_benign": n_ben,
            "topology": auc_topo, "perflow": auc_flow, "combined": auc_comb, "size": auc_size,
            "delta": auc_topo - auc_flow, "ci_lo": ci_lo, "ci_hi": ci_hi,
            "delta_combined_vs_perflow": auc_comb - auc_flow,
            "ci_combined_lo": ci_comb_lo, "ci_combined_hi": ci_comb_hi,
        })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--json", type=Path, default=REPO_ROOT / "results/metrics/h2_synthetic_final.json",
    )
    args = ap.parse_args()

    print("Building 49 Final Test full traces + canonical windowing ...")
    train_runs, test_runs = [], []
    for regime, seeds in FINAL_SEEDS.items():
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

    rows = run_axis("sampling", train_runs, test_runs) + run_axis(
        "truncation", train_runs, test_runs
    )

    print(
        f"\n{'='*90}\nBOOTSTRAP 95% CI on paired delta (topology - per-flow), "
        f"N={N_BOOTSTRAP}\n{'='*90}"
    )
    for r in rows:
        print(f"  {r['axis']:>10} {r['level']:>6}: delta={r['delta']:+.4f}  "
              f"95% CI=[{r['ci_lo']:+.4f}, {r['ci_hi']:+.4f}]")

    print(
        f"\n{'='*90}\nEXPLORATORY (post-hoc, not the pre-registered H2 decision rule): "
        f"bootstrap 95% CI on paired delta (combined - per-flow), "
        f"N={N_BOOTSTRAP}\n{'='*90}"
    )
    for r in rows:
        print(f"  {r['axis']:>10} {r['level']:>6}: "
              f"delta={r['delta_combined_vs_perflow']:+.4f}  "
              f"95% CI=[{r['ci_combined_lo']:+.4f}, {r['ci_combined_hi']:+.4f}]")

    valid = [r for r in rows if np.isfinite(r["delta"])]
    if not valid:
        print("\nno level produced a usable comparison")
        return 1

    best = max(valid, key=lambda r: r["delta"])
    delta = best["delta"]
    ci_excludes_zero = best["ci_lo"] > 0 or best["ci_hi"] < 0
    size_lift = best["size"] - 0.5
    topo_lift = best["topology"] - 0.5

    print(f"\nBest level: {best['axis']} / {best['level']}  delta={delta:+.4f}  "
          f"95% CI=[{best['ci_lo']:+.4f}, {best['ci_hi']:+.4f}]")

    verdict = "REJECTED"
    reason = ""
    if delta < DELTA_THRESHOLD:
        reason = f"delta < {DELTA_THRESHOLD} at every in-scope level."
    elif not ci_excludes_zero:
        verdict, reason = "REJECTED", "the bootstrap 95% CI on the paired difference includes 0."
    elif size_lift > 0.5 * topo_lift:
        share = size_lift / max(topo_lift, 1e-9)
        verdict, reason = "CONFOUNDED", f"C1 size-only explains {share:.0%} of the topology lift."
    else:
        verdict = "SUPPORTED"
        reason = "delta clears the threshold, CI excludes 0, not confounded by size."

    print(f"\nH2 {verdict}: {reason}")

    out = {
        "delta_threshold": DELTA_THRESHOLD, "n_bootstrap": N_BOOTSTRAP,
        "rows": rows, "best": best, "verdict": verdict, "reason": reason,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nResults written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
