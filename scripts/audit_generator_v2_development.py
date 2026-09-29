#!/usr/bin/env python3
"""P2 Development -- structural diagnostics for Generator v2 (informational only).

Per the design freeze (docs/methodology/P2_GENERATOR_V2_DESIGN_FREEZE.md SS8),
the Development split (10 Main: 4 low + 3 medium + 3 high, 10 Low-signal) "may
adjust permitted generative parameters (SS17)" but "does not declare PASS of
behavioral acceptance criteria" -- that only happens at Validation (SS10),
with a disjoint, never-reused seed set (SS12). Everything this script prints
or writes is therefore a Development-stage READING against the AC1-AC12
definitions, not an official PASS/FAIL, and none of it is a gate on anything.

Every quantity is measured from the emitted trace (`is_attack`, canonical
`y_gt`/`attack_ratio_gt`), never assumed from `SimulationConfigV2` -- same
discipline as `src.audit.generator_audit` (P1). Two approximations are used
because `run_simulation_v2` does not expose `AttackTiming` (P2.14) to callers,
by design (SS1: only `simulation_seed` is public):

  * "attack_start" is read off as the first canonical window with y_gt==1,
    not the underlying continuous `attack_start` -- window-resolution (60s),
    not exact.
  * AC6 (gradual transitions) is reported unconditionally over all 20 runs,
    not restricted to "ramp_seconds>0" runs as SS10/AC6 specifies, since
    ramp_seconds is not observable from outside. Flagged explicitly below.

Usage
-----
    .venv/Scripts/python.exe scripts/audit_generator_v2_development.py
    .venv/Scripts/python.exe scripts/audit_generator_v2_development.py \
        --json results/metrics/p2_generator_v2_development.json
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

from src.audit.canonical import build_canonical_windowing  # noqa: E402
from src.audit.generator_audit import (  # noqa: E402
    attack_phase_labels,
    background_flow_stats,
    window_generative_stats,
)
from src.simulator.v2 import (  # noqa: E402
    CONTEXT_MIN_WINDOWS_POST,
    CONTEXT_MIN_WINDOWS_PRE,
    DEFAULT_SERVICES,
    DURATION_SECONDS,
    WINDOW_SECONDS,
    SeverityRegime,
    SimulationConfigV2,
    Stratum,
    run_simulation_v2,
    stratum_of,
)

TAU = 0.01

#: Development seed plan (design freeze SS8): disjoint from every unit-test
#: seed (7, 23, 55, 101, 102 -- all < 1000) and reserved never to be reused as
#: Validation or Final Test seeds (SS12). Base 20000 makes that visually
#: obvious in any log or JSON dump.
DEV_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: (20001, 20002, 20003, 20004),
    SeverityRegime.MEDIUM: (20011, 20012, 20013),
    SeverityRegime.HIGH: (20021, 20022, 20023),
    SeverityRegime.LOW_SIGNAL: tuple(range(20031, 20041)),
}
assert sum(len(v) for v in DEV_SEEDS.values()) == 20, "design freeze SS8: Development total = 20"
assert len(DEV_SEEDS[SeverityRegime.LOW]) == 4
assert len(DEV_SEEDS[SeverityRegime.MEDIUM]) == 3
assert len(DEV_SEEDS[SeverityRegime.HIGH]) == 3
assert len(DEV_SEEDS[SeverityRegime.LOW_SIGNAL]) == 10

#: Reproduction of the onset-feasibility arithmetic in
#: `src.simulator.v2.attack._feasible_onset_range`, using only the frozen
#: constants and `SimulationConfigV2` defaults -- kept local (not imported)
#: because that function is a private implementation detail of the attack
#: module, not part of Generator v2's public surface (SS1).
_ONSET_FRACTION_RANGE = (0.15, 0.70)
_ATTACK_DURATION_RANGE = (300.0, 1800.0)
_ONSET_LO = max(
    _ONSET_FRACTION_RANGE[0] * DURATION_SECONDS, CONTEXT_MIN_WINDOWS_PRE * WINDOW_SECONDS
)
_ONSET_HI = min(
    _ONSET_FRACTION_RANGE[1] * DURATION_SECONDS,
    DURATION_SECONDS - CONTEXT_MIN_WINDOWS_POST * WINDOW_SECONDS - _ATTACK_DURATION_RANGE[0],
)
_ONSET_SPAN = _ONSET_HI - _ONSET_LO


def simulate(seed: int, regime: SeverityRegime) -> pl.DataFrame:
    return run_simulation_v2(SimulationConfigV2(simulation_seed=seed, severity_regime=regime))


def build_run(seed: int, regime: SeverityRegime) -> dict:
    full = simulate(seed, regime)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    gen = attack_phase_labels(window_generative_stats(full, cw))
    return {"full": full, "cw": cw, "gen": gen, "regime": regime, "seed": seed}


def _desc(a: np.ndarray) -> dict:
    if a.size == 0:
        return {k: float("nan") for k in ("n", "mean", "std", "median", "min", "max")}
    return {
        "n": int(a.size), "mean": float(a.mean()), "std": float(a.std()),
        "median": float(np.median(a)), "min": float(a.min()), "max": float(a.max()),
    }


def _print_table(title: str, rows: list[dict], cols: list[str]) -> None:
    print(f"\n{title}")
    if not rows:
        print("  (no rows)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print(" | ".join(c.rjust(widths[c]) for c in cols))
    print("-+-".join("-" * widths[c] for c in cols))
    for r in rows:
        print(" | ".join(str(r.get(c, "")).rjust(widths[c]) for c in cols))


def overlap_coefficient(a: np.ndarray, b: np.ndarray, n_bins: int = 30) -> float:
    """Histogram-based overlapping coefficient on shared bins, in [0, 1].

    OVL = sum_i min(p_a[i], p_b[i]) over a common bin grid spanning both
    samples -- 0 = disjoint supports, 1 = identical distributions. Chosen over
    a KDE estimate for simplicity and determinism (no bandwidth to pick).
    """
    if a.size == 0 or b.size == 0:
        return float("nan")
    lo, hi = min(a.min(), b.min()), max(a.max(), b.max())
    if lo == hi:
        return 1.0
    edges = np.linspace(lo, hi, n_bins + 1)
    ha, _ = np.histogram(a, bins=edges)
    hb, _ = np.histogram(b, bins=edges)
    pa = ha / ha.sum() if ha.sum() else ha.astype(float)
    pb = hb / hb.sum() if hb.sum() else hb.astype(float)
    return float(np.minimum(pa, pb).sum())


def best_threshold_accuracy(x: np.ndarray, y: np.ndarray) -> float:
    """AC1b/AC2b `sep_run`: max bidirectional threshold-split accuracy.

    Tries every split point of sorted `x` in both directions ("high predicts
    attack" and "low predicts attack") and returns the best accuracy -- the
    same operational meaning as fitting a depth-1 decision stump on `x` alone.
    """
    if x.size == 0 or len(set(y.tolist())) < 2:
        return float("nan")
    order = np.argsort(x)
    ys = y[order]
    n = ys.size
    cum_pos = np.cumsum(ys)
    cum_neg = np.cumsum(1 - ys)
    total_pos, total_neg = int(ys.sum()), int(n - ys.sum())
    best = 0.0
    for i in range(n + 1):
        neg_le = cum_neg[i - 1] if i > 0 else 0
        pos_gt = total_pos - (cum_pos[i - 1] if i > 0 else 0)
        pos_le = cum_pos[i - 1] if i > 0 else 0
        neg_gt = total_neg - (cum_neg[i - 1] if i > 0 else 0)
        best = max(best, (neg_le + pos_gt) / n, (pos_le + neg_gt) / n)
    return float(best)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--json", type=Path,
        default=REPO_ROOT / "results/metrics/p2_generator_v2_development.json",
    )
    args = ap.parse_args()

    print("=" * 90)
    print("P2 DEVELOPMENT -- Generator v2 structural diagnostics (informational, not PASS/FAIL)")
    print("=" * 90)
    print(f"tau={TAU} window_seconds={WINDOW_SECONDS} duration_seconds={DURATION_SECONDS}")
    print(f"configured onset window (measured proxy target): [{_ONSET_LO:.0f}, {_ONSET_HI:.0f}) "
          f"seconds, span={_ONSET_SPAN:.0f}s")

    out: dict = {
        "seed_plan": {r.value: list(s) for r, s in DEV_SEEDS.items()},
        "tau": TAU,
    }

    # ---------------------------------------------------------------- build
    runs = []
    for regime, seeds in DEV_SEEDS.items():
        for seed in seeds:
            print(f"simulating regime={regime.value} seed={seed} ...")
            runs.append(build_run(seed, regime))
    print(f"\n{len(runs)} Development runs built.")

    all_gen = pl.concat([
        r["gen"].with_columns(
            pl.lit(r["seed"]).alias("seed"),
            pl.lit(r["regime"].value).alias("severity_regime"),
            pl.lit(stratum_of(r["regime"]).value).alias("stratum"),
        )
        for r in runs
    ])

    # -------------------------------------------------------- AC5 (diversity)
    print("\n--- AC5-style: severity diversity (Development scale, N=20) ---")
    counts = (
        all_gen.group_by("seed", "severity_regime").len().group_by("severity_regime").len()
    ).to_dicts()
    _print_table("runs per severity_regime", counts, ["severity_regime", "len"])
    out["ac5_severity_diversity"] = counts

    # ---------------------------------------------------- AC12 / C2 same-run
    print("\n--- AC12/C2: same-run positives + negatives ---")
    ac12_rows = []
    for r in runs:
        g = r["gen"]
        nb, na = int((g["y_gt"] == 0).sum()), int((g["y_gt"] == 1).sum())
        ac12_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "benign_windows": nb, "attack_windows": na, "both_present": nb > 0 and na > 0,
        })
    _print_table("AC12 per run", ac12_rows,
                 ["seed", "regime", "benign_windows", "attack_windows", "both_present"])
    ac12_pass_fraction = float(np.mean([row["both_present"] for row in ac12_rows]))
    print(f"AC12 fraction of runs with both classes present: {ac12_pass_fraction:.2%} "
          f"(target at Validation: 100%)")
    out["ac12_same_run"] = {"rows": ac12_rows, "fraction_both_present": ac12_pass_fraction}

    # --------------------------------------------------- AC3 onset diversity
    print("\n--- AC3-style: randomized onset (measured off first y_gt==1 window) ---")
    onset_rows = []
    for r in runs:
        g = r["gen"].sort("window_id")
        atk = g.filter(pl.col("y_gt") == 1)
        wid = int(atk["window_id"].min()) if len(atk) else None
        start_s = int(atk["window_start"].min()) if len(atk) else None
        onset_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "attack_start_window_id": wid, "attack_start_s": start_s,
        })
    _print_table("onset per run", onset_rows,
                 ["seed", "regime", "attack_start_window_id", "attack_start_s"])
    starts = [row["attack_start_s"] for row in onset_rows if row["attack_start_s"] is not None]
    distinct_start_windows = len({row["attack_start_window_id"] for row in onset_rows
                                   if row["attack_start_window_id"] is not None})
    observed_span = (max(starts) - min(starts)) if len(starts) >= 2 else 0.0
    span_fraction = observed_span / _ONSET_SPAN if _ONSET_SPAN else float("nan")
    print(f"distinct attack_start_window_id: {distinct_start_windows} / {len(runs)} runs "
          f"(Validation target: >=15 / 30)")
    print(f"observed onset span: {observed_span:.0f}s = {span_fraction:.1%} of configured "
          f"span ({_ONSET_SPAN:.0f}s) (Validation target: >=30%)")
    out["ac3_onset"] = {
        "rows": onset_rows, "distinct_attack_start_window_id": distinct_start_windows,
        "observed_span_s": observed_span, "configured_span_s": _ONSET_SPAN,
        "span_fraction": span_fraction,
    }

    # ------------------------------------------------- AC6 gradual (proxy)
    print("\n--- AC6-style: gradual transitions (UNCONDITIONAL proxy -- see module docstring) ---")
    ac6_rows = []
    for r in runs:
        g = r["gen"]
        intermediate = g.filter(
            (pl.col("attack_ratio_gt") > 0.02) & (pl.col("attack_ratio_gt") < 0.90)
        )
        ac6_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "n_intermediate_windows": len(intermediate),
            "has_ramp_evidence": len(intermediate) >= 2,
        })
    _print_table("AC6 per run (proxy)", ac6_rows,
                 ["seed", "regime", "n_intermediate_windows", "has_ramp_evidence"])
    ac6_fraction = float(np.mean([row["has_ramp_evidence"] for row in ac6_rows]))
    print(f"fraction of runs with >=2 intermediate windows: {ac6_fraction:.2%} "
          f"(Validation target, ramp>0 runs only: >=50% -- this proxy is unconditional over "
          f"all {len(runs)} runs, not just ramp>0, so it UNDERSTATES the true AC6 rate)")
    out["ac6_gradual_proxy"] = {"rows": ac6_rows, "fraction_with_ramp_evidence": ac6_fraction}

    # --------------------------------------------------------- AC7 near-tau
    print("\n--- AC7-style: near-tau availability (bilateral) ---")
    ac7_rows = []
    for r in runs:
        g = r["gen"]
        near_zero = g.filter((pl.col("attack_ratio_gt") > 0) & (pl.col("attack_ratio_gt") < TAU))
        near_tau = g.filter(
            (pl.col("attack_ratio_gt") >= TAU) & (pl.col("attack_ratio_gt") <= 5 * TAU)
        )
        ac7_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "has_near_zero_window": len(near_zero) > 0, "has_near_tau_window": len(near_tau) > 0,
        })
    _print_table("AC7 per run", ac7_rows,
                 ["seed", "regime", "has_near_zero_window", "has_near_tau_window"])
    n_near_zero = sum(row["has_near_zero_window"] for row in ac7_rows)
    n_near_tau = sum(row["has_near_tau_window"] for row in ac7_rows)
    print(f"runs with a near-zero positive window (0<ratio<tau): {n_near_zero} "
          f"(Validation target: >=3)")
    print(f"runs with a near-tau window (tau<=ratio<=5*tau): {n_near_tau} "
          f"(Validation target: >=3)")
    out["ac7_near_tau"] = {
        "rows": ac7_rows, "n_runs_near_zero": n_near_zero, "n_runs_near_tau": n_near_tau,
    }

    # ---------------------------------------------- AC8/AC9 background audit
    print("\n--- AC8/AC9-style: background structure per run ---")
    bg_rows = []
    for r in runs:
        bg = background_flow_stats(r["full"])
        pair_coverage = (
            bg["n_unique_pairs"] / bg["n_possible_ordered_pairs"]
            if bg.get("n_possible_ordered_pairs") else float("nan")
        )
        benign_recip = r["gen"].filter(pl.col("y_gt") == 0)["reciprocity"].to_numpy()
        bg_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "pair_coverage_run": round(pair_coverage, 4),
            "std_recip_run": (
                round(float(benign_recip.std()), 4) if benign_recip.size else float("nan")
            ),
        })
    _print_table("AC8/AC9 per run", bg_rows,
                 ["seed", "regime", "pair_coverage_run", "std_recip_run"])
    coverages = np.array([row["pair_coverage_run"] for row in bg_rows])
    stds = np.array([row["std_recip_run"] for row in bg_rows])
    print(f"AC8 pair_coverage_run: median={np.median(coverages):.3f} "
          f"(target: <0.50), fraction<0.50={float((coverages < 0.50).mean()):.2%} (target >=80%)")
    print(f"AC9 std_recip_run: median={np.median(stds):.3f} (target: >0.05), "
          f"fraction>0.02={float((stds > 0.02).mean()):.2%} (target >=70%)")
    low_recip_services = [
        name for name, profile in DEFAULT_SERVICES.items() if profile.response_probability < 0.5
    ]
    print(f"services configured with reciprocity < 0.5: {[s.value for s in low_recip_services]} "
          f"(target: >=2)")
    out["ac8_ac9_background"] = {
        "rows": bg_rows,
        "ac8_median_pair_coverage": float(np.median(coverages)),
        "ac8_fraction_below_0.5": float((coverages < 0.50).mean()),
        "ac9_median_std_recip": float(np.median(stds)),
        "ac9_fraction_above_0.02": float((stds > 0.02).mean()),
        "low_reciprocity_services": [s.value for s in low_recip_services],
    }

    # ------------------------------------------------------- AC1/AC2 overlap
    print("\n--- AC1/AC2-style: node-count / volume overlap + per-run separability ---")
    n_nodes = all_gen["n_nodes"].to_numpy().astype(float)
    n_flows = all_gen["n_flows"].to_numpy().astype(float)
    y = all_gen["y_gt"].to_numpy()
    ovl_nodes = overlap_coefficient(n_nodes[y == 0], n_nodes[y == 1])
    ovl_flows = overlap_coefficient(n_flows[y == 0], n_flows[y == 1])
    print(f"AC1a pooled OVL(n_nodes) = {ovl_nodes:.4f} (Validation target: >=0.30)")
    print(f"AC2a pooled OVL(n_flows) = {ovl_flows:.4f} (Validation target: >=0.20)")

    sep_rows = []
    for r in runs:
        g = r["gen"]
        y_arr = g["y_gt"].to_numpy()
        sep_nodes = best_threshold_accuracy(g["n_nodes"].to_numpy().astype(float), y_arr)
        sep_flows = best_threshold_accuracy(g["n_flows"].to_numpy().astype(float), y_arr)
        sep_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "sep_run_n_nodes": round(sep_nodes, 4), "sep_run_n_flows": round(sep_flows, 4),
        })
    _print_table("sep_run per run", sep_rows,
                 ["seed", "regime", "sep_run_n_nodes", "sep_run_n_flows"])
    frac_sep_nodes = float(np.mean([row["sep_run_n_nodes"] >= 0.95 for row in sep_rows]))
    eligible = [row for row in sep_rows
                if row["regime"] in ("low", "low_signal")]
    frac_sep_flows_eligible = (
        float(np.mean([row["sep_run_n_flows"] >= 0.95 for row in eligible]))
        if eligible else float("nan")
    )
    print(f"AC1b fraction of runs with sep_run(n_nodes)>=0.95: {frac_sep_nodes:.2%} "
          f"(Validation target: <=20%)")
    print(f"AC2b fraction of eligible runs (low/low_signal) with sep_run(n_flows)>=0.95: "
          f"{frac_sep_flows_eligible:.2%} (Validation target: <=20%, n_eligible={len(eligible)})")
    out["ac1_ac2_overlap_and_separability"] = {
        "ovl_n_nodes": ovl_nodes, "ovl_n_flows": ovl_flows,
        "sep_run_rows": sep_rows,
        "ac1b_fraction_sep_ge_0.95": frac_sep_nodes,
        "ac2b_fraction_sep_ge_0.95_eligible": frac_sep_flows_eligible,
    }

    # --------------------------------------------------------------- AC11b
    print("\n--- AC11b-style: Low-signal validity ---")
    ls_gen = all_gen.filter(pl.col("stratum") == Stratum.LOW_SIGNAL.value)
    main_gen = all_gen.filter(pl.col("stratum") == Stratum.MAIN.value)
    ls_pos = ls_gen.filter(pl.col("y_gt") == 1)["attack_ratio_gt"].to_numpy()
    main_pos = main_gen.filter(pl.col("y_gt") == 1)["attack_ratio_gt"].to_numpy()
    ls_median = float(np.median(ls_pos)) if ls_pos.size else float("nan")
    main_q1 = float(np.percentile(main_pos, 25)) if main_pos.size else float("nan")
    cond2 = ls_median < main_q1
    print(f"median positive attack_ratio_gt (Low-signal) = {ls_median:.4f}")
    print(f"Q1 positive attack_ratio_gt (Main) = {main_q1:.4f}")
    print(f"median(Low-signal) < Q1(Main): {cond2}")
    out["ac11b_low_signal_validity"] = {
        "ls_median_positive_ratio": ls_median, "main_q1_positive_ratio": main_q1,
        "condition_2_holds": cond2,
    }

    # --------------------------------------------------------------- AC11a
    print("\n--- AC11a: Low-signal reproducibility (same seed twice) ---")
    seed = DEV_SEEDS[SeverityRegime.LOW_SIGNAL][0]
    a = simulate(seed, SeverityRegime.LOW_SIGNAL)
    b = simulate(seed, SeverityRegime.LOW_SIGNAL)
    identical = a.equals(b)
    print(f"seed={seed}: identical trace on repeat = {identical}")
    out["ac11a_reproducibility"] = {"seed": seed, "identical": identical}

    # -------------------------------------------------------------- write
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nJSON written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
