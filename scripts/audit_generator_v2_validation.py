#!/usr/bin/env python3
"""P2 Validation -- official PASS/FAIL for AC1-AC9, AC11, AC12 (SS10).

Per `docs/methodology/P2_GENERATOR_V2_DESIGN_FREEZE.md` SS8, Validation runs
30 NEW seeds (5 low + 5 medium + 5 high + 15 low_signal), never used in
Development, and this is where AC1-AC9/AC11/AC12 are officially declared
PASS/FAIL -- not the informational reading Development gave
(`scripts/audit_generator_v2_development.py`,
`docs/methodology/P2_DEVELOPMENT_FINDINGS.md`). AC10 (sample size) is Final
Test only (SS8) and AC4 needs the Development runs too (see below); every
other criterion here is self-contained to this script's 30 Validation runs.

AC4 (temporal non-determinism) is the one criterion that legitimately reads
both splits: Development freezes `p_dev(w)` (the fraction of Development runs
with y_gt(w)==1, per canonical window position w) and the resulting decision
rule `yhat(w) = 1 if p_dev(w)>=0.5 else 0`; Validation evaluates that FROZEN,
pre-committed rule against its own y_gt, never re-fit on Validation data
(SS10 AC4). Recomputing the Development runs here (deterministic given their
seeds) is equivalent to reading them from a saved artifact and avoids
depending on results/metrics/p2_generator_v2_development.json, which is
gitignored and not guaranteed to exist in a fresh checkout.

AC6 (gradual transitions) officially excludes "ramp_seconds=0" runs from its
denominator. `run_simulation_v2` does not expose the realized `ramp_seconds`
to callers (SS1: only `simulation_seed` is public), but every
`SeverityProfile.ramp_seconds_range` in the frozen candidate has a
continuous-uniform lower bound (0.0 or 300.0) -- `ramp_seconds` is drawn from
`rng.uniform(lo, hi)`, so P(ramp_seconds == 0.0 exactly) = 0 for every regime.
In practice every run qualifies as "ramp>0", so the y_gt-based intermediate-
window proxy IS the official measurement here, not an approximation (unlike
in the Development script, which flagged this as unconditional/approximate
before this reasoning had been checked).

Usage
-----
    .venv/Scripts/python.exe scripts/audit_generator_v2_validation.py
    .venv/Scripts/python.exe scripts/audit_generator_v2_validation.py \
        --json results/metrics/p2_generator_v2_validation.json
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

#: Development seed plan, reproduced verbatim from
#: scripts/audit_generator_v2_development.py -- recomputing it here
#: (deterministic given the seeds) is what AC4 needs, and keeps this script
#: independent of the gitignored Development JSON artifact.
DEV_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: (20001, 20002, 20003, 20004),
    SeverityRegime.MEDIUM: (20011, 20012, 20013),
    SeverityRegime.HIGH: (20021, 20022, 20023),
    SeverityRegime.LOW_SIGNAL: tuple(range(20031, 20041)),
}

#: Validation seed plan (design freeze SS8: 15 Main = 5 low + 5 medium +
#: 5 high, 15 Low-signal; SS12: new seeds, never used in Development).
#:
#: BURNED: 30001-30005, 30011-30015, 30021-30025, 30031-30045. That first
#: Validation attempt (against the candidate frozen in
#: docs/methodology/P2_CANDIDATE_FREEZE.md's original version) failed AC4
#: (Acc_time_validation=0.7600 > 0.75) -- per SS14 ("Validation failure:
#: record failure -> burn validation seeds -> return to Development -> new
#: candidate -> new Validation seeds"), those seeds may never be reused as
#: Validation or Final Test seeds, even though only one criterion failed.
#: Base 40000 for the new block keeps it visually disjoint from the burned
#: 30000s, Development's 20000s, and every unit-test seed (all < 1000).
VAL_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: (40001, 40002, 40003, 40004, 40005),
    SeverityRegime.MEDIUM: (40011, 40012, 40013, 40014, 40015),
    SeverityRegime.HIGH: (40021, 40022, 40023, 40024, 40025),
    SeverityRegime.LOW_SIGNAL: tuple(range(40031, 40046)),
}
BURNED_VALIDATION_SEEDS = (
    tuple(range(30001, 30006)) + tuple(range(30011, 30016))
    + tuple(range(30021, 30026)) + tuple(range(30031, 30046))
)
assert sum(len(v) for v in VAL_SEEDS.values()) == 30, "design freeze SS8: Validation total = 30"
assert not set().union(*DEV_SEEDS.values()) & set().union(*VAL_SEEDS.values()), (
    "Validation seeds must be disjoint from Development seeds (SS12)"
)
assert not set(BURNED_VALIDATION_SEEDS) & set().union(*VAL_SEEDS.values()), (
    "a burned Validation seed (SS14) was reused"
)
for _regime, _seeds in VAL_SEEDS.items():
    _expected = {SeverityRegime.LOW_SIGNAL: 15}.get(_regime, 5)
    assert len(_seeds) == _expected, f"{_regime}: expected {_expected} Validation seeds"


def simulate(seed: int, regime: SeverityRegime) -> pl.DataFrame:
    return run_simulation_v2(SimulationConfigV2(simulation_seed=seed, severity_regime=regime))


def build_run(seed: int, regime: SeverityRegime) -> dict:
    full = simulate(seed, regime)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    gen = attack_phase_labels(window_generative_stats(full, cw))
    return {"full": full, "cw": cw, "gen": gen, "regime": regime, "seed": seed}


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


def verdict(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--json", type=Path,
        default=REPO_ROOT / "results/metrics/p2_generator_v2_validation.json",
    )
    args = ap.parse_args()

    print("=" * 90)
    print("P2 VALIDATION -- official AC1-AC9/AC11/AC12 PASS/FAIL (AC10 is Final Test only)")
    print("=" * 90)

    out: dict = {
        "dev_seed_plan": {r.value: list(s) for r, s in DEV_SEEDS.items()},
        "val_seed_plan": {r.value: list(s) for r, s in VAL_SEEDS.items()},
        "tau": TAU,
    }

    # ------------------------------------------------------- AC4: Development
    print("\nBuilding Development runs (for AC4's frozen p_dev(w) rule) ...")
    dev_runs = []
    for regime, seeds in DEV_SEEDS.items():
        for seed in seeds:
            dev_runs.append(build_run(seed, regime))
    dev_gen = pl.concat([r["gen"] for r in dev_runs])
    n_windows = DURATION_SECONDS // WINDOW_SECONDS
    p_dev = np.zeros(n_windows)
    for w in range(n_windows):
        col = dev_gen.filter(pl.col("window_id") == w)["y_gt"]
        p_dev[w] = float(col.to_numpy().mean()) if len(col) else 0.0
    yhat = (p_dev >= 0.5).astype(int)
    print(f"frozen yhat(w) (from {len(dev_runs)} Development runs): "
          f"{int(yhat.sum())}/{n_windows} windows predicted attack")
    out["ac4_frozen_rule"] = {"p_dev": p_dev.tolist(), "yhat": yhat.tolist()}

    # ------------------------------------------------------------ build
    print("\nBuilding Validation runs ...")
    runs = []
    for regime, seeds in VAL_SEEDS.items():
        for seed in seeds:
            print(f"simulating regime={regime.value} seed={seed} ...")
            runs.append(build_run(seed, regime))
    print(f"\n{len(runs)} Validation runs built.")

    all_gen = pl.concat([
        r["gen"].with_columns(
            pl.lit(r["seed"]).alias("seed"),
            pl.lit(r["regime"].value).alias("severity_regime"),
            pl.lit(stratum_of(r["regime"]).value).alias("stratum"),
        )
        for r in runs
    ])

    verdicts: dict[str, str] = {}

    # ------------------------------------------------------------------- AC4
    print("\n--- AC4: temporal non-determinism, out-of-sample ---")
    val_yhat_per_row = all_gen["window_id"].to_numpy().astype(int)
    val_yhat_per_row = yhat[val_yhat_per_row]
    val_y = all_gen["y_gt"].to_numpy()
    acc_time = float((val_yhat_per_row == val_y).mean())
    majority_class = int(round(float(val_y.mean())))
    majority_acc = float((val_y == majority_class).mean())
    ac4_pass = acc_time <= 0.75
    verdicts["AC4"] = verdict(ac4_pass)
    print(f"Acc_time_validation = {acc_time:.4f} (target: <=0.75) -> {verdicts['AC4']}")
    print(f"majority-class accuracy (diagnostic only, not gating) = {majority_acc:.4f}")
    out["ac4"] = {"acc_time_validation": acc_time, "majority_class_accuracy": majority_acc,
                  "verdict": verdicts["AC4"]}

    # ------------------------------------------------------------------ AC5
    print("\n--- AC5: severity diversity ---")
    counts = (
        all_gen.group_by("seed", "severity_regime").len().group_by("severity_regime").len()
    ).to_dicts()
    _print_table("runs per severity_regime", counts, ["severity_regime", "len"])
    ac5_pass = len(counts) >= 3 and all(c["len"] >= 3 for c in counts)
    verdicts["AC5"] = verdict(ac5_pass)
    print(f"-> {verdicts['AC5']} (target: >=3 regimes with >=3 runs each)")
    out["ac5"] = {"rows": counts, "verdict": verdicts["AC5"]}

    # ----------------------------------------------------------- AC12 / C2
    print("\n--- AC12/C2: same-run positives + negatives ---")
    ac12_rows = []
    for r in runs:
        g = r["gen"]
        nb, na = int((g["y_gt"] == 0).sum()), int((g["y_gt"] == 1).sum())
        ac12_rows.append({
            "seed": r["seed"], "regime": r["regime"].value,
            "benign_windows": nb, "attack_windows": na, "both_present": nb > 0 and na > 0,
        })
    frac_both = float(np.mean([row["both_present"] for row in ac12_rows]))
    ac12_pass = frac_both == 1.0
    verdicts["AC12"] = verdict(ac12_pass)
    print(f"fraction of runs with both classes present: {frac_both:.2%} "
          f"(target: 100%) -> {verdicts['AC12']}")
    out["ac12"] = {
        "rows": ac12_rows, "fraction_both_present": frac_both, "verdict": verdicts["AC12"],
    }

    # -------------------------------------------------------------- AC3
    print("\n--- AC3: randomized onset ---")
    onset_rows = []
    for r in runs:
        g = r["gen"].sort("window_id")
        atk = g.filter(pl.col("y_gt") == 1)
        wid = int(atk["window_id"].min()) if len(atk) else None
        start_s = int(atk["window_start"].min()) if len(atk) else None
        onset_rows.append({
            "seed": r["seed"], "attack_start_window_id": wid, "attack_start_s": start_s,
        })
    starts = [row["attack_start_s"] for row in onset_rows if row["attack_start_s"] is not None]
    distinct_start_windows = len({row["attack_start_window_id"] for row in onset_rows
                                   if row["attack_start_window_id"] is not None})
    onset_fraction_range = (0.15, 0.70)
    attack_duration_lo = 300.0
    context_pre, context_post = 5, 5
    onset_lo = max(onset_fraction_range[0] * DURATION_SECONDS, context_pre * WINDOW_SECONDS)
    onset_hi = min(onset_fraction_range[1] * DURATION_SECONDS,
                    DURATION_SECONDS - context_post * WINDOW_SECONDS - attack_duration_lo)
    configured_span = onset_hi - onset_lo
    observed_span = (max(starts) - min(starts)) if len(starts) >= 2 else 0.0
    span_fraction = observed_span / configured_span if configured_span else float("nan")
    ac3_pass = distinct_start_windows >= 15 and span_fraction >= 0.30
    verdicts["AC3"] = verdict(ac3_pass)
    print(f"distinct attack_start_window_id: {distinct_start_windows}/30 (target: >=15)")
    print(f"observed onset span: {span_fraction:.1%} of configured span (target: >=30%)")
    print(f"-> {verdicts['AC3']}")
    out["ac3"] = {
        "rows": onset_rows, "distinct_attack_start_window_id": distinct_start_windows,
        "span_fraction": span_fraction, "verdict": verdicts["AC3"],
    }

    # -------------------------------------------------------------- AC6
    print("\n--- AC6: gradual transitions (ramp_seconds>0 essentially always holds; "
          "see module docstring) ---")
    ac6_rows = []
    for r in runs:
        g = r["gen"]
        intermediate = g.filter(
            (pl.col("attack_ratio_gt") > 0.02) & (pl.col("attack_ratio_gt") < 0.90)
        )
        ac6_rows.append({"seed": r["seed"], "n_intermediate": len(intermediate),
                          "has_ramp_evidence": len(intermediate) >= 2})
    ac6_fraction = float(np.mean([row["has_ramp_evidence"] for row in ac6_rows]))
    ac6_pass = ac6_fraction >= 0.50
    verdicts["AC6"] = verdict(ac6_pass)
    print(f"fraction of runs with >=2 intermediate windows: {ac6_fraction:.2%} "
          f"(target: >=50%) -> {verdicts['AC6']}")
    out["ac6"] = {"rows": ac6_rows, "fraction": ac6_fraction, "verdict": verdicts["AC6"]}

    # -------------------------------------------------------------- AC7
    print("\n--- AC7: near-tau availability (bilateral) ---")
    n_near_zero = n_near_tau = 0
    for r in runs:
        g = r["gen"]
        if len(g.filter((pl.col("attack_ratio_gt") > 0) & (pl.col("attack_ratio_gt") < TAU))):
            n_near_zero += 1
        near_tau_mask = (pl.col("attack_ratio_gt") >= TAU) & (pl.col("attack_ratio_gt") <= 5 * TAU)
        if len(g.filter(near_tau_mask)):
            n_near_tau += 1
    ac7_pass = n_near_zero >= 3 and n_near_tau >= 3
    verdicts["AC7"] = verdict(ac7_pass)
    print(f"runs with near-zero window: {n_near_zero}/30 (target >=3)")
    print(f"runs with near-tau window: {n_near_tau}/30 (target >=3)")
    print(f"-> {verdicts['AC7']}")
    out["ac7"] = {"n_near_zero": n_near_zero, "n_near_tau": n_near_tau, "verdict": verdicts["AC7"]}

    # -------------------------------------------------------------- AC8/AC9
    print("\n--- AC8/AC9: background structure ---")
    bg_rows = []
    for r in runs:
        bg = background_flow_stats(r["full"])
        pair_coverage = (
            bg["n_unique_pairs"] / bg["n_possible_ordered_pairs"]
            if bg.get("n_possible_ordered_pairs") else float("nan")
        )
        benign_recip = r["gen"].filter(pl.col("y_gt") == 0)["reciprocity"].to_numpy()
        bg_rows.append({
            "seed": r["seed"], "pair_coverage_run": round(pair_coverage, 4),
            "std_recip_run": (
                round(float(benign_recip.std()), 4) if benign_recip.size else float("nan")
            ),
        })
    coverages = np.array([row["pair_coverage_run"] for row in bg_rows])
    stds = np.array([row["std_recip_run"] for row in bg_rows])
    ac8_pass = bool(np.median(coverages) < 0.50 and (coverages < 0.50).mean() >= 0.80)
    verdicts["AC8"] = verdict(ac8_pass)
    print(f"AC8 median pair_coverage_run={np.median(coverages):.3f} (target <0.50), "
          f"fraction<0.50={(coverages < 0.50).mean():.2%} (target >=80%) -> {verdicts['AC8']}")
    low_recip_services = [
        s.value for s, p in DEFAULT_SERVICES.items() if p.response_probability < 0.5
    ]
    ac9_pass = bool(
        np.median(stds) > 0.05 and (stds > 0.02).mean() >= 0.70 and len(low_recip_services) >= 2
    )
    verdicts["AC9"] = verdict(ac9_pass)
    print(f"AC9 median std_recip_run={np.median(stds):.3f} (target >0.05), "
          f"fraction>0.02={(stds > 0.02).mean():.2%} (target >=70%), "
          f"low-reciprocity services={low_recip_services} (target >=2) -> {verdicts['AC9']}")
    out["ac8_ac9"] = {
        "rows": bg_rows, "ac8_median": float(np.median(coverages)),
        "ac8_fraction_below_0.5": float((coverages < 0.50).mean()),
        "ac8_verdict": verdicts["AC8"],
        "ac9_median": float(np.median(stds)),
        "ac9_fraction_above_0.02": float((stds > 0.02).mean()),
        "ac9_low_reciprocity_services": low_recip_services, "ac9_verdict": verdicts["AC9"],
    }

    # -------------------------------------------------------------- AC1/AC2
    print("\n--- AC1/AC2: node-count / volume overlap + per-run separability ---")
    n_nodes = all_gen["n_nodes"].to_numpy().astype(float)
    n_flows = all_gen["n_flows"].to_numpy().astype(float)
    y = all_gen["y_gt"].to_numpy()
    ovl_nodes = overlap_coefficient(n_nodes[y == 0], n_nodes[y == 1])
    ovl_flows = overlap_coefficient(n_flows[y == 0], n_flows[y == 1])
    ac1a_pass, ac2a_pass = ovl_nodes >= 0.30, ovl_flows >= 0.20
    print(f"AC1a pooled OVL(n_nodes) = {ovl_nodes:.4f} (target >=0.30) -> {verdict(ac1a_pass)}")
    print(f"AC2a pooled OVL(n_flows) = {ovl_flows:.4f} (target >=0.20) -> {verdict(ac2a_pass)}")

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
    frac_sep_nodes = float(np.mean([row["sep_run_n_nodes"] >= 0.95 for row in sep_rows]))
    eligible = [row for row in sep_rows if row["regime"] in ("low", "low_signal")]
    frac_sep_flows_eligible = (
        float(np.mean([row["sep_run_n_flows"] >= 0.95 for row in eligible]))
        if eligible else float("nan")
    )
    ac1b_pass = frac_sep_nodes <= 0.20
    ac2b_pass = frac_sep_flows_eligible <= 0.20
    verdicts["AC1"] = verdict(ac1a_pass and ac1b_pass)
    verdicts["AC2"] = verdict(ac2a_pass and ac2b_pass)
    print(f"AC1b fraction sep_run(n_nodes)>=0.95: {frac_sep_nodes:.2%} "
          f"(target <=20%) -> {verdict(ac1b_pass)}")
    print(f"AC2b fraction eligible sep_run(n_flows)>=0.95: {frac_sep_flows_eligible:.2%} "
          f"(target <=20%, n_eligible={len(eligible)}) -> {verdict(ac2b_pass)}")
    print(f"AC1 overall -> {verdicts['AC1']}   AC2 overall -> {verdicts['AC2']}")
    out["ac1_ac2"] = {
        "ovl_n_nodes": ovl_nodes, "ovl_n_flows": ovl_flows, "sep_run_rows": sep_rows,
        "ac1a_verdict": verdict(ac1a_pass), "ac1b_verdict": verdict(ac1b_pass),
        "ac1_verdict": verdicts["AC1"],
        "ac2a_verdict": verdict(ac2a_pass), "ac2b_verdict": verdict(ac2b_pass),
        "ac2_verdict": verdicts["AC2"],
    }

    # -------------------------------------------------------------- AC11
    print("\n--- AC11a/b: Low-signal reproducibility + validity ---")
    seed0 = VAL_SEEDS[SeverityRegime.LOW_SIGNAL][0]
    a = simulate(seed0, SeverityRegime.LOW_SIGNAL)
    b = simulate(seed0, SeverityRegime.LOW_SIGNAL)
    ac11a_pass = a.equals(b)
    print(f"AC11a: seed={seed0} identical trace on repeat = {ac11a_pass} -> {verdict(ac11a_pass)}")

    ls_gen = all_gen.filter(pl.col("stratum") == Stratum.LOW_SIGNAL.value)
    main_gen = all_gen.filter(pl.col("stratum") == Stratum.MAIN.value)
    ls_pos = ls_gen.filter(pl.col("y_gt") == 1)["attack_ratio_gt"].to_numpy()
    main_pos = main_gen.filter(pl.col("y_gt") == 1)["attack_ratio_gt"].to_numpy()
    ls_median = float(np.median(ls_pos)) if ls_pos.size else float("nan")
    main_q1 = float(np.percentile(main_pos, 25)) if main_pos.size else float("nan")
    ls_both_classes = (
        ls_gen.group_by("seed").agg(
            (pl.col("y_gt") == 0).sum().alias("nb"), (pl.col("y_gt") == 1).sum().alias("na")
        )
    )
    ls_all_have_both = bool(((ls_both_classes["nb"] > 0) & (ls_both_classes["na"] > 0)).all())
    ac11b_cond2 = ls_median < main_q1
    ac11b_pass = ls_all_have_both and ac11b_cond2
    verdicts["AC11"] = verdict(ac11a_pass and ac11b_pass)
    print(f"AC11b.1 all Low-signal runs have both classes: {ls_all_have_both}")
    print(f"AC11b.2 median(LS)={ls_median:.4f} < Q1(Main)={main_q1:.4f}: {ac11b_cond2}")
    print(f"AC11 overall -> {verdicts['AC11']}")
    out["ac11"] = {
        "ac11a_verdict": verdict(ac11a_pass), "ls_all_have_both_classes": ls_all_have_both,
        "ls_median_positive_ratio": ls_median, "main_q1_positive_ratio": main_q1,
        "ac11b_verdict": verdict(ac11b_pass), "ac11_verdict": verdicts["AC11"],
    }

    # -------------------------------------------------------------- summary
    print("\n" + "=" * 90)
    print("VALIDATION SUMMARY")
    print("=" * 90)
    for name in ("AC1", "AC2", "AC3", "AC4", "AC5", "AC6", "AC7", "AC8", "AC9", "AC11", "AC12"):
        print(f"  {name}: {verdicts[name]}")
    all_pass = all(v == "PASS" for v in verdicts.values())
    print(f"\nOverall: {'ALL PASS' if all_pass else 'AT LEAST ONE FAIL'}")
    out["verdicts"] = verdicts
    out["overall"] = "ALL PASS" if all_pass else "AT LEAST ONE FAIL"

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nJSON written to {args.json}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
