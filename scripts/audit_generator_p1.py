#!/usr/bin/env python3
"""P1 -- Current Generator Audit. Read-only. Does not modify the generator.

Answers: what properties of the current simulator (src.simulator.agents) let
benign traffic be told apart from DDoS without relying on the asymmetry
representation this project studies? Runs entirely on the canonical window
grid frozen by P0.5 (src.audit.canonical) at sampling rate 1:1 -- P0.5's
no-evidence handling under restriction is out of scope here by design (see
P1.16 in the accompanying report).

Nothing in this script changes SimulationConfig, the restriction operators,
the detector features, or the model. It only simulates with the project's
existing simulator, builds canonical windows/ground truth, and measures.

Usage
-----
    python scripts/audit_generator_p1.py
    python scripts/audit_generator_p1.py --json results/metrics/p1_generator_audit.json
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

from src.audit.canonical import (  # noqa: E402
    build_canonical_windowing,
    canonical_window_features,
)
from src.audit.generator_audit import (  # noqa: E402
    attack_phase_labels,
    background_flow_stats,
    window_generative_stats,
)
from src.features import InfoTier  # noqa: E402
from src.features.extractors import PERFLOW_FEATURES, SIZE_FEATURES  # noqa: E402
from src.restriction import sample  # noqa: E402
from src.simulator.agents import AttackType, SimulationConfig, run_simulation  # noqa: E402

TRAIN_SEEDS = (1, 2)
TEST_SEED = 11
ALL_SEEDS = (1, 2, 11)
GEN_VARS = (
    "n_flows", "total_bytes", "fwd_bytes", "bwd_bytes", "total_pkts",
    "n_nodes", "n_edges", "n_src_nodes", "n_dst_nodes", "unique_peers",
    "mean_peers_per_src", "mean_peers_per_dst", "fan_out_max", "fan_in_max",
    "reciprocity", "flows_per_edge", "attack_ratio_gt",
)


def simulate(seed: int, duration: int, attack_type: AttackType) -> pl.DataFrame:
    return run_simulation(SimulationConfig(
        attack_type=attack_type, asymmetry_level=0.8,
        duration_seconds=duration, seed=seed,
    ))


def _arm_auc(train: pl.DataFrame, test: pl.DataFrame, cols: list[str]) -> float:
    """Exact mirror of experiments/04_restriction.py::_arm_auc, sourced from
    the canonical ledger's y_gt instead of the pre-P0.5 window_features' y."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score

    cols = [c for c in cols if c in train.columns]
    ytr, yte = train["y_gt"].to_numpy(), test["y_gt"].to_numpy()
    if len(set(ytr)) < 2 or len(set(yte)) < 2:
        return float("nan")
    model = RandomForestClassifier(
        n_estimators=300, random_state=0, class_weight="balanced"
    ).fit(train[cols].to_numpy(), ytr)
    return float(roc_auc_score(yte, model.predict_proba(test[cols].to_numpy())[:, 1]))


def build_run(seed: int, duration: int, window_seconds: int, tau: float,
              min_flows: int, attack_type: AttackType) -> dict:
    full = simulate(seed, duration, attack_type)
    cw = build_canonical_windowing(full, window_seconds=window_seconds, tau=tau)
    gen = window_generative_stats(full, cw)
    gen = attack_phase_labels(gen)
    feat = canonical_window_features(
        sample(full, rate=1, seed=0), cw, tier=InfoTier.DIRECTIONAL, min_flows=min_flows,
    )
    return {"full": full, "cw": cw, "gen": gen, "feat": feat}


def _desc(a: np.ndarray) -> dict:
    if a.size == 0:
        return {k: float("nan") for k in
                ("n", "mean", "std", "median", "p10", "p25", "p75", "p90", "min", "max")}
    return {
        "n": int(a.size), "mean": float(a.mean()), "std": float(a.std()),
        "median": float(np.median(a)), "p10": float(np.percentile(a, 10)),
        "p25": float(np.percentile(a, 25)), "p75": float(np.percentile(a, 75)),
        "p90": float(np.percentile(a, 90)), "min": float(a.min()), "max": float(a.max()),
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


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--duration", type=int, default=2400)
    ap.add_argument("--window-seconds", type=int, default=60)
    ap.add_argument("--tau", type=float, default=0.01)
    ap.add_argument("--min-flows", type=int, default=10)
    ap.add_argument("--json", type=Path,
                    default=REPO_ROOT / "results/metrics/p1_generator_audit.json")
    args = ap.parse_args()
    cfg = dict(duration=args.duration, window_seconds=args.window_seconds,
               tau=args.tau, min_flows=args.min_flows)

    print("=" * 90)
    print("P1 -- CURRENT GENERATOR AUDIT (read-only, canonical instrument, rate 1:1)")
    print("=" * 90)
    print(f"config: {cfg}")
    print(f"simulation seeds: TRAIN={TRAIN_SEEDS} TEST={TEST_SEED} "
          f"(identical to P0/P0.5, no new seeds for the main DDoS analysis)")

    out: dict = {"config": cfg, "seeds": {"train": TRAIN_SEEDS, "test": TEST_SEED}}

    # ---------------------------------------------------------- P1.1 / build
    runs = {s: build_run(s, args.duration, args.window_seconds, args.tau,
                          args.min_flows, AttackType.DDOS) for s in ALL_SEEDS}

    # -------------------------------------------------------------- P1.6/D
    print("\n--- P1.6 / D -- counts per seed, same-run check ---")
    d_rows = []
    for s in ALL_SEEDS:
        gen = runs[s]["gen"]
        nb, na = int((gen["y_gt"] == 0).sum()), int((gen["y_gt"] == 1).sum())
        d_rows.append({"seed": s, "total_windows": len(gen), "benign": nb,
                        "attack": na, "same_run": True})
    _print_table("D -- counts per seed", d_rows,
                 ["seed", "total_windows", "benign", "attack", "same_run"])
    out["counts_per_seed"] = d_rows

    # -------------------------------------------------------- temporal shortcut
    seqs = {s: runs[s]["gen"].sort("window_id")["y_gt"].to_list() for s in ALL_SEEDS}
    identical_across_seeds = len({tuple(v) for v in seqs.values()}) == 1
    print(f"\ny_gt(window_id) sequence identical across seeds {ALL_SEEDS}: "
          f"{identical_across_seeds}")
    out["temporal_shortcut"] = {
        "y_gt_sequence_identical_across_seeds": identical_across_seeds,
        "sequences": {str(s): v for s, v in seqs.items()},
    }

    # ------------------------------------------------------------- P1.7 / K
    print("\n--- P1.7 / K -- attack schedule (measured, per seed) ---")
    k_rows = []
    for s in ALL_SEEDS:
        gen = runs[s]["gen"].sort("window_id")
        atk = gen.filter(pl.col("y_gt") == 1)
        n_pre = int((gen["window_id"] < atk["window_id"].min()).sum()) if len(atk) else len(gen)
        n_post = int((gen["window_id"] > atk["window_id"].max()).sum()) if len(atk) else 0
        k_rows.append({
            "seed": s,
            "attack_start_s": int(atk["window_start"].min()) if len(atk) else None,
            "attack_end_s": int(atk["window_end"].max()) if len(atk) else None,
            "pre_attack_windows": n_pre, "attack_windows": len(atk), "post_attack_windows": n_post,
        })
    _print_table("K -- attack schedule per seed", k_rows,
                 ["seed", "attack_start_s", "attack_end_s",
                  "pre_attack_windows", "attack_windows", "post_attack_windows"])
    out["attack_schedule"] = k_rows

    # ---------------------------------------------------------- P1.9 gradual?
    print("\n--- P1.9 -- boundary ramp (seed 11, attack_ratio_gt around the transition) ---")
    gen11 = runs[TEST_SEED]["gen"].sort("window_id")
    attack_ids = gen11.filter(pl.col("y_gt") == 1)["window_id"]
    lo, hi = int(attack_ids.min()), int(attack_ids.max())
    ramp = gen11.filter(
        (pl.col("window_id") >= lo - 2) & (pl.col("window_id") <= lo + 2)
    ).select(["window_id", "n_flows", "attack_ratio_gt", "y_gt"])
    ramp_rows = ramp.to_dicts()
    _print_table("boundary ramp (rising edge, seed 11)", ramp_rows,
                 ["window_id", "n_flows", "attack_ratio_gt", "y_gt"])
    fall_rows = gen11.filter(
        (pl.col("window_id") >= hi - 2) & (pl.col("window_id") <= hi + 2)
    ).select(["window_id", "n_flows", "attack_ratio_gt", "y_gt"]).to_dicts()
    _print_table("boundary ramp (falling edge, seed 11)", fall_rows,
                 ["window_id", "n_flows", "attack_ratio_gt", "y_gt"])
    intermediate = gen11.filter(
        (pl.col("attack_ratio_gt") > 0.02) & (pl.col("attack_ratio_gt") < 0.90)
    )
    gradual = len(intermediate) >= 2  # >=2 windows strictly between near-zero and saturated
    out["gradual_attack"] = {
        "boundary_ramp_rising_seed11": ramp_rows,
        "boundary_ramp_falling_seed11": fall_rows,
        "n_windows_with_intermediate_ratio": len(intermediate),
        "verdict": "PASS" if gradual else "FAIL",
    }
    print(f"windows with attack_ratio_gt strictly in (0.02, 0.90): {len(intermediate)} "
          f"-> {'PASS' if gradual else 'FAIL'} (gradual)")

    # ------------------------------------------------------------- P1.8 / J
    print("\n--- P1.8 / J -- attack_ratio_gt distribution (all seeds, positive windows) ---")
    all_gen = pl.concat([runs[s]["gen"].with_columns(pl.lit(s).alias("seed")) for s in ALL_SEEDS])
    pos = all_gen.filter(pl.col("y_gt") == 1)["attack_ratio_gt"].to_numpy()
    ratio_desc = _desc(pos)
    print(f"attack_ratio_gt | positive windows: {ratio_desc}")
    bins = [(0, 0.01), (0.01, 0.05), (0.05, 0.10), (0.10, 0.25), (0.25, 0.50),
            (0.50, 0.75), (0.75, 0.90), (0.90, 1.0001)]
    j_rows = []
    for lo_b, hi_b in bins:
        n = int(((all_gen["attack_ratio_gt"] >= lo_b) & (all_gen["attack_ratio_gt"] < hi_b)).sum())
        label = f"[{lo_b},{hi_b if hi_b != 1.0001 else 1.0}{')' if hi_b != 1.0001 else ']'}"
        j_rows.append({"range": label, "windows": n})
    _print_table("J -- attack_ratio_gt buckets (all windows, all seeds)", j_rows,
                 ["range", "windows"])
    out["attack_ratio_distribution"] = {"positive_windows_stats": ratio_desc, "buckets": j_rows}

    # -------------------------------------------------------------- P1.2 / E
    print("\n--- P1.2 / E -- distributions by class (all windows, all seeds) ---")
    e_rows = []
    for var in GEN_VARS:
        for cls, y in (("benign", 0), ("attack", 1)):
            vals = all_gen.filter(pl.col("y_gt") == y)[var].to_numpy().astype(float)
            d = _desc(vals)
            e_rows.append({"variable": var, "class": cls, **d})
    _print_table("E -- distributions by class",
                 [{k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()}
                  for r in e_rows],
                 ["variable", "class", "n", "mean", "std", "median",
                  "p10", "p25", "p75", "p90", "min", "max"])
    out["distributions_by_class"] = e_rows

    # -------------------------------------------------------------- P1.13 / F
    print("\n--- P1.13 / F -- ratio attack/benign (median), all windows all seeds ---")
    f_vars = ["n_flows", "n_nodes", "n_edges", "total_bytes", "unique_peers",
              "fan_in_max", "fan_out_max"]
    f_rows = []
    for var in f_vars:
        mb = float(np.median(all_gen.filter(pl.col("y_gt") == 0)[var].to_numpy()))
        ma = float(np.median(all_gen.filter(pl.col("y_gt") == 1)[var].to_numpy()))
        f_rows.append({"variable": var, "median_benign": round(mb, 3),
                       "median_attack": round(ma, 3),
                       "ratio_attack_over_benign": round(ma / mb, 3) if mb else float("inf")})
    _print_table("F -- attack/benign ratios", f_rows,
                 ["variable", "median_benign", "median_attack", "ratio_attack_over_benign"])
    out["density_ratios"] = f_rows

    # -------------------------------------------------------------- P1.3 / G
    print("\n--- P1.3 / G -- per-seed medians (not pooled) ---")
    g_rows = []
    for s in ALL_SEEDS:
        gen = runs[s]["gen"]
        b, a = gen.filter(pl.col("y_gt") == 0), gen.filter(pl.col("y_gt") == 1)
        row = {"seed": s}
        for var in ("n_flows", "n_edges"):
            mb = float(np.median(b[var].to_numpy())) if len(b) else float("nan")
            ma = float(np.median(a[var].to_numpy())) if len(a) else float("nan")
            row[f"median_benign_{var}"] = round(mb, 2)
            row[f"median_attack_{var}"] = round(ma, 2)
            row[f"ratio_{var}"] = round(ma / mb, 2) if mb else float("nan")
        g_rows.append(row)
    _print_table("G -- per-seed medians", g_rows,
                 ["seed", "median_benign_n_flows", "median_attack_n_flows", "ratio_n_flows",
                  "median_benign_n_edges", "median_attack_n_edges", "ratio_n_edges"])
    out["per_seed_medians"] = g_rows

    # -------------------------------------------------------------- P1.4 / H
    print("\n--- P1.4 / H -- C1 size-only control ---")
    train_feat = pl.concat([runs[s]["feat"] for s in TRAIN_SEEDS])
    test_feat = runs[TEST_SEED]["feat"]
    c1_auc = _arm_auc(train_feat, test_feat, list(SIZE_FEATURES))
    print(f"C1 size-only: features={SIZE_FEATURES} train_seeds={TRAIN_SEEDS} "
          f"test_seed={TEST_SEED} AUC={c1_auc:.4f}")
    # leave-one-seed-out sensitivity (diagnostic addition, not the historical protocol)
    c1_loso = []
    for held_out in ALL_SEEDS:
        tr_seeds = [s for s in ALL_SEEDS if s != held_out]
        tr = pl.concat([runs[s]["feat"] for s in tr_seeds])
        te = runs[held_out]["feat"]
        auc = _arm_auc(tr, te, list(SIZE_FEATURES))
        c1_loso.append({"held_out_as_test": held_out, "train_seeds": tr_seeds,
                        "AUC": round(auc, 4)})
    _print_table("C1 leave-one-seed-out (diagnostic, not the historical protocol)",
                 c1_loso, ["held_out_as_test", "train_seeds", "AUC"])
    out["c1_size_only"] = {
        "features": list(SIZE_FEATURES), "model": "RandomForest(n_estimators=300, "
        "random_state=0, class_weight='balanced')", "train_seeds": TRAIN_SEEDS,
        "test_seed": TEST_SEED, "AUC": c1_auc, "leave_one_seed_out": c1_loso,
    }

    # -------------------------------------------------------------- P1.5 / I
    print("\n--- P1.5 / I -- Flow baseline (1:1) ---")
    flow_auc = _arm_auc(train_feat, test_feat, list(PERFLOW_FEATURES))
    flow_gate = "PASS" if (np.isfinite(flow_auc) and flow_auc <= 0.90) else "FAIL"
    print(f"Flow baseline: features={PERFLOW_FEATURES} train_seeds={TRAIN_SEEDS} "
          f"test_seed={TEST_SEED} AUC={flow_auc:.4f} -> Phase0 <=0.90: {flow_gate}")
    out["flow_baseline"] = {
        "features": list(PERFLOW_FEATURES), "train_seeds": TRAIN_SEEDS,
        "test_seed": TEST_SEED, "AUC": flow_auc, "phase0_le_0.90": flow_gate,
    }

    # -------------------------------------------------------------- P1.12 / M
    print("\n--- P1.12 / M -- background audit (benign flows, DDoS-run traces) ---")
    bg = {s: background_flow_stats(runs[s]["full"]) for s in ALL_SEEDS}
    print(json.dumps(bg[TEST_SEED], indent=2))
    out["background_audit"] = bg

    # -------------------------------------------------------------- P1.10 stealth
    print("\n--- P1.10 -- stealth stratum attempt (Infiltration, current instrument) ---")
    inf_runs = {s: build_run(s, args.duration, args.window_seconds, args.tau,
                              args.min_flows, AttackType.INFILTRATION) for s in ALL_SEEDS}
    inf_train_feat = pl.concat([inf_runs[s]["feat"] for s in TRAIN_SEEDS])
    inf_test_feat = inf_runs[TEST_SEED]["feat"]
    inf_counts = {s: {"benign": int((inf_runs[s]["gen"]["y_gt"] == 0).sum()),
                       "attack": int((inf_runs[s]["gen"]["y_gt"] == 1).sum())}
                  for s in ALL_SEEDS}
    inf_flow_auc = _arm_auc(inf_train_feat, inf_test_feat, list(PERFLOW_FEATURES))
    inf_c1_auc = _arm_auc(inf_train_feat, inf_test_feat, list(SIZE_FEATURES))
    print(f"Infiltration counts per seed: {inf_counts}")
    print(f"Infiltration Flow-baseline AUC (attempted repro): {inf_flow_auc}")
    print(f"Infiltration C1 size-only AUC (attempted repro): {inf_c1_auc}")
    out["stealth_stratum_attempt"] = {
        "attack_type": "INFILTRATION", "counts_per_seed": inf_counts,
        "flow_baseline_AUC": inf_flow_auc, "c1_size_only_AUC": inf_c1_auc,
        "note": "attempted reproduction with current canonical instrument and the "
                "project's standard seeds/duration -- NOT the original run, whose "
                "code was never committed and predates src.audit.canonical.",
    }

    # -------------------------------------------------------------- write JSON
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nJSON written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
