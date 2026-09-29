#!/usr/bin/env python3
"""Post-hoc dependence sensitivity: cluster bootstrap over host-pair instead
of over individual flows, for H3's confirmatory result on UNSW-NB15 and
BoT-IoT. NOT a new confirmatory test -- it reports whether the orientation
conclusion in results/{unsw,botiot}/asymmetry_by_attack.csv survives
resampling at the host-pair level instead of the flow level. See
docs/methodology/PROVENANCE.md and docs/ESTADO-ACTUAL.md.

Per scripts/dependence_cluster_inventory.py, both testbeds run attacks from
a handful of dedicated machines: UNSW attack families sit on 25-40
host-pairs, BoT-IoT attack groups on 4-32. Groups with fewer than
MIN_CLUSTERS (10) host-pairs are NOT bootstrapped -- a resample of that few
items is not a meaningful confidence interval, and reporting one would
manufacture false precision. Their row in the output states n_clusters and
"not computed", nothing else.

    python scripts/dependence_cluster_bootstrap.py --dataset unsw   --data-dir "<unsw dir>"
    python scripts/dependence_cluster_bootstrap.py --dataset botiot --data-dir "<botiot dir>"

Reuses auc_lookup/orientation/confident/B/SEED/NEUTRAL UNCHANGED from
scripts/run_unsw_external_validation.py (same pattern scripts/run_botiot_h3.py
uses). Only the resampling unit changes: cluster (host-pair) instead of row.
AUC is still the count-weighted Mann-Whitney form; a cluster draw becomes a
per-row *weight* (how many times that row's cluster was drawn) instead of an
in/out row selection, which is the direct generalization of the existing
count-based engine to a weighted resample.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingest.bot_iot import GROUPS as BOTIOT_GROUPS  # noqa: E402
from src.ingest.bot_iot import load_botiot  # noqa: E402
from src.ingest.unsw_nb15 import CATEGORIES as UNSW_CATEGORIES  # noqa: E402
from src.ingest.unsw_nb15 import load_unsw  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "unsw_run", ROOT / "scripts" / "run_unsw_external_validation.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

MIN_CLUSTERS = 10
OUT = ROOT / "results" / "dependence"


def weighted_auc(benign_weight: np.ndarray, benign_codes: np.ndarray,
                  attack_weight: np.ndarray, attack_codes: np.ndarray,
                  n_values: int) -> float:
    """Generalizes run.auc_from_codes(run.auc_lookup(...)) to weighted rows.
    weight=1 for every row reduces exactly to the unweighted formula."""
    bc = np.bincount(benign_codes, weights=benign_weight, minlength=n_values)
    lookup = run.auc_lookup(bc)
    n_b_eff = bc.sum()
    numerator = (lookup[attack_codes] * attack_weight).sum()
    return float(numerator / (attack_weight.sum() * n_b_eff))


def cluster_ids(df: pl.DataFrame) -> np.ndarray:
    """Dense 0..K-1 host-pair id within this frame alone."""
    return (
        df.select(pl.struct(["src_ip", "dst_ip"]).rank("dense").alias("c"))["c"]
        .to_numpy().astype(np.int64) - 1
    )


def group_arrays(benign: pl.DataFrame, attack: pl.DataFrame):
    """A_bytes value-codes shared across benign+attack, plus each side's
    cluster ids. Mirrors run.analyze's per-group code computation, A_bytes
    only (the primary, orientation-bearing feature)."""
    def a_bytes(d: pl.DataFrame) -> np.ndarray:
        fb = np.log1p(d["fwd_bytes"].to_numpy().astype(np.float64))
        bb = np.log1p(d["bwd_bytes"].to_numpy().astype(np.float64))
        return fb - bb

    x_b, x_a = a_bytes(benign), a_bytes(attack)
    values, inv = np.unique(np.concatenate([x_b, x_a]), return_inverse=True)
    codes_b, codes_a = inv[: len(x_b)], inv[len(x_b):]
    return codes_b, codes_a, len(values), cluster_ids(benign), cluster_ids(attack)


def cluster_bootstrap_ci(codes_b, codes_a, n_values, cid_b, cid_a,
                          rng: np.random.Generator) -> tuple[float, float]:
    k_b, k_a = cid_b.max() + 1, cid_a.max() + 1
    draws = np.empty(run.B)
    for b in range(run.B):
        wb = np.bincount(rng.integers(0, k_b, k_b), minlength=k_b)[cid_b]
        wa = np.bincount(rng.integers(0, k_a, k_a), minlength=k_a)[cid_a]
        draws[b] = weighted_auc(wb.astype(np.float64), codes_b,
                                 wa.astype(np.float64), codes_a, n_values)
    lo, hi = np.percentile(draws, [2.5, 97.5])
    return float(lo), float(hi)


def run_dataset(name: str, benign: pl.DataFrame, groups: dict[str, pl.DataFrame],
                 flow_table: pl.DataFrame, rng: np.random.Generator) -> list[dict]:
    rows = []
    for g, sub in groups.items():
        ref = flow_table.filter(
            (pl.col("category") == g) & (pl.col("feature") == "A_bytes")
            & (pl.col("population") == "primary_all_rows"))
        if ref.height == 0:
            continue
        ref = ref.row(0, named=True)
        k_a = sub.select(pl.struct(["src_ip", "dst_ip"]).n_unique()).item()
        k_b = benign.select(pl.struct(["src_ip", "dst_ip"]).n_unique()).item()
        row = {
            "dataset": name, "group": g, "n_rows_attack": sub.height,
            "n_clusters_attack": k_a, "n_clusters_benign": k_b,
            "flow_auc_signed": ref["auc_signed"],
            "flow_ci_lo": ref["ci_lo"], "flow_ci_hi": ref["ci_hi"],
            "flow_orientation": ref["orientation"],
        }
        if k_a < MIN_CLUSTERS:
            row |= {"cluster_ci_lo": None, "cluster_ci_hi": None,
                    "cluster_orientation": None, "orientation_changed": None,
                    "note": f"not computed: only {k_a} host-pairs (< {MIN_CLUSTERS})"}
            rows.append(row)
            continue
        t0 = time.time()
        codes_b, codes_a, n_values, cid_b, cid_a = group_arrays(benign, sub)
        clo, chi = cluster_bootstrap_ci(codes_b, codes_a, n_values, cid_b, cid_a, rng)
        c_orient = run.orientation(ref["auc_signed"])
        c_confident = run.confident(ref["auc_signed"], clo, chi)
        row |= {
            "cluster_ci_lo": clo, "cluster_ci_hi": chi,
            "cluster_orientation": c_orient if c_confident else "near-neutral or not confident",
            "orientation_changed": (c_orient if c_confident else None) != ref["orientation"],
            "note": "",
        }
        print(f"[{time.strftime('%H:%M:%S')}] {name}/{g}: flow CI [{ref['ci_lo']:.3f},"
              f" {ref['ci_hi']:.3f}] -> cluster CI [{clo:.3f}, {chi:.3f}]"
              f" ({k_a} clusters, {time.time() - t0:.0f}s)")
        rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["unsw", "botiot"], required=True)
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()
    rng = np.random.default_rng(run.SEED)

    if args.dataset == "unsw":
        df = load_unsw(args.data_dir, dedup=False)
        benign = df.filter(pl.col("label") == 0)
        groups = {c: df.filter(pl.col("attack_category") == c) for c in UNSW_CATEGORIES}
        flow_table = pl.read_csv(ROOT / "results" / "unsw" / "asymmetry_by_attack.csv")
    else:
        df = load_botiot(args.data_dir)
        benign = df.filter(pl.col("label") == 0)
        groups = {g: df.filter(pl.col("attack_category") == g) for g in BOTIOT_GROUPS}
        flow_table = pl.read_csv(ROOT / "results" / "botiot" / "asymmetry_by_attack.csv")

    rows = run_dataset(args.dataset, benign, groups, flow_table, rng)
    OUT.mkdir(parents=True, exist_ok=True)
    out_path = OUT / f"cluster_bootstrap_{args.dataset}.csv"
    pl.DataFrame(rows).write_csv(out_path)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
