#!/usr/bin/env python3
"""A1 follow-up diagnostic: why do host-pair and time-block bootstraps
disagree for 5 of 8 verifiable BoT-IoT groups?

Measures, from real data:
  1. How concentrated the shared benign reference is by host-pair (top-1 and
     top-5 pair share of benign rows; the benign population is shared by all
     groups, so this is one number, repeated per row for convenience).
  2. How extreme the dominant benign pair is relative to each attack group:
     the fraction of that group's attack rows whose A_bytes lies below the
     pair's median A_bytes (0 = the pair sits below every attack row), plus
     the AUC against that pair alone and against benign with that pair
     removed.
  3. Side-isolated host-pair bootstraps: benign pairs resampled with attack
     rows fixed (each counted once), and attack pairs resampled with benign
     rows fixed. If the benign-only CI reproduces the committed host-pair CI
     in comparison.csv, the host-pair width comes from the benign reference.

POST-HOC ROBUSTNESS ANALYSIS. Diagnostic only: reads comparison.csv, writes
only results/audit/a1_bot_dependence/benign_concentration.csv. B, SEED and
MIN_CLUSTERS are imported unchanged; each side-isolated bootstrap gets its
own np.random.default_rng(SEED) per group.

    python scripts/audit_a1_benign_concentration.py --data-dir "<botiot dir>"
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

from src.ingest.bot_iot import GROUPS, load_botiot  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "a1", ROOT / "scripts" / "audit_a1_bot_dependence.py")
a1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a1)
dep, run = a1.dep, a1.run

OUT = ROOT / "results" / "audit" / "a1_bot_dependence" / "benign_concentration.csv"


def top_shares(cid: np.ndarray, k: int = 5) -> tuple[float, float]:
    """Share of rows held by the largest cluster, and by the k largest."""
    n = np.sort(np.bincount(cid))[::-1]
    return float(n[0] / n.sum()), float(n[:k].sum() / n.sum())


def collapse(codes: np.ndarray, cid: np.ndarray, n_values: int):
    """Aggregate rows to unique (cluster, code) cells: returns cell codes,
    cell cluster ids and cell counts. A per-cluster weight w applied to
    cell counts gives the same weighted AUC as w applied to every row."""
    key = cid.astype(np.int64) * n_values + codes
    uniq, cnt = np.unique(key, return_counts=True)
    return uniq % n_values, uniq // n_values, cnt.astype(np.float64)


def side_bootstrap_ci(codes_b, w_b, cid_b, codes_a, w_a, cid_a, n_values,
                      resample: str, rng: np.random.Generator) -> tuple[float, float]:
    """Resample clusters on ONE side only ('benign' or 'attack'); the other
    side keeps its fixed weights. Rows may be pre-collapsed cells (w = counts)."""
    cid, base = (cid_b, w_b) if resample == "benign" else (cid_a, w_a)
    k = int(cid.max()) + 1
    draws = np.empty(run.B)
    for b in range(run.B):
        w = np.bincount(rng.integers(0, k, k), minlength=k)[cid] * base
        wb, wa = (w, w_a) if resample == "benign" else (w_b, w)
        draws[b] = dep.weighted_auc(wb, codes_b, wa, codes_a, n_values)
    lo, hi = np.percentile(draws, [2.5, 97.5])
    return float(lo), float(hi)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()

    df = load_botiot(args.data_dir)
    benign = df.filter(pl.col("label") == 0)
    comp = pl.read_csv(ROOT / "results" / "audit" / "a1_bot_dependence" / "comparison.csv")

    cid_b_rows, k_b = a1.dense(a1.pair_ids(benign))
    top1, top5 = top_shares(cid_b_rows)
    sizes = np.bincount(cid_b_rows)
    dom = int(np.argmax(sizes))
    dom_row = benign.filter(pl.Series(cid_b_rows == dom)).row(0, named=True)
    x_b = a1.a_bytes(benign)
    x_dom = x_b[cid_b_rows == dom]
    in_dom = cid_b_rows == dom
    # How much does the dominant pair's share of the benign reference vary
    # under each resampling unit? Host-pair: it is either drawn (m times) or
    # not. 60s time-block: its rows are spread over many blocks.
    cid_b_t60, k_b_t60 = a1.dense(a1.timeblock_ids(benign, 60))
    n_blocks_with_dom = len(np.unique(cid_b_t60[in_dom]))
    share_sd = {}
    units = {"hostpair": (cid_b_rows, k_b), "timeblock_60s": (cid_b_t60, k_b_t60)}
    for unit, (cid, k) in units.items():
        rng = np.random.default_rng(run.SEED)
        s = np.empty(run.B)
        for b in range(run.B):
            w = np.bincount(rng.integers(0, k, k), minlength=k)[cid]
            s[b] = w[in_dom].sum() / w.sum()
        share_sd[unit] = (float(s.std()), *map(float, np.percentile(s, [2.5, 97.5])))
    print(f"benign rows {benign.height}, pairs {k_b}; top-1 {top1:.4f}, top-5 {top5:.4f}; "
          f"dominant pair {dom_row['src_ip']} -> {dom_row['dst_ip']} ({sizes[dom]} rows), "
          f"A_bytes median {np.median(x_dom):.3f}; present in {n_blocks_with_dom}/{k_b_t60} "
          f"benign 60s blocks; share SD/95% range under resampling: {share_sd}")

    rows = []
    for g in GROUPS:
        ref = comp.filter(pl.col("group") == g)
        verifiable = ref.height > 0 and ref["hostpair_ci_lo"][0] is not None
        attack = df.filter(pl.col("attack_category") == g)
        x_a = a1.a_bytes(attack)
        codes_b, codes_a, n_values = a1.value_codes(benign, attack)
        cid_a_rows, k_a = a1.dense(a1.pair_ids(attack))
        ones_b = np.ones(len(codes_b))

        auc_all = dep.weighted_auc(ones_b, codes_b, np.ones(len(codes_a)), codes_a, n_values)
        auc_dom_only = dep.weighted_auc(in_dom.astype(float), codes_b,
                                        np.ones(len(codes_a)), codes_a, n_values)
        auc_wo_dom = dep.weighted_auc((~in_dom).astype(float), codes_b,
                                      np.ones(len(codes_a)), codes_a, n_values)

        # Attack side collapsed to (pair, code) cells: millions of rows -> few cells.
        ca_codes, ca_cid, ca_cnt = collapse(codes_a, cid_a_rows, n_values)
        t0 = time.time()
        blo = bhi = alo = ahi = tlo = thi = None
        ref = ref.row(0, named=True)  # comparison.csv has all 10 groups
        if verifiable:  # same MIN_CLUSTERS gate as comparison.csv
            blo, bhi = side_bootstrap_ci(codes_b, ones_b, cid_b_rows, ca_codes, ca_cnt, ca_cid,
                                         n_values, "benign", np.random.default_rng(run.SEED))
            alo, ahi = side_bootstrap_ci(codes_b, ones_b, cid_b_rows, ca_codes, ca_cnt, ca_cid,
                                         n_values, "attack", np.random.default_rng(run.SEED))
            tlo, thi = side_bootstrap_ci(codes_b, ones_b, cid_b_t60, ca_codes, ca_cnt, ca_cid,
                                         n_values, "benign", np.random.default_rng(run.SEED))
        row = {
            "group": g, "verifiable": verifiable,
            "n_benign_rows": benign.height, "n_benign_pairs": k_b,
            "benign_top1_pair_share": top1, "benign_top5_pair_share": top5,
            "dominant_pair": f"{dom_row['src_ip']}->{dom_row['dst_ip']}",
            "dominant_pair_rows": int(sizes[dom]),
            "n_benign_blocks_60s": k_b_t60,
            "dominant_pair_blocks_60s": n_blocks_with_dom,
            **{f"dominant_share_{stat}_{u}": share_sd[u][i] for u in units
               for i, stat in enumerate(("sd", "p025", "p975"))},
            "dominant_pair_median_a_bytes": float(np.median(x_dom)),
            "attack_median_a_bytes": float(np.median(x_a)),
            "dominant_pair_quantile_in_attack": float((x_a < np.median(x_dom)).mean()),
            "flow_auc_signed": ref["flow_auc_signed"],
            "flow_auc_recomputed": auc_all,
            "auc_vs_dominant_pair_only": auc_dom_only,
            "auc_vs_benign_without_dominant_pair": auc_wo_dom,
            "n_attack_pairs": k_a,
            "benign_only_ci_lo": blo, "benign_only_ci_hi": bhi,
            "attack_only_ci_lo": alo, "attack_only_ci_hi": ahi,
            "benign_only_timeblock_60s_ci_lo": tlo, "benign_only_timeblock_60s_ci_hi": thi,
            "hostpair_ci_lo": ref["hostpair_ci_lo"], "hostpair_ci_hi": ref["hostpair_ci_hi"],
            "timeblock_60s_ci_lo": ref["timeblock_60s_ci_lo"],
            "timeblock_60s_ci_hi": ref["timeblock_60s_ci_hi"],
        }
        rows.append(row)
        print(f"[{time.strftime('%H:%M:%S')}] {g}: q={row['dominant_pair_quantile_in_attack']:.3f} "
              f"AUC all {auc_all:.3f} / dom-only {auc_dom_only:.3f} / w/o dom {auc_wo_dom:.3f}")
        if verifiable:
            print(f"    benign-only pair [{blo:.3f}, {bhi:.3f}] vs host-pair "
                  f"[{ref['hostpair_ci_lo']:.3f}, {ref['hostpair_ci_hi']:.3f}]; attack-only pair "
                  f"[{alo:.3f}, {ahi:.3f}]; benign-only 60s block [{tlo:.3f}, {thi:.3f}] "
                  f"({time.time() - t0:.0f}s)", flush=True)

    pl.DataFrame(rows).write_csv(OUT)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
