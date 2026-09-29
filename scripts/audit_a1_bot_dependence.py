#!/usr/bin/env python3
"""A1 reviewer audit: BoT-IoT dependence sensitivity beyond host-pair
cluster bootstrap. Frozen per docs/reviewer_audit/A1_BOT_DEPENDENCE.md.
Adds, to the already-computed host-pair result
(results/dependence/cluster_bootstrap_botiot.csv,
scripts/dependence_cluster_bootstrap.py):

  C. two-stage bootstrap: host-pairs resampled, then flows resampled within
     each drawn pair-replicate. A pair drawn m times contributes a
     Multinomial(m * n_pair, uniform) weight vector over its own rows --
     the sum of m independent Multinomial(n_pair, uniform) draws over the
     same probability vector equals one Multinomial(m * n_pair, uniform)
     draw (multinomial additivity).
  D. time-block bootstrap: cluster id = timestamp // block_seconds, for
     block_seconds in {60, 300, 600}.
  Cluster-weighted point estimate: each host-pair weighted 1/n_pair_rows.

POST-HOC ROBUSTNESS ANALYSIS. Never writes to results/botiot/ or
results/dependence/.

    python scripts/audit_a1_bot_dependence.py --data-dir "<botiot dir>"
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
    "dep_boot", ROOT / "scripts" / "dependence_cluster_bootstrap.py")
dep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dep)
run = dep.run

MIN_CLUSTERS = dep.MIN_CLUSTERS
OUT = ROOT / "results" / "audit" / "a1_bot_dependence"
BLOCK_SECONDS = 300  # primary granularity; feeds sign_stable
# Freeze item 2 also names 60s and 600s. They were added after the first run
# (see A1_BOT_DEPENDENCE_REPORT.md). Each gets its own generator seeded with
# SEED so the shared `rng` feeding 300s and two-stage draws exactly what it
# drew before -- previously committed columns stay bit-identical. They are
# reported evidence only; sign_stable is not changed to use them.
EXTRA_BLOCK_SECONDS = (60, 600)


def a_bytes(d: pl.DataFrame) -> np.ndarray:
    fb = np.log1p(d["fwd_bytes"].to_numpy().astype(np.float64))
    bb = np.log1p(d["bwd_bytes"].to_numpy().astype(np.float64))
    return fb - bb


def value_codes(benign: pl.DataFrame, attack: pl.DataFrame):
    x_b, x_a = a_bytes(benign), a_bytes(attack)
    values, inv = np.unique(np.concatenate([x_b, x_a]), return_inverse=True)
    return inv[: len(x_b)], inv[len(x_b):], len(values)


def dense(ids: np.ndarray) -> tuple[np.ndarray, int]:
    """Map arbitrary integer ids to dense 0..K-1 codes."""
    if len(ids) == 0:
        return ids, 0
    _, inv = np.unique(ids, return_inverse=True)
    return inv, int(inv.max()) + 1


def timeblock_ids(df: pl.DataFrame, block_seconds: int) -> np.ndarray:
    return df["timestamp"].to_numpy().astype(np.int64) // block_seconds


def pair_ids(df: pl.DataFrame) -> np.ndarray:
    return (df.select(pl.struct(["src_ip", "dst_ip"]).rank("dense").alias("c"))["c"]
            .to_numpy().astype(np.int64) - 1)


def cluster_bootstrap_ci(codes_b, codes_a, n_values, cid_b, cid_a, k_b, k_a,
                          rng: np.random.Generator) -> tuple[float, float]:
    draws = np.empty(run.B)
    for b in range(run.B):
        wb = np.bincount(rng.integers(0, k_b, k_b), minlength=k_b)[cid_b]
        wa = np.bincount(rng.integers(0, k_a, k_a), minlength=k_a)[cid_a]
        draws[b] = dep.weighted_auc(wb.astype(np.float64), codes_b,
                                     wa.astype(np.float64), codes_a, n_values)
    lo, hi = np.percentile(draws, [2.5, 97.5])
    return float(lo), float(hi)


def two_stage_bootstrap_ci(codes_b, codes_a, n_values, cid_b, cid_a, k_b, k_a,
                            rng: np.random.Generator) -> tuple[float, float]:
    n_per_b = np.bincount(cid_b, minlength=k_b)
    n_per_a = np.bincount(cid_a, minlength=k_a)
    rows_b = [np.nonzero(cid_b == p)[0] for p in range(k_b)]
    rows_a = [np.nonzero(cid_a == p)[0] for p in range(k_a)]
    draws = np.empty(run.B)
    for b in range(run.B):
        m_b = np.bincount(rng.integers(0, k_b, k_b), minlength=k_b)
        m_a = np.bincount(rng.integers(0, k_a, k_a), minlength=k_a)
        wb = np.zeros(len(codes_b))
        for p in np.nonzero(m_b)[0]:
            r = rows_b[p]
            wb[r] = rng.multinomial(int(m_b[p]) * n_per_b[p], np.full(len(r), 1 / len(r)))
        wa = np.zeros(len(codes_a))
        for p in np.nonzero(m_a)[0]:
            r = rows_a[p]
            wa[r] = rng.multinomial(int(m_a[p]) * n_per_a[p], np.full(len(r), 1 / len(r)))
        draws[b] = dep.weighted_auc(wb, codes_b, wa, codes_a, n_values)
    lo, hi = np.percentile(draws, [2.5, 97.5])
    return float(lo), float(hi)


def cluster_weighted_point(codes_b, codes_a, n_values, cid_b, cid_a, k_b, k_a) -> float:
    wb = 1.0 / np.bincount(cid_b, minlength=k_b)[cid_b]
    wa = 1.0 / np.bincount(cid_a, minlength=k_a)[cid_a]
    return dep.weighted_auc(wb, codes_b, wa, codes_a, n_values)


def stable(r: dict) -> bool | None:
    """True iff every computed CI in row r (flow, host-pair, two-stage, and
    time-block when available) is confident (does not straddle 0.5) AND all
    agree on the same side of 0.5. None if the row's group wasn't verifiable
    (host-pairs below MIN_CLUSTERS, so two_stage was never computed)."""
    if r.get("two_stage_ci_lo") is None:
        return None
    cis = [(r["flow_ci_lo"], r["flow_ci_hi"]), (r["hostpair_ci_lo"], r["hostpair_ci_hi"]),
           (r["two_stage_ci_lo"], r["two_stage_ci_hi"])]
    if r.get("timeblock_300s_ci_lo") is not None:
        cis.append((r["timeblock_300s_ci_lo"], r["timeblock_300s_ci_hi"]))
    # Each CI's own side (above/below 0.5), None if it straddles 0.5 (not
    # confident). Stable requires every computed CI to be confident AND
    # all on the same side -- not just the single flow-level point sign
    # repeated (a set of one constant is trivially a singleton and would
    # always report "stable" regardless of the CIs; that was a bug).
    sides = [True if lo > 0.5 else False if hi < 0.5 else None for lo, hi in cis]
    if any(s is None for s in sides):
        return False
    return len(set(sides)) == 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()
    rng = np.random.default_rng(run.SEED)
    extra_rngs = {s: np.random.default_rng(run.SEED) for s in EXTRA_BLOCK_SECONDS}

    df = load_botiot(args.data_dir)
    benign = df.filter(pl.col("label") == 0)
    hostpair = pl.read_csv(ROOT / "results" / "dependence" / "cluster_bootstrap_botiot.csv")

    rows = []
    for g in GROUPS:
        attack = df.filter(pl.col("attack_category") == g)
        ref = hostpair.filter(pl.col("group") == g)
        if ref.height == 0:
            continue
        ref = ref.row(0, named=True)
        codes_b, codes_a, n_values = value_codes(benign, attack)
        cid_b_p, k_b_p = dense(pair_ids(benign))
        cid_a_p, k_a_p = dense(pair_ids(attack))
        row = {
            "group": g,
            "flow_auc_signed": ref["flow_auc_signed"],
            "flow_ci_lo": ref["flow_ci_lo"], "flow_ci_hi": ref["flow_ci_hi"],
            "hostpair_ci_lo": ref["cluster_ci_lo"], "hostpair_ci_hi": ref["cluster_ci_hi"],
        }
        # Time-block is gated on its own block count (freeze item 2), not on
        # host-pairs, so 60s/600s run for every group that clears MIN_CLUSTERS.
        for s in EXTRA_BLOCK_SECONDS:
            cid_b_x, k_b_x = dense(timeblock_ids(benign, s))
            cid_a_x, k_a_x = dense(timeblock_ids(attack, s))
            if k_a_x < MIN_CLUSTERS:
                row |= {f"timeblock_{s}s_ci_lo": None, f"timeblock_{s}s_ci_hi": None,
                        f"note_timeblock_{s}s": f"not computed: only {k_a_x} time blocks"}
                continue
            t0 = time.time()
            xlo, xhi = cluster_bootstrap_ci(codes_b, codes_a, n_values, cid_b_x, cid_a_x,
                                            k_b_x, k_a_x, extra_rngs[s])
            row |= {f"timeblock_{s}s_ci_lo": xlo, f"timeblock_{s}s_ci_hi": xhi,
                    f"note_timeblock_{s}s": f"{k_a_x} time blocks"}
            print(f"[{time.strftime('%H:%M:%S')}] {g}: time-block {s}s CI [{xlo:.3f}, {xhi:.3f}]"
                  f" ({k_a_x} blocks, {time.time() - t0:.0f}s)", flush=True)
        if k_a_p < MIN_CLUSTERS:
            row |= {"timeblock_300s_ci_lo": None, "timeblock_300s_ci_hi": None,
                    "two_stage_ci_lo": None, "two_stage_ci_hi": None,
                    "cluster_weighted_point": None,
                    "note": f"not computed: only {k_a_p} host-pairs (< {MIN_CLUSTERS})"}
            rows.append(row)
            continue

        cid_b_t, k_b_t = dense(timeblock_ids(benign, BLOCK_SECONDS))
        cid_a_t, k_a_t = dense(timeblock_ids(attack, BLOCK_SECONDS))
        if k_a_t < MIN_CLUSTERS:
            row |= {"timeblock_300s_ci_lo": None, "timeblock_300s_ci_hi": None,
                    "note_timeblock": f"not computed: only {k_a_t} time blocks"}
        else:
            t0 = time.time()
            tlo, thi = cluster_bootstrap_ci(codes_b, codes_a, n_values, cid_b_t, cid_a_t,
                                             k_b_t, k_a_t, rng)
            row |= {"timeblock_300s_ci_lo": tlo, "timeblock_300s_ci_hi": thi}
            print(f"[{time.strftime('%H:%M:%S')}] {g}: time-block CI [{tlo:.3f}, {thi:.3f}]"
                  f" ({k_a_t} blocks, {time.time() - t0:.0f}s)")

        t0 = time.time()
        slo, shi = two_stage_bootstrap_ci(codes_b, codes_a, n_values, cid_b_p, cid_a_p,
                                           k_b_p, k_a_p, rng)
        cwp = cluster_weighted_point(codes_b, codes_a, n_values, cid_b_p, cid_a_p, k_b_p, k_a_p)
        row |= {"two_stage_ci_lo": slo, "two_stage_ci_hi": shi, "cluster_weighted_point": cwp}
        print(f"[{time.strftime('%H:%M:%S')}] {g}: two-stage CI [{slo:.3f}, {shi:.3f}],"
              f" cluster-weighted point {cwp:.3f} ({time.time() - t0:.0f}s)")
        rows.append(row)

    for r in rows:
        r["sign_stable"] = stable(r)

    OUT.mkdir(parents=True, exist_ok=True)
    pl.DataFrame(rows).write_csv(OUT / "comparison.csv")
    print(f"wrote {OUT / 'comparison.csv'}")


if __name__ == "__main__":
    main()
