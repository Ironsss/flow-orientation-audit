#!/usr/bin/env python3
"""Post-hoc multiplicity sensitivity: does testing 9 UNSW-NB15 families (or
10 BoT-IoT groups) at once change which ones are "significant" against
H0: AUC_signed = 0.5, once corrected for running that many tests? NOT a new
confirmatory test -- the pre-registered decision rule (>=1 confident
positive and >=1 confident negative family, at the CI-based 'confident'
definition) is untouched. This asks the same question a different way: raw
per-family p-values vs. Holm-adjusted ones, corrected separately within
each dataset (UNSW's 9 families are one family of tests; BoT-IoT's 10
groups are a separate family -- never pooled together, and never pooled
with H2).

p-values are derived from the already-committed B=2000 percentile
bootstrap draws (results/{unsw,botiot}/asymmetry_bootstrap.csv, the same
draws the pre-registered CIs come from) rather than a separate parametric
test, so this stays inside the pre-registered nonparametric framework:
p_raw = 2 * min(P(draw <= 0.5), P(draw >= 0.5)), the standard percentile
bootstrap two-sided p-value.

    python scripts/multiplicity_holm_sensitivity.py

No data download needed -- reuses committed results only.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingest.bot_iot import GROUPS as BOTIOT_GROUPS  # noqa: E402
from src.ingest.unsw_nb15 import CATEGORIES as UNSW_CATEGORIES  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "unsw_run", ROOT / "scripts" / "run_unsw_external_validation.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

OUT = ROOT / "results" / "multiplicity"
ALPHA = 0.05


def holm(p: np.ndarray) -> np.ndarray:
    """Holm-Bonferroni step-down adjustment. Standard definition: sort
    ascending, adjusted_i = max_{j<=i}((m-j+1)*p_(j)), enforced monotone,
    clipped to 1."""
    m = len(p)
    order = np.argsort(p)
    adj_sorted = np.empty(m)
    running_max = 0.0
    for i, idx in enumerate(order):
        running_max = max(running_max, (m - i) * p[idx])
        adj_sorted[i] = min(running_max, 1.0)
    adjusted = np.empty(m)
    adjusted[order] = adj_sorted
    return adjusted


def bootstrap_p(draws: np.ndarray) -> float:
    """Two-sided percentile-bootstrap p-value. Floored at 1/B: with B=2000
    draws, 'zero of them crossed 0.5' means p < 0.0005, not p = 0."""
    p_hi = float((draws <= 0.5).mean())
    p_lo = float((draws >= 0.5).mean())
    return max(min(2 * min(p_hi, p_lo), 1.0), 1.0 / len(draws))


def sig_orientation(auc: float, p: float) -> str:
    return run.orientation(auc) if p < ALPHA else "not significant"


def process(dataset: str, boot_path: Path, table_path: Path, groups: list[str]) -> list[dict]:
    """groups must be the exact pre-registered family (UNSW_CATEGORIES or
    BOTIOT_GROUPS) -- the bootstrap CSVs also carry descriptive rollup rows
    ("ALL (descriptive)", and for BoT-IoT the 4 category-level aggregates
    DDoS/DoS/Theft/Reconnaissance) that were never part of the frozen
    decision rule and must not be counted in the multiplicity family."""
    boot = pl.read_csv(boot_path).filter(
        (pl.col("population") == "primary_all_rows") & (pl.col("feature") == "A_bytes"))
    table = pl.read_csv(table_path).filter(
        (pl.col("population") == "primary_all_rows") & (pl.col("feature") == "A_bytes"))
    draws = {g: boot.filter(pl.col("category") == g)["auc_signed"].to_numpy() for g in groups}
    point_auc = dict(zip(table["category"].to_list(), table["auc_signed"].to_list(),
                          strict=True))
    aucs = np.array([point_auc[g] for g in groups])  # frozen point estimate, not the draws
    p_raw = np.array([bootstrap_p(draws[g]) for g in groups])
    p_holm = holm(p_raw)
    rows = []
    for g, auc, pr, ph in zip(groups, aucs, p_raw, p_holm, strict=True):
        o_raw, o_holm = sig_orientation(auc, pr), sig_orientation(auc, ph)
        rows.append({
            "dataset": dataset, "group": g, "auc_signed": auc,
            "p_raw": pr, "p_holm": ph,
            "orientation_raw": o_raw, "orientation_holm": o_holm,
            "changed": o_raw != o_holm,
        })
    return rows


def main() -> None:
    unsw = ROOT / "results" / "unsw"
    botiot = ROOT / "results" / "botiot"
    rows = (
        process("UNSW-NB15", unsw / "asymmetry_bootstrap.csv", unsw / "asymmetry_by_attack.csv",
                UNSW_CATEGORIES)
        + process("BoT-IoT", botiot / "asymmetry_bootstrap.csv",
                   botiot / "asymmetry_by_attack.csv", BOTIOT_GROUPS)
    )
    OUT.mkdir(parents=True, exist_ok=True)
    out_path = OUT / "holm_sensitivity.csv"
    pl.DataFrame(rows).write_csv(out_path)
    print(f"wrote {out_path}")
    for r in rows:
        flag = " <-- CHANGED" if r["changed"] else ""
        print(f"{r['dataset']:10s} {r['group']:22s} auc={r['auc_signed']:.3f} "
              f"p_raw={r['p_raw']:.4g} p_holm={r['p_holm']:.4g} "
              f"{r['orientation_raw']} -> {r['orientation_holm']}{flag}")


if __name__ == "__main__":
    main()
