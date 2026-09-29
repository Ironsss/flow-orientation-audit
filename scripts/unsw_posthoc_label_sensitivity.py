#!/usr/bin/env python3
"""POST-HOC / EXPLORATORY -- not part of the frozen UNSW-NB15 plan.

Question (raised in review of manuscript v1, 2026-09-22): 11.5% of UNSW-NB15
Normal rows involve a ground-truth attacker host (214,378 with the attacker
as destination, 40,413 as source). If attacker-involved return traffic sits
in the negative class, the labeling policy itself could inflate
AUC_signed > 0.5. Does removing those rows from Normal change the per-family
AUCs?

Same machinery as the confirmatory run (analyze() imported unchanged, same
B and seed); only the Normal population differs. The H3 verdict is NOT
re-evaluated from this -- it stays the frozen one.

    python scripts/unsw_posthoc_label_sensitivity.py --data-dir <UNSW-NB15>
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingest.unsw_nb15 import attacker_ips, load_unsw  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "unsw_run", ROOT / "scripts" / "run_unsw_external_validation.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()

    att = attacker_ips(args.data_dir)
    df = load_unsw(args.data_dir)
    involved = pl.col("src_ip").is_in(list(att)) | pl.col("dst_ip").is_in(list(att))
    clean = df.filter((pl.col("label") == 1) | ~involved)
    dropped = df.height - clean.height
    print(f"Normal rows dropped (attacker-involved): {dropped:,}")

    table, _, _, _ = run.analyze(
        clean, att, "posthoc_normal_excl_attacker_hosts", np.random.default_rng(run.SEED))
    base = pl.read_csv(ROOT / "results/unsw/asymmetry_by_attack.csv").filter(
        pl.col("population") == "primary_all_rows").select(
        "feature", "category", pl.col("auc_signed").alias("auc_primary"))
    out = (pl.DataFrame([r for r in table if r["computed"]])
           .select("population", "feature", "category", "n_attack", "n_benign",
                   "auc_signed", "ci_lo", "ci_hi", "orientation", "confident")
           .join(base, on=["feature", "category"], how="left")
           .with_columns((pl.col("auc_signed") - pl.col("auc_primary")).alias("shift")))
    out.write_csv(ROOT / "results/unsw/posthoc_label_sensitivity.csv")
    with pl.Config(tbl_rows=40, tbl_cols=12, float_precision=4, tbl_width_chars=200):
        print(out.filter(pl.col("feature") != "A_bytes_attack_oriented"))


if __name__ == "__main__":
    main()
