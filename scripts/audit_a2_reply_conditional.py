#!/usr/bin/env python3
"""A2 reviewer audit: how much of the per-flow directional-asymmetry signal
is reply-presence (bwd == 0) versus magnitude conditional on reply. Frozen
per docs/reviewer_audit/A2_REPLY_CONDITIONAL.md.

POST-HOC ROBUSTNESS ANALYSIS. Never writes to results/{unsw,botiot}/.

    python scripts/audit_a2_reply_conditional.py --dataset unsw   --data-dir "<unsw dir>"
    python scripts/audit_a2_reply_conditional.py --dataset botiot --data-dir "<botiot dir>"
    python scripts/audit_a2_reply_conditional.py --dataset cicids --data-dir "<cicids dir>"
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

_spec = importlib.util.spec_from_file_location(
    "unsw_run", ROOT / "scripts" / "run_unsw_external_validation.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

OUT = ROOT / "results" / "audit" / "a2_reply"

# Canonical (UNSW, BoT-IoT) column names differ from raw CICFlowMeter names.
SCHEMAS = {
    "unsw": dict(fb="fwd_bytes", bb="bwd_bytes", fp="fwd_packets", bp="bwd_packets"),
    "botiot": dict(fb="fwd_bytes", bb="bwd_bytes", fp="fwd_packets", bp="bwd_packets"),
    "cicids": dict(
        fb="totlen_fwd_pkts", bb="totlen_bwd_pkts", fp="tot_fwd_pkts", bp="tot_bwd_pkts"),
}


def counting_auc(benign_x: np.ndarray, attack_x: np.ndarray) -> float | None:
    if len(benign_x) == 0 or len(attack_x) == 0:
        return None
    values, inv = np.unique(np.concatenate([benign_x, attack_x]), return_inverse=True)
    codes_b, codes_a = inv[: len(benign_x)], inv[len(benign_x):]
    bc = np.bincount(codes_b, minlength=len(values))
    lk = run.auc_lookup(bc)
    return run.auc_from_codes(lk, codes_a, len(benign_x))


def load(
    dataset: str, data_dir: Path
) -> tuple[pl.DataFrame, dict[str, np.ndarray], dict[str, str]]:
    cols = SCHEMAS[dataset]
    if dataset == "unsw":
        from src.ingest.unsw_nb15 import load_unsw
        df = load_unsw(data_dir, dedup=False)
        groups = {"label": df["attack_category"].fill_null("").to_numpy(),
                  "is_attack": (df["label"] == 1).to_numpy()}
    elif dataset == "botiot":
        from src.ingest.bot_iot import load_botiot
        df = load_botiot(data_dir)
        groups = {"label": df["attack_category"].fill_null("").to_numpy(),
                  "is_attack": (df["label"] == 1).to_numpy()}
    else:
        from src.ingest.loader import load_directory
        df = load_directory(data_dir).collect()
        groups = {"label": df["label"].str.strip_chars().to_numpy(),
                  "is_attack": df["is_attack"].to_numpy().astype(bool)}
    return df, groups, cols


def analyze(df: pl.DataFrame, groups: dict, cols: dict, dataset: str) -> tuple[list, list]:
    fb = np.log1p(df[cols["fb"]].to_numpy().astype(np.float64))
    bb = np.log1p(df[cols["bb"]].to_numpy().astype(np.float64))
    fp = np.log1p(df[cols["fp"]].to_numpy().astype(np.float64))
    bp = np.log1p(df[cols["bp"]].to_numpy().astype(np.float64))
    a_bytes, a_packets = fb - bb, fp - bp
    reply_bytes = df[cols["bb"]].to_numpy() > 0
    reply_packets = df[cols["bp"]].to_numpy() > 0
    benign = ~groups["is_attack"]
    labels = np.unique(groups["label"][groups["is_attack"] & (groups["label"] != "")])

    rates, aucs = [], []
    for g in labels:
        m = groups["is_attack"] & (groups["label"] == g)
        rates.append({
            "dataset": dataset, "group": str(g), "n_attack": int(m.sum()),
            "n_benign": int(benign.sum()),
            "reply_rate_attack_bytes": float(reply_bytes[m].mean()),
            "reply_rate_benign_bytes": float(reply_bytes[benign].mean()),
            "reply_rate_attack_packets": float(reply_packets[m].mean()),
            "reply_rate_benign_packets": float(reply_packets[benign].mean()),
        })
        for feat, x, reply in (
            ("A_bytes", a_bytes, reply_bytes), ("A_packets", a_packets, reply_packets)
        ):
            for slice_name, sel in (("all", np.ones_like(benign)), ("answered", reply),
                                     ("unanswered", ~reply)):
                bm, am = benign & sel, m & sel
                auc = counting_auc(x[bm], x[am])
                aucs.append({"dataset": dataset, "group": str(g), "feature": feat,
                              "slice": slice_name, "n_attack": int(am.sum()),
                              "n_benign": int(bm.sum()), "auc_signed": auc})
    return rates, aucs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=list(SCHEMAS), required=True)
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()

    df, groups, cols = load(args.dataset, args.data_dir)
    rates, aucs = analyze(df, groups, cols, args.dataset)

    OUT.mkdir(parents=True, exist_ok=True)
    for name, rows in (("reply_rates", rates), ("auc_by_slice", aucs)):
        path = OUT / f"{name}.csv"
        new = pl.DataFrame(rows)
        if path.exists():
            new = pl.concat([pl.read_csv(path).filter(pl.col("dataset") != args.dataset), new])
        new.write_csv(path)
        print(f"wrote {path} ({new.height} rows)")


if __name__ == "__main__":
    main()
