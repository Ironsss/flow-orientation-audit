#!/usr/bin/env python3
"""A3 reviewer audit: per-raw-label AUC breakdown on CICIDS-2018, checking
whether the Label column actually separates HOIC/LOIC-HTTP/LOIC-UDP/Hulk/
etc. rather than treating a capture as one unresolvable mix. Frozen per
docs/reviewer_audit/A3_EXPORTER_AND_LABEL_SEMANTICS.md.

POST-HOC ROBUSTNESS ANALYSIS. Does not edit docs/datos-reales/'s existing
exploratory write-up; re-derives independently from data/raw/*.csv.

    python scripts/audit_a3_cicids_labels.py --data-dir data/raw
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

from src.ingest.loader import load_csv  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "a2", ROOT / "scripts" / "audit_a2_reply_conditional.py")
a2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a2)

OUT = ROOT / "results" / "audit"


def per_file(path: Path) -> list[dict]:
    df = load_csv(path).collect()
    label = df["label"].str.strip_chars().to_numpy()
    benign = label == "Benign"
    fb = np.log1p(df["totlen_fwd_pkts"].to_numpy().astype(np.float64))
    bb = np.log1p(df["totlen_bwd_pkts"].to_numpy().astype(np.float64))
    fp = np.log1p(df["tot_fwd_pkts"].to_numpy().astype(np.float64))
    bp = np.log1p(df["tot_bwd_pkts"].to_numpy().astype(np.float64))
    a_bytes, a_packets = fb - bb, fp - bp
    reply = df["totlen_bwd_pkts"].to_numpy() > 0

    rows = []
    for lab in np.unique(label[~benign]):
        m = label == lab
        n = int(m.sum())
        if n == 0:
            continue
        auc_b = a2.counting_auc(a_bytes[benign], a_bytes[m])
        rows.append({
            "capture_file": path.name, "label": str(lab), "n": n,
            "auc_signed_bytes": auc_b,
            "auc_sep_bytes": max(auc_b, 1 - auc_b) if auc_b is not None else None,
            "auc_signed_packets": a2.counting_auc(a_packets[benign], a_packets[m]),
            "reply_rate": float(reply[m].mean()),
            "median_a_bytes_attack": float(np.median(a_bytes[m])),
            "median_a_bytes_benign": float(np.median(a_bytes[benign])),
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()

    paths = sorted(args.data_dir.glob("*.csv"))
    rows = []
    for path in paths:
        print(f"processing {path.name}")
        rows += per_file(path)

    OUT.mkdir(parents=True, exist_ok=True)
    out_path = OUT / "a3_cicids_labels.csv"
    pl.DataFrame(rows).write_csv(out_path)
    print(f"wrote {out_path} ({len(rows)} label rows across {len(paths)} files)")


if __name__ == "__main__":
    main()
