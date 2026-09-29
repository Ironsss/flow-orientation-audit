"""NF-CSE-CIC-IDS2018-v2 (standalone, fine labels) loader for reviewer audit A4.

Columns keep their NF names on purpose. NF `IN_BYTES`/`OUT_BYTES` count whole
packets including headers; CICFlowMeter `totlen_fwd_pkts`/`totlen_bwd_pkts`
count payload only (docs/reviewer_audit/A4_FEATURE_MAPPING.md). They are not
renamed to a shared canonical name because they do not mean the same thing.

Every column is read as a string first, so the exact-duplicate test is over
the raw text of all 45 columns (the preflight's method), and the four
directional fields are then cast strictly: a missing or unparseable value
raises instead of silently becoming null or 0.
"""
from __future__ import annotations

from pathlib import Path

import polars as pl

DIRECTIONAL = ["IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS"]
LABEL_COLS = ["Label", "Attack"]
SEP = "\x1f"


def load_nf_cse_cicids2018_v2(path: str | Path) -> tuple[pl.DataFrame, dict]:
    """Return (frame, info).

    frame columns: IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS (Int64), Label (Int64),
    Attack (str), feature_hash (u64 over the 43 non-label columns).
    info: n_raw, n_benign_raw, n_attack_raw, n_exact_duplicates_removed.
    """
    lf = pl.scan_csv(path, infer_schema=False)  # every column as String
    cols = lf.collect_schema().names()
    missing = [c for c in DIRECTIONAL + LABEL_COLS if c not in cols]
    if missing:
        raise ValueError(f"NF file lacks columns {missing}")
    features = [c for c in cols if c not in LABEL_COLS]
    df = lf.select(
        *[pl.col(c).cast(pl.Int64, strict=True) for c in DIRECTIONAL],
        pl.col("Label").cast(pl.Int64, strict=True),
        pl.col("Attack"),
        pl.concat_str(features, separator=SEP).hash().alias("feature_hash"),
        pl.concat_str(cols, separator=SEP).hash().alias("row_hash"),
    ).collect(engine="streaming")
    if df.null_count().sum_horizontal().item() > 0:
        raise ValueError(f"NF file has missing values: {df.null_count().row(0, named=True)}")
    info = {
        "n_raw": df.height,
        "n_benign_raw": int((df["Label"] == 0).sum()),
        "n_attack_raw": int((df["Label"] == 1).sum()),
    }
    # Exact full-row duplicates (all 45 raw columns), removed for symmetry with
    # canonical `.unique()`. 64-bit hash, as in the preflight.
    df = df.unique(subset="row_hash", keep="first", maintain_order=True).drop("row_hash")
    info["n_exact_duplicates_removed"] = info["n_raw"] - df.height
    return df, info
