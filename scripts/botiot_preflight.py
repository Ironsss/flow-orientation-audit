#!/usr/bin/env python3
"""BoT-IoT Phase 0 -- blind structural preflight (BOTIOT_H3_FREEZE.md SS9).

Computes ONLY what SS9 allows: file names/sizes/SHA256, row counts, column
types (castability), nulls, duplicates, the label vocabulary with counts,
attack/category consistency, the attacker-IP presence check, and the stime
range per group (C2). No statistic of sbytes/dbytes/spkts/dpkts -- or of
pkts/bytes/rate/srate/drate, which are derived from the same counters -- is
ever split by label here: those columns appear only in the castability and
null checks, which are computed over all rows regardless of label.

    python scripts/botiot_preflight.py --data-dir "<...>/Entire Dataset"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
FILES = [f"UNSW_2018_IoT_Botnet_Dataset_{i}.csv" for i in range(1, 75)]
NAMES_FILE = "UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv"
# Paper Fig. 1 (Koroniotis et al. 2019), frozen in BOTIOT_H3_FREEZE.md SS2.
ATTACKERS = ["192.168.100.147", "192.168.100.148", "192.168.100.149", "192.168.100.150"]
NUMERIC = ["pkSeqID", "stime", "pkts", "bytes", "ltime", "seq", "dur", "mean", "stddev",
           "sum", "min", "max", "spkts", "dpkts", "sbytes", "dbytes", "rate", "srate",
           "drate", "attack"]
PORTS = ["sport", "dport"]


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    d = ap.parse_args().data_dir
    out: dict = {"data_dir": str(d)}

    names = [c.strip() for c in (d / NAMES_FILE).read_text().strip().split(",")]
    out["columns"] = names
    missing = [f for f in FILES if not (d / f).exists()]
    out["missing_files"] = missing
    assert not missing, missing

    _log("hashing files")
    out["files"] = {f: {"bytes": (d / f).stat().st_size, "sha256": sha256(d / f)}
                    for f in FILES + [NAMES_FILE]}

    def scan(f: str) -> pl.LazyFrame:
        return pl.scan_csv(d / f, has_header=False, new_columns=names, infer_schema=False,
                           quote_char='"')

    _log("row counts per file")
    for f in FILES:
        out["files"][f]["rows"] = scan(f).select(pl.len()).collect().item()
    out["rows_total"] = sum(out["files"][f]["rows"] for f in FILES)

    q = pl.concat([scan(f) for f in FILES])

    _log("nulls/empties and castability")
    empty = [((pl.col(c).is_null()) | (pl.col(c).str.strip_chars() == "")).sum().alias(c)
             for c in names]
    out["null_or_empty"] = q.select(empty).collect(engine="streaming").row(0, named=True)
    bad = [(pl.col(c).is_not_null() & (pl.col(c).str.strip_chars() != "")
            & pl.col(c).cast(pl.Float64, strict=False).is_null()).sum().alias(c)
           for c in NUMERIC]
    out["non_numeric_values"] = q.select(bad).collect(engine="streaming").row(0, named=True)
    port_bad = [(pl.col(c).is_not_null() & (pl.col(c).str.strip_chars() != "")
                 & pl.col(c).cast(pl.Int64, strict=False).is_null()).sum().alias(c)
                for c in PORTS]
    out["non_decimal_ports"] = q.select(port_bad).collect(engine="streaming").row(0, named=True)
    out["non_decimal_port_examples"] = {
        c: q.filter(pl.col(c).str.strip_chars().ne("")
                    & pl.col(c).cast(pl.Int64, strict=False).is_null())
            .select(pl.col(c)).unique().head(10).collect(engine="streaming")[c].to_list()
        for c in PORTS}

    _log("label vocabulary, stime range per group")
    labels = (q.group_by("attack", "category", "subcategory")
               .agg(pl.len().alias("rows"),
                    pl.col("stime").cast(pl.Float64).min().alias("stime_min"),
                    pl.col("stime").cast(pl.Float64).max().alias("stime_max"))
               .sort("attack", "category", "subcategory")
               .collect(engine="streaming"))
    out["label_groups"] = labels.to_dicts()

    _log("attacker-IP presence (attack rows, all groups pooled)")
    att = q.filter(pl.col("attack").str.strip_chars() == "1").select(
        pl.len().alias("attack_rows"),
        (pl.col("saddr").is_in(ATTACKERS) | pl.col("daddr").is_in(ATTACKERS))
        .sum().alias("involving_attacker_host"),
    ).collect(engine="streaming").row(0, named=True)
    out["attacker_presence"] = att | {"attacker_set": ATTACKERS}

    _log("exact duplicates (all columns except pkSeqID)")
    others = [c for c in names if c != "pkSeqID"]
    h = q.select(pl.concat_str([pl.col(c).fill_null("") for c in others], separator="\x1f")
                 .hash(seed=0).alias("h")).collect(engine="streaming")["h"]
    out["duplicates"] = {"rows": len(h), "distinct": h.n_unique(),
                         "duplicate_rows": len(h) - h.n_unique(),
                         "method": "64-bit hash of all columns except pkSeqID"}
    out["pkSeqID_distinct"] = q.select(pl.col("pkSeqID").n_unique()).collect(
        engine="streaming").item()

    res = ROOT / "results" / "botiot"
    res.mkdir(parents=True, exist_ok=True)
    (res / "preflight.json").write_text(json.dumps(out, indent=2, default=str))
    _log(f"done -> {res / 'preflight.json'}")


if __name__ == "__main__":
    main()
