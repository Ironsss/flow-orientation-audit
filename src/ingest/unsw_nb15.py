"""
UNSW-NB15 adapter: the four header-less flow CSVs -> canonical flow schema.

Column names and semantics come from the official NUSW-NB15_features.csv
(copy in docs/methodology/unsw/). Handling decisions are the ones frozen in
docs/methodology/UNSW_EXTERNAL_VALIDATION_FREEZE.md SS7.1 -- change them
there first, never here alone.

Canonical schema:
[timestamp, src_ip, dst_ip, src_port, dst_port, fwd_bytes, bwd_bytes,
 fwd_packets, bwd_packets, label, attack_category, dataset]
fwd = source->destination (sbytes/Spkts), bwd = destination->source.
"""

from pathlib import Path

import polars as pl

FLOW_FILES = [f"UNSW-NB15_{i}.csv" for i in range(1, 5)]
GT_FILE = "NUSW-NB15_GT.csv"

# Official order, NUSW-NB15_features.csv `No.,Name`.
RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload",
    "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
    "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat",
    "Label",
]

# Official family order (description PDF). Also the fixed plotting order.
CATEGORIES = [
    "Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits", "Generic",
    "Reconnaissance", "Shellcode", "Worms",
]


def _port(col: str) -> pl.Expr:
    """Decimal or 0x-hex port; '-' and anything unparseable -> null."""
    s = pl.col(col).str.strip_chars()
    return (
        pl.when(s.str.starts_with("0x"))
        .then(s.str.slice(2).str.to_integer(base=16, strict=False))
        .otherwise(s.str.to_integer(strict=False))
    )


def read_raw(data_dir: Path) -> pl.DataFrame:
    """All four flow files as strings, official column names, BOM stripped."""
    frames = [
        pl.read_csv(
            Path(data_dir) / f, has_header=False, new_columns=RAW_COLUMNS,
            infer_schema=False, encoding="utf8-lossy",
        )
        for f in FLOW_FILES
    ]
    return pl.concat(frames).with_columns(
        pl.col("srcip").str.strip_chars_start("﻿")
    )


def to_canonical(raw: pl.DataFrame) -> pl.DataFrame:
    cat = pl.col("attack_cat").str.strip_chars()
    cat = pl.when(cat == "Backdoor").then(pl.lit("Backdoors")).otherwise(cat)
    label = pl.col("Label").str.strip_chars().cast(pl.Int8)
    return raw.select(
        pl.col("Stime").cast(pl.Int64).alias("timestamp"),
        pl.col("srcip").alias("src_ip"),
        pl.col("dstip").alias("dst_ip"),
        _port("sport").alias("src_port"),
        _port("dsport").alias("dst_port"),
        pl.col("sbytes").cast(pl.Int64).alias("fwd_bytes"),
        pl.col("dbytes").cast(pl.Int64).alias("bwd_bytes"),
        pl.col("Spkts").cast(pl.Int64).alias("fwd_packets"),
        pl.col("Dpkts").cast(pl.Int64).alias("bwd_packets"),
        label.alias("label"),
        pl.when(label == 1).then(cat).otherwise(None).alias("attack_category"),
        pl.lit("UNSW-NB15").alias("dataset"),
    )


def load_unsw(data_dir: Path, dedup: bool = False) -> pl.DataFrame:
    """Canonical frame. dedup=True drops exact duplicates across all 49 raw
    fields (the pre-registered sensitivity population, FREEZE SS7.1)."""
    raw = read_raw(data_dir)
    if dedup:
        raw = raw.unique(maintain_order=True)
    return to_canonical(raw)


def attacker_ips(data_dir: Path) -> set[str]:
    """Distinct `Source IP` of the dataset's own ground-truth attack log."""
    gt = pl.read_csv(Path(data_dir) / GT_FILE, infer_schema=False,
                     encoding="utf8-lossy")
    return {ip.strip() for ip in gt["Source IP"].drop_nulls() if ip.strip()}
