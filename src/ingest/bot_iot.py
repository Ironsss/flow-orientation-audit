"""
BoT-IoT adapter: the 74 header-less "Entire Dataset" CSVs -> canonical flow schema.

Column names come from the release's own
UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv; semantics from the dataset
paper's Table 2 (Koroniotis et al. 2019). Handling decisions are frozen in
docs/methodology/BOTIOT_H3_FREEZE.md SS4 and SS9.1 -- change them there
first, never here alone.

Canonical schema (same as src/ingest/unsw_nb15.py):
[timestamp, src_ip, dst_ip, src_port, dst_port, fwd_bytes, bwd_bytes,
 fwd_packets, bwd_packets, label, attack_category, dataset]
fwd = source->destination (sbytes/spkts), bwd = destination->source.
`attack_category` holds the frozen SS2 group name, not the raw strings.
"""

from pathlib import Path

import polars as pl

FLOW_FILES = [f"UNSW_2018_IoT_Botnet_Dataset_{i}.csv" for i in range(1, 75)]
NAMES_FILE = "UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv"

# Paper Fig. 1; frozen in BOTIOT_H3_FREEZE.md SS2 / SS5.
ATTACKERS = ["192.168.100.147", "192.168.100.148", "192.168.100.149", "192.168.100.150"]

# (category, subcategory) raw strings -> frozen SS2 group, in the SS2 order
# (also the fixed plotting order). Mapping verified one-to-one in SS9.1.
GROUP_MAP = {
    ("Reconnaissance", "Service_Scan"): "Recon/Service scan",
    ("Reconnaissance", "OS_Fingerprint"): "Recon/OS fingerprint",
    ("DDoS", "TCP"): "DDoS/TCP",
    ("DDoS", "UDP"): "DDoS/UDP",
    ("DDoS", "HTTP"): "DDoS/HTTP",
    ("DoS", "TCP"): "DoS/TCP",
    ("DoS", "UDP"): "DoS/UDP",
    ("DoS", "HTTP"): "DoS/HTTP",
    ("Theft", "Keylogging"): "Theft/Keylogging",
    ("Theft", "Data_Exfiltration"): "Theft/Data theft",
}
GROUPS = list(GROUP_MAP.values())


def column_names(data_dir: Path) -> list[str]:
    return [c.strip() for c in (Path(data_dir) / NAMES_FILE).read_text().strip().split(",")]


def scan_raw(data_dir: Path) -> pl.LazyFrame:
    """All 74 files, every column as a string."""
    names = column_names(data_dir)
    return pl.concat([
        pl.scan_csv(Path(data_dir) / f, has_header=False, new_columns=names,
                    infer_schema=False, quote_char='"')
        for f in FLOW_FILES
    ])


def _port(col: str) -> pl.Expr:
    """Decimal or 0x-hex port; empty, service names ('xinetd') -> null."""
    s = pl.col(col).str.strip_chars()
    return (pl.when(s.str.starts_with("0x"))
            .then(s.str.slice(2).str.to_integer(base=16, strict=False))
            .otherwise(s.str.to_integer(strict=False)))


def _group() -> pl.Expr:
    cat, sub = pl.col("category").str.strip_chars(), pl.col("subcategory").str.strip_chars()
    expr = pl.lit(None, dtype=pl.String)
    for (c, s), g in GROUP_MAP.items():
        expr = pl.when((cat == c) & (sub == s)).then(pl.lit(g)).otherwise(expr)
    return expr


def to_canonical(raw: pl.LazyFrame) -> pl.LazyFrame:
    label = pl.col("attack").str.strip_chars().cast(pl.Int8)
    return raw.select(
        pl.col("stime").cast(pl.Float64).alias("timestamp"),
        pl.col("saddr").str.strip_chars().cast(pl.Categorical).alias("src_ip"),
        pl.col("daddr").str.strip_chars().cast(pl.Categorical).alias("dst_ip"),
        _port("sport").alias("src_port"),
        _port("dport").alias("dst_port"),
        pl.col("sbytes").cast(pl.Int64).alias("fwd_bytes"),
        pl.col("dbytes").cast(pl.Int64).alias("bwd_bytes"),
        pl.col("spkts").cast(pl.Int64).alias("fwd_packets"),
        pl.col("dpkts").cast(pl.Int64).alias("bwd_packets"),
        label.alias("label"),
        pl.when(label == 1).then(_group()).otherwise(None).alias("attack_category"),
        pl.lit("BoT-IoT").alias("dataset"),
    )


def load_botiot(data_dir: Path) -> pl.DataFrame:
    """Canonical frame, all rows as released (FREEZE SS4 primary population)."""
    return to_canonical(scan_raw(data_dir)).collect(engine="streaming")


def duplicate_count(data_dir: Path) -> int:
    """Exact duplicates across all raw columns except pkSeqID (SS4 dedup definition),
    by 64-bit row hash. Order-independent, so streaming is safe."""
    q = scan_raw(data_dir)
    others = [c for c in column_names(data_dir) if c != "pkSeqID"]
    h = q.select(pl.concat_str([pl.col(c).fill_null("") for c in others], separator="\x1f")
                 .hash(seed=0)).collect(engine="streaming").to_series()
    return len(h) - h.n_unique()
