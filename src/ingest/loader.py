"""
CICIDS-2018 data ingestion using Polars lazy evaluation.

Reads raw CSV flow files and produces a standardized schema:
[timestamp, src_ip, dst_ip, src_port, dst_port, protocol, ...features..., label]
"""

from pathlib import Path

import polars as pl

# Standard column mapping from CICIDS-2018 CSVs (CIC-FlowMeter output).
# The raw CSVs have inconsistent whitespace in headers.
COLUMN_RENAME = {
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "tot_fwd_pkts",
    "Tot Bwd Pkts": "tot_bwd_pkts",
    "TotLen Fwd Pkts": "totlen_fwd_pkts",
    "TotLen Bwd Pkts": "totlen_bwd_pkts",
    "Fwd Pkt Len Max": "fwd_pkt_len_max",
    "Fwd Pkt Len Min": "fwd_pkt_len_min",
    "Fwd Pkt Len Mean": "fwd_pkt_len_mean",
    "Fwd Pkt Len Std": "fwd_pkt_len_std",
    "Bwd Pkt Len Max": "bwd_pkt_len_max",
    "Bwd Pkt Len Min": "bwd_pkt_len_min",
    "Bwd Pkt Len Mean": "bwd_pkt_len_mean",
    "Bwd Pkt Len Std": "bwd_pkt_len_std",
    "Flow Byts/s": "flow_byts_per_s",
    "Flow Pkts/s": "flow_pkts_per_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Tot": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Tot": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Len": "fwd_header_len",
    "Bwd Header Len": "bwd_header_len",
    "Fwd Pkts/s": "fwd_pkts_per_s",
    "Bwd Pkts/s": "bwd_pkts_per_s",
    "Pkt Len Min": "pkt_len_min",
    "Pkt Len Max": "pkt_len_max",
    "Pkt Len Mean": "pkt_len_mean",
    "Pkt Len Std": "pkt_len_std",
    "Pkt Len Var": "pkt_len_var",
    "FIN Flag Cnt": "fin_flag_cnt",
    "SYN Flag Cnt": "syn_flag_cnt",
    "RST Flag Cnt": "rst_flag_cnt",
    "PSH Flag Cnt": "psh_flag_cnt",
    "ACK Flag Cnt": "ack_flag_cnt",
    "URG Flag Cnt": "urg_flag_cnt",
    "CWE Flag Count": "cwe_flag_cnt",
    "ECE Flag Cnt": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Pkt Size Avg": "pkt_size_avg",
    "Fwd Seg Size Avg": "fwd_seg_size_avg",
    "Bwd Seg Size Avg": "bwd_seg_size_avg",
    "Fwd Byts/b Avg": "fwd_byts_b_avg",
    "Fwd Pkts/b Avg": "fwd_pkts_b_avg",
    "Fwd Blk Rate Avg": "fwd_blk_rate_avg",
    "Bwd Byts/b Avg": "bwd_byts_b_avg",
    "Bwd Pkts/b Avg": "bwd_pkts_b_avg",
    "Bwd Blk Rate Avg": "bwd_blk_rate_avg",
    "Subflow Fwd Pkts": "subflow_fwd_pkts",
    "Subflow Fwd Byts": "subflow_fwd_byts",
    "Subflow Bwd Pkts": "subflow_bwd_pkts",
    "Subflow Bwd Byts": "subflow_bwd_byts",
    "Init Fwd Win Byts": "init_fwd_win_byts",
    "Init Bwd Win Byts": "init_bwd_win_byts",
    "Fwd Act Data Pkts": "fwd_act_data_pkts",
    "Fwd Seg Size Min": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
    "Label": "label",
}

# Source/destination IP columns present in some CICIDS-2018 variants
IP_COLUMNS = {
    "Src IP": "src_ip",
    "Dst IP": "dst_ip",
    "Src Port": "src_port",
}

# Classic numeric features used as baseline (without IAG)
CLASSIC_FEATURES = [
    "dst_port",
    "protocol",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "fwd_pkt_len_max",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "flow_byts_per_s",
    "flow_pkts_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_mean",
    "fwd_iat_std",
    "bwd_iat_mean",
    "bwd_iat_std",
    "fwd_psh_flags",
    "bwd_psh_flags",
    "fwd_header_len",
    "bwd_header_len",
    "fwd_pkts_per_s",
    "bwd_pkts_per_s",
    "pkt_len_min",
    "pkt_len_max",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_var",
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "down_up_ratio",
    "pkt_size_avg",
    "init_fwd_win_byts",
    "init_bwd_win_byts",
    "fwd_act_data_pkts",
    "fwd_seg_size_min",
    "active_mean",
    "active_std",
    "idle_mean",
    "idle_std",
]


def _strip_columns(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Strip whitespace from column names (CICIDS CSVs have trailing spaces)."""
    rename_map = {col: col.strip() for col in lf.collect_schema().names()}
    return lf.rename(rename_map)


def _normalize_columns(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Apply the standard column renaming."""
    existing = set(lf.collect_schema().names())
    all_mappings = {**COLUMN_RENAME, **IP_COLUMNS}
    rename_map = {k: v for k, v in all_mappings.items() if k in existing}
    return lf.rename(rename_map)


def _clean_data(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Remove infinities and NaNs from numeric columns; drop duplicates.

    Note: `.unique()` does not guarantee the output preserves input row
    order — and empirically, that order is not even stable across repeated
    runs on the same input (observed directly while testing this module).
    Callers that need chronological order (e.g. build_temporal_graphs) must
    re-sort by timestamp explicitly rather than relying on CSV/insertion
    order, and tests against this function's output must not assert on row
    position.
    """
    schema = lf.collect_schema()
    numeric_cols = [
        name for name, dtype in schema.items() if dtype.is_numeric()
    ]

    for col in numeric_cols:
        lf = lf.with_columns(
            pl.when(pl.col(col).is_infinite() | pl.col(col).is_nan())
            .then(0.0)
            .otherwise(pl.col(col))
            .alias(col)
        )

    return lf.unique()


def _parse_timestamp(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Parse the timestamp column into a proper datetime."""
    if "timestamp" not in lf.collect_schema().names():
        return lf

    # CICIDS-2018 uses multiple date formats across files
    return lf.with_columns(
        pl.col("timestamp")
        .str.strptime(pl.Datetime, "%d/%m/%Y %H:%M:%S", strict=False)
        .fill_null(
            pl.col("timestamp").str.strptime(
                pl.Datetime, "%d/%m/%Y %H:%M", strict=False
            )
        )
        .alias("timestamp")
    )


def _encode_label(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Create binary label: 0 = benign, 1 = attack."""
    return lf.with_columns(
        pl.when(pl.col("label").str.to_lowercase().str.contains("benign"))
        .then(pl.lit(0))
        .otherwise(pl.lit(1))
        .alias("is_attack"),
    )


def _numeric_schema_overrides(path: str | Path) -> dict[str, pl.DataType]:
    """Force every genuinely-numeric raw column to Float64 at parse time.

    Without this, a single non-numeric value anywhere in the first
    `infer_schema_length` rows makes polars infer the *entire* column as
    String instead of nulling just that one value. That happens for real on
    CICIDS-2018 files that embed repeated CICFlowMeter export headers mid-file
    (see docs/onboarding/setup/SETUP-LOCAL.md): on
    Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv, this silently turned
    all 49 CLASSIC_FEATURES into String columns, which `_clean_data()` then
    skips entirely since it only touches numeric-dtype columns -- the
    infinity/NaN cleaning it exists to do never ran.

    Reads the real header line first (not inferred) so the override keys match
    whatever whitespace variant is actually in the file, the same reason
    `_strip_columns` exists.
    """
    non_numeric = {"Flow ID", "Src IP", "Dst IP", "Timestamp", "Label"}
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        raw_cols = fh.readline().rstrip("\n\r").split(",")
    return {raw: pl.Float64 for raw in raw_cols if raw.strip() not in non_numeric}


def load_csv(path: str | Path) -> pl.LazyFrame:
    """Load a single CICIDS-2018 CSV file into a cleaned lazy frame."""
    overrides = _numeric_schema_overrides(path)
    lf = pl.scan_csv(
        path, infer_schema_length=10000, ignore_errors=True, schema_overrides=overrides
    )
    lf = _strip_columns(lf)
    lf = _normalize_columns(lf)
    lf = _clean_data(lf)
    lf = _parse_timestamp(lf)
    lf = _encode_label(lf)
    return lf


def load_directory(directory: str | Path) -> pl.LazyFrame:
    """Load all CSV files in a directory and concatenate them."""
    from tqdm import tqdm

    directory = Path(directory)
    csv_files = sorted(directory.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {directory}")

    frames = [load_csv(f) for f in tqdm(csv_files, desc="Scanning CICIDS-2018 CSVs")]
    return pl.concat(frames, how="diagonal_relaxed")


def get_flow_schema() -> list[str]:
    """Return the list of expected columns after ingestion."""
    return list(COLUMN_RENAME.values()) + list(IP_COLUMNS.values()) + ["is_attack"]
