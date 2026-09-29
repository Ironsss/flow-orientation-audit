#!/usr/bin/env python3
"""
Statistical analysis of the real CICIDS-2018 files downloaded to this machine.

Every number this repository has cited about feature behaviour, per-flow
asymmetry AUC, and Phase 0 window criteria came from `src/simulator/agents.py`
(synthetic traffic), not from CICIDS-2018 itself. This script runs the same
measurements -- reusing the project's own tested code, not reimplementing it --
against the two real files in `data/raw/`, so the comparison in
`docs/datos-reales/ANALISIS-DATOS-REALES.tex` is reproducible rather than typed
by hand.

Memory discipline (the file with IPs is 3.8 GB / 7.9M rows):
  - Column stats (nulls, means, quantiles) are single-pass lazy aggregations
    over the whole file -- polars never materializes the 84-column frame.
  - The correlation/redundancy step needs a materialized matrix, so it takes a
    bounded, deterministic systematic sample (every k-th row, no RNG needed)
    instead of the full population.
  - The Phase 0 / window-level pipeline run selects only the six columns
    `window_features` actually touches before collecting eagerly, not the full
    schema.

Usage
-----
    python scripts/analyze_real_data.py data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
    python scripts/analyze_real_data.py data/raw/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
    python scripts/analyze_real_data.py data/raw/  # both files found in the directory
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.audit.ablation import correlation_groups  # noqa: E402
from src.features.extractors import PERFLOW_FEATURES, SIZE_FEATURES, TOPOLOGY_FEATURES  # noqa: E402
from src.features.tiers import InfoTier  # noqa: E402
from src.features.windows import window_features  # noqa: E402
from src.ingest.loader import (  # noqa: E402
    CLASSIC_FEATURES,
    COLUMN_RENAME,
    IP_COLUMNS,
    _normalize_columns,
    _numeric_schema_overrides,
    _strip_columns,
    load_csv,
)

RESULTS_DIR = Path("results")
FIGURES_DIR = RESULTS_DIR / "figures"
METRICS_DIR = RESULTS_DIR / "metrics"

GREEN, YELLOW, BLUE, BOLD, NC = (
    "\033[0;32m", "\033[1;33m", "\033[0;34m", "\033[1m", "\033[0m",
)


def _log(msg: str) -> None:
    print(f"{BLUE}[INFO]{NC} {msg}")


def _header(msg: str) -> None:
    print(f"\n{BOLD}{msg}{NC}\n{'-' * len(msg)}")


# --------------------------------------------------------------------- schema
def describe_columns(path: Path) -> list[dict]:
    """Raw header, read as plain text -- no dtype inference (see the
    preflight_data.py fix in docs/onboarding/setup/SETUP-LOCAL.md: letting
    polars infer types just to read column names is what broke on both real
    files tried against it)."""
    with path.open(encoding="utf-8", errors="replace") as fh:
        raw_cols = [c.strip() for c in fh.readline().rstrip("\n\r").split(",")]

    rename_all = {**COLUMN_RENAME, **IP_COLUMNS}
    rows = []
    for raw in raw_cols:
        normalized = rename_all.get(raw)
        if raw == "Flow ID":
            role = "identifier"
        elif raw in IP_COLUMNS:
            role = "ip/port"
        elif normalized == "label":
            role = "label"
        elif normalized == "timestamp":
            role = "timestamp"
        elif normalized in CLASSIC_FEATURES:
            role = "classic_feature (directional)" if (
                "fwd" in normalized or "bwd" in normalized
            ) else "classic_feature (non-directional)"
        elif normalized is not None:
            role = "other_mapped"
        else:
            role = "unmapped"
        rows.append({"raw_column": raw, "normalized": normalized or "(unmapped)", "role": role})
    return rows


def embedded_header_count(path: Path) -> int:
    """Count data rows that are actually a repeated CSV header.

    All columns are read as plain strings (infer_schema_length=0 forces this
    in polars, so a header token in a numeric column position never raises).
    A header row shows up as an ordinary string row whose last column equals,
    literally, the name of that column ("Label") -- which no real flow label
    ever is. Confirmed against the Infiltration file (26 occurrences via
    `grep -c "^Dst Port"` during the preflight investigation); this measures
    it precisely instead of by hand.
    """
    lf = pl.scan_csv(path, infer_schema_length=0, has_header=True)
    label_col = lf.collect_schema().names()[-1]
    return int(
        lf.filter(pl.col(label_col) == label_col).select(pl.len()).collect().item()
    )


def raw_infinities(path: Path) -> dict[str, int]:
    """Infinite values in the rate columns *before* load_csv's `_clean_data`
    zeroes them -- so the data-quality section reports what CICFlowMeter
    actually emitted (division by zero on zero-duration flows), not what the
    cleaned pipeline shows downstream."""
    overrides = _numeric_schema_overrides(path)
    lf = pl.scan_csv(
        path, infer_schema_length=10000, ignore_errors=True, schema_overrides=overrides
    )
    lf = _normalize_columns(_strip_columns(lf))
    names = lf.collect_schema().names()
    cols = [c for c in ("flow_byts_per_s", "flow_pkts_per_s") if c in names]
    if not cols:
        return {}
    result = lf.select([pl.col(c).is_infinite().sum().alias(c) for c in cols]).collect()
    row = result.row(0, named=True)
    return {c: int(row[c]) for c in cols}


# --------------------------------------------------------------- numeric summary
def numeric_summary(path: Path) -> pl.DataFrame:
    """One row per CLASSIC_FEATURES column: count/null/mean/std/quantiles/max.

    A single lazy `.select` over the whole (cleaned) file -- one pass,
    ~9 aggregations per column, never a materialized 84-column frame.
    """
    lf = load_csv(path)
    names = lf.collect_schema().names()
    cols = [c for c in CLASSIC_FEATURES if c in names]

    aggs = []
    for c in cols:
        aggs += [
            pl.col(c).count().alias(f"{c}__count"),
            pl.col(c).null_count().alias(f"{c}__null"),
            pl.col(c).mean().alias(f"{c}__mean"),
            pl.col(c).std().alias(f"{c}__std"),
            pl.col(c).min().alias(f"{c}__min"),
            pl.col(c).median().alias(f"{c}__p50"),
            pl.col(c).quantile(0.90).alias(f"{c}__p90"),
            pl.col(c).quantile(0.99).alias(f"{c}__p99"),
            pl.col(c).max().alias(f"{c}__max"),
        ]
    row = lf.select(aggs).collect().row(0, named=True)

    records = []
    for c in cols:
        std = row[f"{c}__std"]
        null_count = row[f"{c}__null"]
        count = row[f"{c}__count"]
        null_rate = (null_count / count) if count else 1.0
        records.append({
            "feature": c,
            "directional": ("fwd" in c or "bwd" in c),
            "count": count,
            "null_count": null_count,
            "null_rate": null_rate,
            "mean": row[f"{c}__mean"],
            "std": std,
            "min": row[f"{c}__min"],
            "p50": row[f"{c}__p50"],
            "p90": row[f"{c}__p90"],
            "p99": row[f"{c}__p99"],
            "max": row[f"{c}__max"],
            "degenerate": bool((std is not None and std == 0.0) or null_rate > 0.99),
        })
    return pl.DataFrame(records)


# --------------------------------------------------------------- correlation
def sampled_classic_matrix(
    path: Path, cols: list[str], sample_n: int = 750_000
) -> tuple[np.ndarray, int]:
    """Deterministic systematic sample (every k-th row) of CLASSIC_FEATURES.

    No RNG, no seed to record: the same file always yields the same sample.
    Still a single lazy pass -- the filter is evaluated while scanning, so the
    full 84-column frame is never materialized, only the ~sample_n x len(cols)
    result.
    """
    lf = load_csv(path)
    total = lf.select(pl.len()).collect().item()
    stride = max(total // sample_n, 1)
    sampled = (
        lf.with_row_index("row_nr")
        .filter(pl.col("row_nr") % stride == 0)
        .select(cols)
        # A handful of rows carry a genuine null in every CLASSIC_FEATURES
        # column -- the residual of an embedded duplicate header row (see
        # src/ingest/loader.py::_numeric_schema_overrides): _clean_data()
        # zeroes infinities/NaNs but leaves true nulls as nulls. A single NaN
        # anywhere poisons every pairwise entry of np.corrcoef's output, so
        # these rows must not reach the correlation matrix.
        .drop_nulls()
        .collect()
    )
    return sampled.to_numpy().astype(np.float64), stride


# --------------------------------------------------------------- per-flow AUC
def perflow_auc(path: Path) -> dict:
    """Real-data equivalent of scripts/validate_claims.py::claim_perflow_auc,
    which measured AUC 0.998 (PortScan) / 0.946 (DDoS) on the *simulator*.
    Same formula (log-ratio of forward/backward byte totals), real flows."""
    from sklearn.metrics import roc_auc_score

    df = (
        load_csv(path)
        .select(["is_attack", "totlen_fwd_pkts", "totlen_bwd_pkts"])
        .drop_nulls()
        .collect()
    )
    y = df["is_attack"].to_numpy()
    fwd = np.log1p(df["totlen_fwd_pkts"].to_numpy())
    bwd = np.log1p(df["totlen_bwd_pkts"].to_numpy())
    ratio = fwd - bwd

    attack_rate = float(y.mean())
    auc = float(roc_auc_score(y, ratio)) if 0.0 < attack_rate < 1.0 else None
    return {"n_flows": len(df), "attack_rate": attack_rate, "auc": auc}


# --------------------------------------------------- Phase 0 sweep + current pipeline
def phase0_and_current_pipeline(
    path: Path,
    windows: tuple[int, ...] = (10, 30, 60, 120, 300),
    taus: tuple[float, ...] = (0.01, 0.05, 0.1),
) -> dict:
    """Grid over (window_seconds, tau) using `src.features.windows.window_features`
    -- the project's *current* pipeline (docs/metodologia/REPLANTEO-OPERACIONAL.md,
    H2), not the retired src/graphs + src/iag/index.py index. This is the first
    time this pipeline has run against real data.

    At the default config (60s, tau=0.01) also reports the window-level AUC of
    every topology/per-flow/size feature against the label -- descriptive only:
    with as few as tens of positive windows this is far below the >=250/class
    power the project's own preregistration requires, and must not be read as a
    confirmatory H2 result.
    """
    needed = ["timestamp", "src_ip", "dst_ip", "is_attack", "totlen_fwd_pkts", "totlen_bwd_pkts"]
    flows = load_csv(path).select(needed).drop_nulls().collect()

    grid = []
    default_rows = None
    for w in windows:
        for tau in taus:
            rows = window_features(flows, tier=InfoTier.DIRECTIONAL, window_seconds=w, tau=tau)
            n = len(rows)
            n_pos = int(rows["y"].sum()) if n else 0
            n_neg = n - n_pos
            ratios = rows["attack_ratio"].to_numpy() if n else np.array([])
            mid = float(((ratios > 0.02) & (ratios < 0.98)).mean()) if n else 0.0
            grid.append({
                "window_s": w, "tau": tau, "n_windows": n, "n_pos": n_pos, "n_neg": n_neg,
                "mid_fraction": mid,
                "meets_criterion_3_n250": min(n_pos, n_neg) >= 250,
                "meets_criterion_4_spans_tau": mid >= 0.10,
            })
            if w == 60 and abs(tau - 0.01) < 1e-9:
                default_rows = rows

    window_level_auc: dict[str, float] = {}
    n_windows_default = len(default_rows) if default_rows is not None else 0
    n_pos_default = int(default_rows["y"].sum()) if default_rows is not None else 0
    if default_rows is not None and 0 < n_pos_default < n_windows_default:
        from sklearn.metrics import roc_auc_score

        y = default_rows["y"].to_numpy()
        for col in (*TOPOLOGY_FEATURES, *PERFLOW_FEATURES, *SIZE_FEATURES):
            if col in default_rows.columns:
                vals = default_rows[col].to_numpy()
                if np.isfinite(vals).all() and vals.std() > 0:
                    window_level_auc[col] = float(roc_auc_score(y, vals))

    return {
        "grid": grid,
        "n_windows_default": n_windows_default,
        "n_pos_default": n_pos_default,
        "window_level_auc_default_config": window_level_auc,
        "power_warning": (
            f"n_pos={n_pos_default} at the default config is far below the >=250/class "
            "power requirement in docs/metodologia/README.md -- these AUCs are descriptive, "
            "not a confirmatory H2 test."
        ),
    }


# ------------------------------------------------------------------- figures
def make_figures(path: Path, tag: str) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.viz.plots import setup_style

    setup_style()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    saved = []

    df = load_csv(path).select(
        ["is_attack", "flow_duration", "totlen_fwd_pkts", "totlen_bwd_pkts"]
    ).drop_nulls().collect()

    fig, ax = plt.subplots()
    dur = df["flow_duration"].to_numpy()
    dur = dur[dur > 0]
    ax.hist(np.log10(dur + 1), bins=60, color="#2196F3", alpha=0.85)
    ax.set_xlabel("log10(flow_duration + 1) [microseconds]")
    ax.set_ylabel("count")
    ax.set_title(f"flow_duration distribution -- {tag}")
    p = FIGURES_DIR / f"real_data_{tag}_flow_duration.png"
    fig.savefig(p, dpi=200, bbox_inches="tight")
    plt.close(fig)
    saved.append(str(p))

    y = df["is_attack"].to_numpy()
    if 0 < y.mean() < 1:
        fwd = np.log1p(df["totlen_fwd_pkts"].to_numpy())
        bwd = np.log1p(df["totlen_bwd_pkts"].to_numpy())
        ratio = fwd - bwd
        fig, ax = plt.subplots()
        ax.hist(ratio[y == 0], bins=60, alpha=0.6, density=True, label="Benign", color="#2196F3")
        ax.hist(ratio[y == 1], bins=60, alpha=0.6, density=True, label="Attack", color="#F44336")
        ax.set_xlabel("log(1+fwd bytes) - log(1+bwd bytes)")
        ax.set_ylabel("density")
        ax.set_title(f"Per-flow asymmetry ratio, real data -- {tag}")
        ax.legend()
        p = FIGURES_DIR / f"real_data_{tag}_perflow_ratio.png"
        fig.savefig(p, dpi=200, bbox_inches="tight")
        plt.close(fig)
        saved.append(str(p))

    return saved


def make_correlation_heatmap(matrix: np.ndarray, cols: list[str], tag: str) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    corr = np.corrcoef(matrix, rowvar=False)
    fig, ax = plt.subplots(figsize=(14, 12))
    im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(cols)))
    ax.set_yticks(range(len(cols)))
    ax.set_xticklabels(cols, rotation=90, fontsize=6)
    ax.set_yticklabels(cols, fontsize=6)
    fig.colorbar(im, ax=ax, shrink=0.8)
    ax.set_title(f"CLASSIC_FEATURES correlation, real data -- {tag}")
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    p = FIGURES_DIR / f"real_data_{tag}_correlation.png"
    fig.tight_layout()
    fig.savefig(p, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return str(p)


# ------------------------------------------------------------------------ main
def analyze_file(path: Path, has_ips: bool) -> dict:
    tag = path.stem.split("_")[0].lower()
    _header(f"Analyzing {path.name}")
    t0 = time.time()

    result: dict = {"file": path.name, "has_ips": has_ips}

    _log("describing columns")
    result["columns"] = describe_columns(path)

    _log("counting embedded duplicate header rows")
    result["embedded_header_rows"] = embedded_header_count(path)

    _log("measuring raw infinities before cleaning")
    result["raw_infinities"] = raw_infinities(path)

    _log("computing numeric summary (single lazy pass)")
    summary = numeric_summary(path)
    result["numeric_summary"] = summary.to_dicts()
    result["n_directional_classic_features"] = int(summary["directional"].sum())
    result["n_classic_features"] = len(summary)
    result["degenerate_features"] = summary.filter(pl.col("degenerate"))["feature"].to_list()

    _log("computing per-flow asymmetry AUC (real data)")
    result["perflow_auc"] = perflow_auc(path)

    _log("sampling for correlation / redundancy (systematic, no RNG)")
    cols = summary.filter(~pl.col("degenerate"))["feature"].to_list()
    matrix, stride = sampled_classic_matrix(path, cols)
    index_groups = correlation_groups(matrix, feature_names=cols, threshold=0.80)
    named_groups = [[cols[i] for i in g] for g in index_groups]
    result["correlation_sample"] = {
        "n_rows_sampled": matrix.shape[0], "stride": stride,
        "redundancy_groups_at_0.80": [g for g in named_groups if len(g) > 1],
        "n_redundant_groups": sum(1 for g in named_groups if len(g) > 1),
    }

    _log("generating figures")
    result["figures"] = make_figures(path, tag)
    result["figures"].append(make_correlation_heatmap(matrix, cols, tag))

    if has_ips:
        _log("running Phase 0 sweep + current pipeline (window_features)")
        result["phase0_and_pipeline"] = phase0_and_current_pipeline(path)

    result["elapsed_seconds"] = round(time.time() - t0, 1)
    _log(f"done in {result['elapsed_seconds']}s")
    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("path", type=Path, help="CSV file or directory of CSVs (data/raw/)")
    args = ap.parse_args()

    paths = sorted(args.path.glob("*.csv")) if args.path.is_dir() else [args.path]
    if not paths:
        print(f"no CSV files found under {args.path}")
        return 2

    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    all_results = []
    for p in paths:
        with p.open(encoding="utf-8", errors="replace") as fh:
            header_cols = {c.strip() for c in fh.readline().split(",")}
        has_ips = {"Src IP", "Dst IP"} <= header_cols
        all_results.append(analyze_file(p, has_ips))

    out_path = METRICS_DIR / "real_data_summary.json"
    out_path.write_text(json.dumps(all_results, indent=2, default=str))
    _header("Done")
    print(f"{GREEN}Summary written to {out_path}{NC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
