#!/usr/bin/env python3
"""H2 real data -- re-run with canonical windowing, as an independent check
of the synthetic result (docs/methodology/H2_SYNTHETIC_FINDINGS.md: H2
REJECTED).

`experiments/04_restriction.py --data-path ...` already ran this once (PR
#24, docs/datos-reales/ANALISIS-DATOS-REALES.tex Sec. "H2 bajo restriccion")
against the one real CICIDS-2018 file with Src/Dst IP columns
(Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv, a DDoS-LOIC-HTTP
capture -- still the only IP-bearing file among all 10; no second capture
exists). That run used the pre-P0.5 windowing (src.features.windows.window_
features, which re-derives window boundaries from each restricted frame's
own ts.min() -- the exact anchor-drift bug P0.5 was built to fix). Result:
at window_seconds=10 the power gate (>=250 windows/class) cleared for the
first time, but the per-flow baseline saturated (0.977-1.000,
SATURATION_LIMIT=0.90), blocking a certified verdict; the raw/uncertified
pattern across all 16 combinations never showed topology beating per-flow.

This script re-runs the same 8 levels (4 sampling + 4 truncation) at the
same two window sizes (60s, 10s -- for exact diffability against the old
table), using src.audit.canonical (P0.5's anchor-fixed windowing) and the
paired bootstrap 95% CI scripts/run_h2_synthetic.py introduced, changing
only the measuring instrument. experiments/04_restriction.py itself is
untouched -- it is the pre-registered experiment; its old real-data row
stays as the "before" side of the diff in the write-up.

Ordering, and why it matters (the one substantive difference from
scripts/run_h2_synthetic.py, which only ever sees full untouched simulated
runs): src.restriction.operators.truncate() computes its window phase from
ts.min() of whatever frame it is given. For one real trace split by time,
applying truncate() AFTER the temporal train/test split would desync the
test split's truncation phase from the canonical grid's anchor -- a second
anchor-drift bug, distinct from the one src.audit.canonical already fixes.
So:
    truncation axis: truncate() the full untouched trace FIRST (so its
        internal ts.min() still equals the canonical grid's global_t0),
        THEN split the truncated rows at the boundary.
    sampling axis: split first, THEN sample() each split independently
        (sample() has no timestamp dependency, so this ordering is safe --
        matches PR #24's existing convention of independent sampling seeds
        per split).

Most cells here are expected to stay gate-blocked (this is real, imbalanced,
single-file data, not a validated synthetic instrument) -- this script
never computes a single top-level verdict the way run_h2_synthetic.py does.
It reports delta + bootstrap CI for every cell, both gate checks
(MIN_WINDOWS_PER_CLASS, SATURATION_LIMIT), and prints a certified
REJECTED/SUPPORTED/CONFOUNDED line ONLY for cells that clear both gates --
every other cell gets the same "GATE FAILED -- no verdict, raw numbers
written for inspection" honesty block experiments/04_restriction.py already
uses.

Usage
-----
    .venv/Scripts/python.exe scripts/run_h2_real.py
    .venv/Scripts/python.exe scripts/run_h2_real.py --window-seconds 10
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.audit.canonical import (  # noqa: E402
    CanonicalWindowing,
    build_canonical_windowing,
    canonical_window_features,
)
from src.features import InfoTier  # noqa: E402
from src.features.extractors import PERFLOW_FEATURES, SIZE_FEATURES, TOPOLOGY_FEATURES  # noqa: E402
from src.ingest.loader import load_csv  # noqa: E402
from src.restriction import sample, truncate  # noqa: E402

TAU = 0.01
MIN_FLOWS = 10
DELTA_THRESHOLD = 0.05  # matches experiments/04_restriction.py
N_BOOTSTRAP = 2000
BOOTSTRAP_SEED = 0
MIN_WINDOWS_PER_CLASS = 250  # matches experiments/04_restriction.py's gate
SATURATION_LIMIT = 0.90  # matches experiments/04_restriction.py's gate
TRAIN_FRACTION = 0.70
WINDOW_SECONDS_LEVELS = (60, 10)  # matches the old table exactly, for diffability
SAMPLING_LEVELS = [(1, "1:1"), (10, "1:10"), (100, "1:100"), (1000, "1:1000")]
TRUNCATION_LEVELS = [(1 / 60, "1s"), (5 / 60, "5s"), (10 / 60, "10s"), (1.0, "60s")]
SAMPLE_SEED_TRAIN = 1  # matches PR #24's real-data convention
SAMPLE_SEED_TEST = 11
DEFAULT_DATA_PATH = REPO_ROOT / "data/raw/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"


def _load_real(path: Path) -> pl.DataFrame:
    """Real flows, only the columns downstream code touches. Verbatim port
    of experiments/04_restriction.py::_load_real -- duplicated, not
    imported (this repo's existing convention: run_h2_synthetic.py and
    experiments/04_restriction.py each already duplicate this kind of small
    helper independently rather than share a module)."""
    cols = ["timestamp", "src_ip", "dst_ip", "is_attack", "totlen_fwd_pkts", "totlen_bwd_pkts"]
    return load_csv(path).select(cols).drop_nulls().collect()


def split_timestamp(cw: CanonicalWindowing, train_fraction: float = TRAIN_FRACTION) -> int:
    """Epoch-second boundary between train and test, aligned to a canonical
    window edge so no single window's flows are split across the two sets.

    Deliberately not src.models.benchmark.temporal_split: that function cuts
    by raw row index after sorting, which is not window-aware and can bisect
    a window's rows between train and test. The cut here is exactly
    cw.window_start[split_idx] -- a genuine grid boundary by construction of
    build_canonical_windowing.
    """
    split_idx = min(max(round(cw.n_windows * train_fraction), 1), cw.n_windows - 1)
    return int(cw.window_start[split_idx])


def temporal_row_split(
    df: pl.DataFrame, split_ts: int, timestamp_col: str = "timestamp",
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Rows before split_ts -> train, at/after -> test. Row-level, but safe
    because split_ts is a window boundary (see split_timestamp)."""
    epoch = df[timestamp_col].dt.epoch("s")
    return df.filter(epoch < split_ts), df.filter(epoch >= split_ts)


def fit_and_score(train: pl.DataFrame, test: pl.DataFrame, cols: list[str]):
    from sklearn.ensemble import RandomForestClassifier

    cols = [c for c in cols if c in train.columns]
    ytr, yte = train["y_gt"].to_numpy(), test["y_gt"].to_numpy()
    if not cols or len(set(ytr.tolist())) < 2 or len(set(yte.tolist())) < 2:
        return None, yte
    model = RandomForestClassifier(
        n_estimators=300, random_state=0, class_weight="balanced"
    ).fit(train[cols].to_numpy(), ytr)
    return model.predict_proba(test[cols].to_numpy())[:, 1], yte


def auc(y: np.ndarray, score: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score

    if score is None or len(set(y.tolist())) < 2:
        return float("nan")
    return float(roc_auc_score(y, score))


def bootstrap_ci_delta(
    y: np.ndarray, score_a: np.ndarray, score_b: np.ndarray, *, n: int = N_BOOTSTRAP,
) -> tuple[float, float]:
    """95% CI on AUC(a) - AUC(b), paired resampling of (y, score_a, score_b)
    -- same method as scripts/run_h2_synthetic.py."""
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    n_rows = len(y)
    deltas = np.empty(n)
    for i in range(n):
        idx = rng.integers(0, n_rows, size=n_rows)
        yb = y[idx]
        if len(set(yb.tolist())) < 2:
            deltas[i] = np.nan
            continue
        deltas[i] = auc(yb, score_a[idx]) - auc(yb, score_b[idx])
    deltas = deltas[np.isfinite(deltas)]
    if deltas.size == 0:
        return float("nan"), float("nan")
    return float(np.percentile(deltas, 2.5)), float(np.percentile(deltas, 97.5))


def run_level(
    axis: str, level: float, label: str, window_seconds: int, cw: CanonicalWindowing,
    real_df: pl.DataFrame, split_ts: int,
) -> dict:
    if axis == "sampling":
        train_rows, test_rows = temporal_row_split(real_df, split_ts)
        train_rows = sample(train_rows, rate=int(level), seed=SAMPLE_SEED_TRAIN)
        test_rows = sample(test_rows, rate=int(level), seed=SAMPLE_SEED_TEST)
    else:
        truncated = truncate(real_df, window_seconds=window_seconds, observed_fraction=level)
        train_rows, test_rows = temporal_row_split(truncated, split_ts)

    train = canonical_window_features(
        train_rows, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS
    ).filter(pl.col("feature_available"))
    test = canonical_window_features(
        test_rows, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS
    ).filter(pl.col("feature_available"))
    # Train/test temporal separation is enforced by construction: a train
    # frame restricted to train_rows has zero surviving rows in any
    # test-period window (and vice versa), so feature_available already
    # excludes them -- no explicit window-id partitioning needed here.

    n_atk = int(test["y_gt"].sum()) if len(test) else 0
    n_ben = len(test) - n_atk

    score_topo, y_topo = fit_and_score(train, test, list(TOPOLOGY_FEATURES))
    score_flow, y_flow = fit_and_score(train, test, list(PERFLOW_FEATURES))
    score_comb, _ = fit_and_score(train, test, list(TOPOLOGY_FEATURES) + list(PERFLOW_FEATURES))
    score_size, _ = fit_and_score(train, test, list(SIZE_FEATURES))

    auc_topo, auc_flow = auc(y_topo, score_topo), auc(y_flow, score_flow)
    auc_comb, auc_size = auc(y_topo, score_comb), auc(y_topo, score_size)

    ci_lo = ci_hi = float("nan")
    if score_topo is not None and score_flow is not None:
        ci_lo, ci_hi = bootstrap_ci_delta(y_topo, score_topo, score_flow)

    # Exploratory only -- see scripts/run_h2_synthetic.py's identical caveat.
    ci_comb_lo = ci_comb_hi = float("nan")
    if score_comb is not None and score_flow is not None:
        ci_comb_lo, ci_comb_hi = bootstrap_ci_delta(y_topo, score_comb, score_flow)

    gate_failures = []
    if min(n_atk, n_ben) < MIN_WINDOWS_PER_CLASS:
        gate_failures.append(f"power ({min(n_atk, n_ben)}<{MIN_WINDOWS_PER_CLASS})")
    if np.isfinite(auc_flow) and auc_flow > SATURATION_LIMIT:
        gate_failures.append(f"saturation ({auc_flow:.4f}>{SATURATION_LIMIT})")
    gate = "+".join(gate_failures) if gate_failures else "OK"

    return {
        "axis": axis, "level": label, "window_seconds": window_seconds,
        "n_attack": n_atk, "n_benign": n_ben,
        "topology": auc_topo, "perflow": auc_flow, "combined": auc_comb, "size": auc_size,
        "delta": auc_topo - auc_flow, "ci_lo": ci_lo, "ci_hi": ci_hi,
        "delta_combined_vs_perflow": auc_comb - auc_flow,
        "ci_combined_lo": ci_comb_lo, "ci_combined_hi": ci_comb_hi,
        "gate": gate, "gate_failures": gate_failures,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--data-path", type=Path, default=DEFAULT_DATA_PATH)
    ap.add_argument(
        "--window-seconds", type=int, nargs="+", default=list(WINDOW_SECONDS_LEVELS),
    )
    ap.add_argument(
        "--json", type=Path, default=REPO_ROOT / "results/metrics/h2_real_canonical.json",
    )
    args = ap.parse_args()

    print(f"Loading real data from {args.data_path} ...")
    real_df = _load_real(args.data_path)
    print(f"{len(real_df):,} rows loaded.")

    all_rows: list[dict] = []
    split_ts_by_window: dict[int, int] = {}
    for window_seconds in args.window_seconds:
        print(f"\n{'#'*90}\nWINDOW_SECONDS = {window_seconds}\n{'#'*90}")
        cw = build_canonical_windowing(real_df, window_seconds=window_seconds, tau=TAU)
        split_ts = split_timestamp(cw)
        split_ts_by_window[window_seconds] = split_ts
        train_rows, test_rows = temporal_row_split(real_df, split_ts)
        print(f"n_windows={cw.n_windows}  split_ts={split_ts}  "
              f"train_rows={len(train_rows):,}  test_rows={len(test_rows):,}")

        print(
            f"\n{'level':>10}{'topology':>11}{'per-flow':>11}"
            f"{'combined':>11}{'C1 size':>10}{'n_atk/n_ben':>14}{'gate':>22}"
        )
        print("-" * 90)
        for axis, levels in (("sampling", SAMPLING_LEVELS), ("truncation", TRUNCATION_LEVELS)):
            for level, label in levels:
                row = run_level(axis, level, label, window_seconds, cw, real_df, split_ts)
                all_rows.append(row)
                n_atk_ben = f"{row['n_attack']}/{row['n_benign']}"
                print(
                    f"{axis[:4]}/{label:>5}{row['topology']:>11.4f}{row['perflow']:>11.4f}"
                    f"{row['combined']:>11.4f}{row['size']:>10.4f}"
                    f"{n_atk_ben:>14}{row['gate']:>22}"
                )

    return _report(all_rows, args, split_ts_by_window)


def _report(rows: list[dict], args, split_ts_by_window: dict[int, int]) -> int:
    print(
        f"\n{'='*90}\nBOOTSTRAP 95% CI on paired delta (topology - per-flow), "
        f"N={N_BOOTSTRAP}\n{'='*90}"
    )
    for r in rows:
        print(f"  w={r['window_seconds']:>3} {r['axis']:>10} {r['level']:>5}: "
              f"delta={r['delta']:+.4f}  95% CI=[{r['ci_lo']:+.4f}, {r['ci_hi']:+.4f}]  "
              f"gate={r['gate']}")

    print(
        f"\n{'='*90}\nEXPLORATORY (post-hoc, not the H2 decision rule): "
        f"bootstrap 95% CI on paired delta (combined - per-flow), N={N_BOOTSTRAP}\n{'='*90}"
    )
    for r in rows:
        print(f"  w={r['window_seconds']:>3} {r['axis']:>10} {r['level']:>5}: "
              f"delta={r['delta_combined_vs_perflow']:+.4f}  "
              f"95% CI=[{r['ci_combined_lo']:+.4f}, {r['ci_combined_hi']:+.4f}]")

    print(f"\n{'='*90}\nPER-CELL VERDICT (only where both gates clear)\n{'='*90}")
    any_certified = False
    for r in rows:
        if r["gate"] != "OK":
            print(f"  w={r['window_seconds']:>3} {r['axis']:>10} {r['level']:>5}: "
                  f"GATE FAILED ({r['gate']}) -- no verdict, raw numbers only")
            continue
        any_certified = True
        ci_excludes_zero = r["ci_lo"] > 0 or r["ci_hi"] < 0
        if r["delta"] < DELTA_THRESHOLD:
            verdict = "REJECTED"
        elif not ci_excludes_zero:
            verdict = "REJECTED (CI includes 0)"
        elif (r["size"] - 0.5) > 0.5 * (r["topology"] - 0.5):
            verdict = "CONFOUNDED (C1 explains most of the lift)"
        else:
            verdict = "SUPPORTED"
        print(f"  w={r['window_seconds']:>3} {r['axis']:>10} {r['level']:>5}: "
              f"delta={r['delta']:+.4f} CI=[{r['ci_lo']:+.4f},{r['ci_hi']:+.4f}] -> {verdict}")

    if not any_certified:
        print(
            "\nGATE FAILED at every level -- no verdict on H2 is reported from real data.\n"
            "This is the sixth-plus time this project's instruments have blocked a\n"
            "measurement (CLAUDE.md) -- a baseline near saturation leaves no headroom for\n"
            "any treatment to win in. The raw, uncertified numbers above are written for\n"
            "inspection; see docs/datos-reales/ANALISIS-DATOS-REALES.tex for the honest\n"
            "reading of the pattern they show."
        )

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps({
        "data_path": str(args.data_path), "tau": TAU,
        "window_seconds_levels": list(split_ts_by_window),
        "split_ts_by_window": split_ts_by_window,
        "rows": rows,
    }, indent=2, default=str))
    print(f"\nResults written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
