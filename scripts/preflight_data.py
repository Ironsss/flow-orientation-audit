#!/usr/bin/env python3
"""
Preflight check for a real CICIDS-2018 capture, before committing to a full run.

Run this on ONE file before downloading the rest of the dataset. It answers, in
about a minute, the questions that otherwise surface after tens of gigabytes and
several hours:

  1. Does this file carry Src IP / Dst IP? Without them the graph pipeline
     cannot run at all -- build_temporal_graphs() raises ValueError. Most of the
     "Processed Traffic Data for ML Algorithms" CSVs distributed for
     CSE-CIC-IDS2018 start at `Dst Port` and have no IP columns whatsoever.
     This is the single most likely way for this project to lose a week.
  2. How many of the 49 CLASSIC_FEATURES are actually present?
  3. Does the timestamp parse?
  4. What is the class balance, and does it produce a usable label?
  5. Do the resulting windows satisfy the Phase 0 acceptance criteria fixed in
     docs/metodologia/ -- enough windows per class, and an attack_ratio
     distribution that actually spans the labelling threshold rather than
     sitting at 0 or 1?

Check 5 is the point. The pre-registration states five criteria the data must
meet before the experiment is worth running; this script evaluates the three of
them that are properties of the data (the other two are properties of the
experimental design). A dataset that fails them is not a dataset to run on, and
knowing that early is worth more than any partial result.

Usage
-----
    python scripts/preflight_data.py path/to/one_file.csv
    python scripts/preflight_data.py data/raw/              # whole directory
    python scripts/preflight_data.py file.csv --window 60 --tau 0.01

Exit codes
----------
    0  usable for the pre-registered experiment
    1  usable for ingestion but NOT for the graph pipeline (no IP columns)
    2  unusable (cannot parse, no label, or no usable windows)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ingest.loader import CLASSIC_FEATURES  # noqa: E402

GREEN, YELLOW, RED, BLUE, BOLD, NC = (
    "\033[0;32m", "\033[1;33m", "\033[0;31m", "\033[0;34m", "\033[1m", "\033[0m",
)


def ok(msg: str) -> None:
    print(f"{GREEN}[PASS]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC} {msg}")


def fail(msg: str) -> None:
    print(f"{RED}[FAIL]{NC} {msg}")


def info(msg: str) -> None:
    print(f"{BLUE}[INFO]{NC} {msg}")


def header(msg: str) -> None:
    print(f"\n{BOLD}{msg}{NC}\n{'-' * len(msg)}")


def _csv_paths(target: Path) -> list[Path]:
    if target.is_dir():
        return sorted(target.glob("*.csv"))
    return [target]


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("path", type=Path, help="CSV file or directory of CSVs")
    ap.add_argument("--window", type=int, default=60, help="window seconds (default 60)")
    ap.add_argument(
        "--tau", type=float, default=0.01, help="attack_ratio label threshold (default 0.01)"
    )
    ap.add_argument("--max-rows", type=int, default=2_000_000,
                    help="rows to read for the window analysis (default 2e6)")
    args = ap.parse_args()

    if not args.path.exists():
        fail(f"path does not exist: {args.path}")
        return 2

    paths = _csv_paths(args.path)
    if not paths:
        fail(f"no .csv files found under {args.path}")
        return 2

    header(f"Preflight: {args.path}")
    info(f"{len(paths)} CSV file(s); inspecting {paths[0].name}")

    # ---------------------------------------------------------------- headers
    header("1. Column schema")
    try:
        with paths[0].open(encoding="utf-8", errors="replace") as fh:
            raw_cols = fh.readline().rstrip("\n\r").split(",")
    except Exception as exc:  # noqa: BLE001 - report any parse failure verbatim
        fail(f"cannot read the CSV header: {type(exc).__name__}: {exc}")
        return 2

    stripped = {c.strip() for c in raw_cols}
    info(f"{len(raw_cols)} columns; first: {', '.join(list(stripped)[:4])}")

    has_ips = {"Src IP", "Dst IP"} <= stripped
    if has_ips:
        ok("Src IP and Dst IP present -- the graph pipeline can run")
    else:
        fail("Src IP / Dst IP MISSING -- build_temporal_graphs() will raise ValueError")
        print(
            f"""
  {BOLD}This is the blocker to resolve before anything else.{NC}

  Most CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" CSVs begin at
  `Dst Port` and carry no addresses, so every graph-based part of this project
  is inapplicable to them as distributed. Options, in the order worth trying:

    (a) Use the day(s) that do carry addresses. At least one file in the
        released set has the wider schema (Flow ID, Src IP, Src Port, Dst IP).
        Check every file before concluding -- schemas are not uniform.
    (b) Regenerate flows from the raw PCAPs with CICFlowMeter configured to keep
        addresses. Most faithful, and the most work; the PCAPs are large.
    (c) Use a dataset that ships addresses (e.g. UNSW-NB15, CIC-IDS2017) and
        state the change of dataset explicitly in the paper.
    (d) Restrict the project to per-flow asymmetry, which needs no graph and is
        where the measured signal already lives.

  Option (d) deserves a hard look before (b): the repository has already
  measured per-flow asymmetry at AUC 0.998 / 0.946 against a graph pipeline that
  contributed nothing, so paying for PCAP reprocessing to rebuild graphs is
  buying back the component the evidence retired.
"""
        )

    # The loader renames; count by checking the rename targets actually present.
    from src.ingest.loader import COLUMN_RENAME

    renamed = {COLUMN_RENAME[c] for c in stripped if c in COLUMN_RENAME}
    present = [c for c in CLASSIC_FEATURES if c in renamed]
    n_classic = len(present)
    if n_classic >= 40:
        ok(f"{n_classic}/{len(CLASSIC_FEATURES)} CLASSIC_FEATURES present")
    elif n_classic >= 10:
        warn(f"only {n_classic}/{len(CLASSIC_FEATURES)} CLASSIC_FEATURES present")
    else:
        fail(f"only {n_classic}/{len(CLASSIC_FEATURES)} CLASSIC_FEATURES present")

    if not has_ips:
        info("stopping here: without IP columns the remaining checks cannot run")
        return 1

    # ------------------------------------------------------------- ingestion
    header("2. Ingestion and labels")
    from src.ingest.loader import load_csv

    try:
        df = load_csv(paths[0]).head(args.max_rows).collect()
    except Exception as exc:  # noqa: BLE001
        fail(f"load_csv failed: {type(exc).__name__}: {exc}")
        return 2
    ok(f"loaded {len(df):,} rows")

    if "timestamp" not in df.columns or df["timestamp"].null_count() == len(df):
        fail("timestamp missing or entirely unparsed")
        return 2
    nulls = df["timestamp"].null_count()
    if nulls:
        warn(f"{nulls:,} rows ({nulls / len(df):.1%}) have an unparsed timestamp")
    else:
        ok("timestamp parsed for every row")

    if "is_attack" not in df.columns:
        fail("no is_attack column -- the Label column did not map")
        return 2
    rate = float(df["is_attack"].mean())
    info(f"flow-level attack rate: {rate:.2%}")
    if rate in (0.0, 1.0):
        fail("only one class present in this file -- cannot be used alone")
        return 2
    ok("both classes present at flow level")

    # --------------------------------------------------------------- windows
    header("3. Phase 0 acceptance criteria (docs/metodologia/)")
    ts = df["timestamp"].dt.epoch("s").to_numpy()
    bucket = (ts // args.window) * args.window
    per_window = (
        df.with_columns(pl.Series("w", bucket))
        .group_by("w")
        .agg(pl.col("is_attack").mean().alias("ratio"), pl.len().alias("n"))
        .filter(pl.col("n") >= 5)
    )
    n_windows = len(per_window)
    if n_windows == 0:
        fail("no windows with at least 5 flows")
        return 2

    ratios = per_window["ratio"].to_numpy()
    n_pos = int((ratios >= args.tau).sum())
    n_neg = n_windows - n_pos
    info(
        f"{n_windows:,} windows of {args.window}s "
        f"({n_pos:,} positive / {n_neg:,} negative at tau={args.tau})"
    )

    verdict = 0

    # criterion: >=250 windows per class
    if min(n_pos, n_neg) >= 250:
        ok(f"criterion 'n >= 250 per class': met (min class = {min(n_pos, n_neg):,})")
    else:
        fail(f"criterion 'n >= 250 per class': NOT met (min class = {min(n_pos, n_neg):,})")
        info(
            "      several days concatenated may suffice -- re-run on the directory"
        )
        verdict = max(verdict, 1)

    # criterion: attack_ratio spans the threshold rather than piling at 0 or 1
    mid = float(((ratios > 0.02) & (ratios < 0.98)).mean())
    if mid >= 0.10:
        ok(f"criterion 'attack_ratio spans tau': met ({mid:.1%} of windows are partial)")
    else:
        fail(
            f"criterion 'attack_ratio spans tau': NOT met "
            f"(only {mid:.1%} partial; the rest are ~0 or ~1)"
        )
        info(
            "      a degenerate ratio means the label is nearly a run identifier,"
            " which is how"
        )
        info("      this project produced a confounded AUC of 1.0 on simulated data")
        verdict = max(verdict, 1)

    # criterion: positives and negatives coexist within the same capture (C2)
    if n_pos > 0 and n_neg > 0:
        ok("criterion C2 'within-run positives and negatives': met (same capture)")
        info(
            "      real captures satisfy C2 for free"
            " -- this was the control the simulator violated"
        )
    else:
        fail("criterion C2: one class absent")
        verdict = 2

    header("Verdict")
    if verdict == 0:
        ok(
            "this data satisfies the data-side Phase 0 criteria; "
            "the experiment can be designed against it"
        )
    elif verdict == 1:
        warn(
            "usable, but at least one Phase 0 criterion is unmet "
            "-- re-run on more days before concluding"
        )
    else:
        fail("not usable as-is")
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
