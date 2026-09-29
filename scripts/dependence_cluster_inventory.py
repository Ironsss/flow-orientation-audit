"""
Cluster-unit inventory for the post-hoc dependence sensitivity (not a new
confirmatory test -- see docs/methodology/PROVENANCE.md and
docs/ESTADO-ACTUAL.md SS "Pendiente"). Reports how many distinct clusters
each candidate dependence unit (host-pair, single attacker host, UNSW
capture-session) actually has per group, on the same canonical frames the
confirmatory H3 runners load. Too few clusters makes a cluster bootstrap for
that group unstable or degenerate; this script exists so that gets checked
before any resampling code is written, not assumed.

Usage:
  python scripts/dependence_cluster_inventory.py --dataset unsw   --data-dir <path>
  python scripts/dependence_cluster_inventory.py --dataset botiot --data-dir <path>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.ingest.bot_iot import GROUPS as BOTIOT_GROUPS  # noqa: E402
from src.ingest.bot_iot import load_botiot  # noqa: E402
from src.ingest.unsw_nb15 import CATEGORIES as UNSW_CATEGORIES  # noqa: E402
from src.ingest.unsw_nb15 import load_unsw  # noqa: E402

OUT = ROOT / "results" / "dependence"

# UNSW-NB15's documented two-session gap, located directly from Stime (see
# docs/methodology/PROVENANCE.md): session 1 ends 2015-01-23 00:25:24 UTC,
# session 2 starts 2015-02-18 00:23:28 UTC. Anything before the midpoint of
# the gap is session 1.
UNSW_SESSION_SPLIT = (1421972724 + 1424219008) // 2


def _inventory_rows(df: pl.DataFrame, groups: list[str], dataset: str) -> list[dict]:
    rows = []
    all_ = df.filter(pl.col("label") == 0)
    named = {"Normal": all_} | {g: df.filter(pl.col("attack_category") == g) for g in groups}
    for name, sub in named.items():
        n = sub.height
        n_pairs = sub.select(pl.struct(["src_ip", "dst_ip"]).n_unique()).item() if n else 0
        n_src = sub.select(pl.col("src_ip").n_unique()).item() if n else 0
        n_dst = sub.select(pl.col("dst_ip").n_unique()).item() if n else 0
        row = {
            "dataset": dataset, "group": name, "n_rows": n,
            "n_host_pairs": n_pairs, "n_src_hosts": n_src, "n_dst_hosts": n_dst,
            "rows_per_pair_median": (n / n_pairs) if n_pairs else None,
        }
        if dataset == "UNSW-NB15":
            s1 = sub.filter(pl.col("timestamp") < UNSW_SESSION_SPLIT).height
            row["n_session1"] = s1
            row["n_session2"] = n - s1
        if dataset == "BoT-IoT":
            from src.ingest.bot_iot import ATTACKERS
            row["n_attacker_hosts"] = (
                sub.select(pl.concat_list(["src_ip", "dst_ip"]).alias("ip"))
                .select(pl.col("ip").list.explode().cast(pl.String))
                .filter(pl.col("ip").is_in(ATTACKERS))["ip"].n_unique()
                if n else 0)
            for label, secs in (("60s", 60), ("300s", 300), ("600s", 600)):
                row[f"n_time_blocks_{label}"] = (
                    sub.select((pl.col("timestamp").cast(pl.Int64) // secs).n_unique()).item()
                    if n else 0)
        rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["unsw", "botiot"], required=True)
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()

    if args.dataset == "unsw":
        df = load_unsw(args.data_dir, dedup=False)
        rows = _inventory_rows(df, UNSW_CATEGORIES, "UNSW-NB15")
    else:
        df = load_botiot(args.data_dir)
        rows = _inventory_rows(df, BOTIOT_GROUPS, "BoT-IoT")

    OUT.mkdir(parents=True, exist_ok=True)
    out_path = OUT / f"cluster_inventory_{args.dataset}.csv"
    pl.DataFrame(rows).write_csv(out_path)
    print(f"wrote {out_path}")
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
