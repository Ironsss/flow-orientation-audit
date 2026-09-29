"""A4 Steps 0-1: STRUCTURAL preflight of the downloaded NF-UQ-NIDS-v2 bag.

POST-HOC reviewer robustness audit, pre-freeze. This script computes NO
outcome: no AUC, no A_bytes / A_packets, no feature distribution, and no
feature-by-label relationship. It produces only:

  * file sizes, SHA256 (and SHA1, checked against the bag's manifest-sha1.txt);
  * schema, row counts, null / empty / numeric-parse-failure counts;
  * (Dataset, Label, Attack) row counts -- label counts are structural preflight;
  * exact duplicate-row counts per Dataset (64-bit row hash);
  * distinct src/dst IP counts per Dataset;
  * LABEL-BLIND invariant-violation counts between paired fields of the
    NF-CSE-CIC-IDS2018-v2 subset (Label/Attack are not read for these).

Usage:
    .venv/Scripts/python.exe scripts/audit_a4_preflight.py [BAG_DIR]
"""

import csv
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "audit" / "a4_representation"
BAG = Path(sys.argv[1] if len(sys.argv) > 1 else
           r"C:\Users\DavidG\Downloads\9810e03bba4983da_MOHANAD_A4706"
           r"\9810e03bba4983da_MOHANAD_A4706")
DATA = BAG / "data"
BIG = DATA / "NF-UQ-NIDS-v2.csv"
DOC = DATA / "NetFlow_v2_Features.csv"
CIC = "NF-CSE-CIC-IDS2018-v2"
c = pl.col


def hashes(p: Path) -> tuple[str, str]:
    h256, h1 = hashlib.sha256(), hashlib.sha1()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 24), b""):
            h256.update(chunk)
            h1.update(chunk)
    return h256.hexdigest(), h1.hexdigest()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rep: dict = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                            capture_output=True, text=True).stdout.strip(),
                 "python": sys.version, "platform": platform.platform(),
                 "polars": pl.__version__, "bag_dir": str(BAG)}

    bag_sha1 = dict(reversed(line.split(None, 1)) for line in
                    (BAG / "manifest-sha1.txt").read_text().splitlines() if line.strip())
    rep["files"] = {}
    for p in (DOC, BIG):
        s256, s1 = hashes(p)
        rep["files"][p.name] = {"size_bytes": p.stat().st_size, "sha256": s256, "sha1": s1,
                                "sha1_matches_bag_manifest": bag_sha1.get(f"data/{p.name}") == s1}
    rep["doc_rows"] = pl.read_csv(DOC, encoding="utf8-lossy").height

    rep["inferred_dtypes_100k"] = {
        k: str(v) for k, v in pl.scan_csv(BIG, infer_schema_length=100_000)
        .collect_schema().items()}
    lf = pl.scan_csv(BIG, infer_schema_length=0)  # every column as String
    cols = list(rep["inferred_dtypes_100k"])
    r = lf.select(pl.len().alias("rows"),
                  *[c(x).null_count().alias(f"null::{x}") for x in cols],
                  *[c(x).str.len_bytes().eq(0).sum().alias(f"empty::{x}") for x in cols],
                  ).collect(engine="streaming").row(0, named=True)
    rep["rows"] = r["rows"]
    rep["null_counts"] = {x: r[f"null::{x}"] for x in cols}
    rep["empty_string_counts"] = {x: r[f"empty::{x}"] for x in cols}

    text_cols = {"IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Attack", "Dataset"}
    rep["numeric_parse_failures"] = lf.select(
        *[(c(x).is_not_null() & c(x).cast(pl.Float64, strict=False).is_null()).sum().alias(x)
          for x in cols if x not in text_cols]).collect(engine="streaming").row(0, named=True)

    rep["dataset_label_attack_counts"] = (
        lf.group_by(["Dataset", "Label", "Attack"]).agg(pl.len().alias("n"))
        .sort(["Dataset", "Label", "Attack"]).collect(engine="streaming").to_dicts())

    # Exact full-row duplicates via a 64-bit hash (collision odds ~n^2/2^65).
    rep["duplicates_by_dataset"] = (
        lf.select(pl.concat_str(pl.all(), separator="\x1f").hash().alias("h"), c("Dataset"))
        .group_by(["Dataset", "h"]).agg(pl.len().alias("n"))
        .group_by("Dataset").agg(pl.len().alias("distinct_rows"), c("n").sum().alias("rows"))
        .with_columns((c("rows") - c("distinct_rows")).alias("duplicate_rows"))
        .sort("Dataset").collect(engine="streaming").to_dicts())

    rep["distinct_ips_by_dataset"] = (
        lf.group_by("Dataset").agg(c("IPV4_SRC_ADDR").n_unique().alias("n_src_ip"),
                                   c("IPV4_DST_ADDR").n_unique().alias("n_dst_ip"))
        .sort("Dataset").collect(engine="streaming").to_dicts())

    rep["cic_label_blind_invariant_violations"] = invariant_violations(
        lf.filter(c("Dataset") == CIC))
    rep["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "preflight_inventory.json").write_text(json.dumps(rep, indent=1))

    cic_rows = next(d["rows"] for d in rep["duplicates_by_dataset"] if d["Dataset"] == CIC)
    big, doc = rep["files"][BIG.name], rep["files"][DOC.name]
    base = dict(label_column="Label (binary) + Attack (category)", timestamp_column="NONE",
                src_ip_column="IPV4_SRC_ADDR", dst_ip_column="IPV4_DST_ADDR",
                candidate_fwd_bytes="IN_BYTES", candidate_bwd_bytes="OUT_BYTES",
                candidate_fwd_packets="IN_PKTS", candidate_bwd_packets="OUT_PKTS")
    none = {k: "N/A" for k in base}
    manifest = [
        dict(dataset="NetFlow-v2 feature description (documentation)", filename=DOC.name,
             absolute_source_path=str(DOC), size_bytes=doc["size_bytes"], sha256=doc["sha256"],
             rows=rep["doc_rows"], columns="Feature;Description", **none),
        dict(dataset="NF-UQ-NIDS-v2 (all four source datasets)", filename=BIG.name,
             absolute_source_path=str(BIG), size_bytes=big["size_bytes"], sha256=big["sha256"],
             rows=rep["rows"], columns=";".join(cols), **base),
        dict(dataset=f"{CIC} (subset: Dataset == '{CIC}')", filename=BIG.name,
             absolute_source_path=str(BIG), size_bytes=big["size_bytes"], sha256=big["sha256"],
             rows=cic_rows, columns=";".join(cols), **base),
    ]
    write_manifest(manifest)
    print(json.dumps(rep, indent=1))


def invariant_violations(lf: pl.LazyFrame) -> dict:
    """LABEL-BLIND invariant-violation counts between paired NF fields.

    Label/Attack are never read. Returns counts only.
    """
    num = ["IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "RETRANSMITTED_IN_BYTES",
           "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_PKTS",
           "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "NUM_PKTS_UP_TO_128_BYTES",
           "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES",
           "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES"]
    sub = lf.select([c(x).cast(pl.Float64) for x in num])
    tot_b, tot_p = c("IN_BYTES") + c("OUT_BYTES"), c("IN_PKTS") + c("OUT_PKTS")
    bins = sum(c(x) for x in num[10:])
    return sub.select(
        rows=pl.len(),
        retx_in_bytes_gt_in_bytes=(c("RETRANSMITTED_IN_BYTES") > c("IN_BYTES")).sum(),
        retx_out_bytes_gt_out_bytes=(c("RETRANSMITTED_OUT_BYTES") > c("OUT_BYTES")).sum(),
        retx_in_pkts_gt_in_pkts=(c("RETRANSMITTED_IN_PKTS") > c("IN_PKTS")).sum(),
        retx_out_pkts_gt_out_pkts=(c("RETRANSMITTED_OUT_PKTS") > c("OUT_PKTS")).sum(),
        in_pkts0_but_in_bytes_pos=((c("IN_PKTS") == 0) & (c("IN_BYTES") > 0)).sum(),
        in_pkts_pos_but_in_bytes0=((c("IN_PKTS") > 0) & (c("IN_BYTES") == 0)).sum(),
        out_pkts0_but_out_bytes_pos=((c("OUT_PKTS") == 0) & (c("OUT_BYTES") > 0)).sum(),
        out_pkts_pos_but_out_bytes0=((c("OUT_PKTS") > 0) & (c("OUT_BYTES") == 0)).sum(),
        in_bytes_lt_20_per_in_pkt=((c("IN_PKTS") > 0) & (c("IN_BYTES") < 20 * c("IN_PKTS"))).sum(),
        out_bytes_lt_20_per_out_pkt=((c("OUT_PKTS") > 0)
                                     & (c("OUT_BYTES") < 20 * c("OUT_PKTS"))).sum(),
        tot_bytes_lt_shortest_x_pkts=(tot_b < c("SHORTEST_FLOW_PKT") * tot_p).sum(),
        tot_bytes_gt_longest_x_pkts=(tot_b > c("LONGEST_FLOW_PKT") * tot_p).sum(),
        size_bins_ne_total_pkts=(bins != tot_p).sum(),
        zero_total_pkts=(tot_p == 0).sum(),
    ).collect(engine="streaming").row(0, named=True)


def write_manifest(rows: list[dict]) -> None:
    """Upsert rows into data_manifest.csv, keyed by (dataset, absolute_source_path)."""
    path = OUT / "data_manifest.csv"
    old = []
    if path.exists():
        with path.open(newline="") as fh:
            old = list(csv.DictReader(fh))
    key = lambda d: (d["dataset"], d["absolute_source_path"])  # noqa: E731
    new = {key(d) for d in rows}
    merged = [d for d in old if key(d) not in new] + rows
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(merged)


if __name__ == "__main__":
    main()
