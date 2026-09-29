"""A4 gate + STRUCTURAL preflight of the standalone NF-CSE-CIC-IDS2018-v2 bag.

POST-HOC reviewer robustness audit, pre-freeze. Same discipline as
audit_a4_preflight.py: NO AUC, no A_bytes / A_packets, no feature distribution,
no feature-by-label relationship. It produces only:

  * the GATE: total / benign / attack row counts against the UQ RDM figures
    (18,893,708 / 16,635,567 / 2,258,141); a mismatch exits non-zero before
    anything else is written;
  * file sizes, SHA256 + SHA1 (checked against the bag's manifest-sha1.txt);
  * byte-identity of NetFlow_v2_Features.csv with the earlier merged bag's copy;
  * schema, null / empty / numeric-parse-failure counts;
  * (Label, Attack) row counts -- label counts are structural preflight;
  * exact duplicate-row count (64-bit row hash), distinct src/dst IPs;
  * LABEL-BLIND invariant-violation counts (shared with audit_a4_preflight.py).

Usage:
    .venv/Scripts/python.exe scripts/audit_a4_finegrained_preflight.py [BAG_DIR]
"""

import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_a4_preflight import OUT, ROOT, hashes, invariant_violations, write_manifest  # noqa: E402

BAG = Path(sys.argv[1] if len(sys.argv) > 1 else
           r"C:\Users\DavidG\Downloads\b3427ed8ad063a09_MOHANAD_A4706"
           r"\b3427ed8ad063a09_MOHANAD_A4706")
DATA = BAG / "data"
BIG = DATA / "NF-CSE-CIC-IDS2018-v2.csv"
DOC = DATA / "NetFlow_v2_Features.csv"
OLD_DOC = Path(r"C:\Users\DavidG\Downloads\9810e03bba4983da_MOHANAD_A4706"
               r"\9810e03bba4983da_MOHANAD_A4706\data\NetFlow_v2_Features.csv")
GATE = {"rows": 18_893_708, "benign": 16_635_567, "attack": 2_258_141}  # UQ RDM page
c = pl.col


def main() -> None:
    lf = pl.scan_csv(BIG, infer_schema_length=0)  # every column as String
    la = (lf.group_by(["Label", "Attack"]).agg(pl.len().alias("n"))
          .sort(["Label", "Attack"]).collect(engine="streaming"))
    found = {"rows": int(la["n"].sum()),
             "benign": int(la.filter(c("Label") == "0")["n"].sum()),
             "attack": int(la.filter(c("Label") == "1")["n"].sum())}
    print("GATE required", GATE, "found", found)
    if found != GATE or found["benign"] + found["attack"] != found["rows"]:
        sys.exit("BLOCKED: row counts do not match the published UQ RDM figures")

    rep: dict = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                            capture_output=True, text=True).stdout.strip(),
                 "python": sys.version, "platform": platform.platform(),
                 "polars": pl.__version__, "bag_dir": str(BAG),
                 "gate_required": GATE, "gate_found": found, "gate_passed": True,
                 "label_attack_counts": la.to_dicts()}

    bag_sha1 = dict(reversed(line.split(None, 1)) for line in
                    (BAG / "manifest-sha1.txt").read_text().splitlines() if line.strip())
    rep["files"] = {}
    for p in (DOC, BIG):
        s256, s1 = hashes(p)
        rep["files"][p.name] = {"size_bytes": p.stat().st_size, "sha256": s256, "sha1": s1,
                                "sha1_matches_bag_manifest": bag_sha1.get(f"data/{p.name}") == s1}
    rep["features_doc_byte_identical_to_merged_bag"] = (
        OLD_DOC.exists() and OLD_DOC.read_bytes() == DOC.read_bytes())
    rep["doc_rows"] = pl.read_csv(DOC, encoding="utf8-lossy").height

    rep["inferred_dtypes_100k"] = {
        k: str(v) for k, v in pl.scan_csv(BIG, infer_schema_length=100_000)
        .collect_schema().items()}
    cols = list(rep["inferred_dtypes_100k"])
    r = lf.select(*[c(x).null_count().alias(f"null::{x}") for x in cols],
                  *[c(x).str.len_bytes().eq(0).sum().alias(f"empty::{x}") for x in cols],
                  ).collect(engine="streaming").row(0, named=True)
    rep["rows"] = found["rows"]
    rep["null_counts"] = {x: r[f"null::{x}"] for x in cols}
    rep["empty_string_counts"] = {x: r[f"empty::{x}"] for x in cols}

    text_cols = {"IPV4_SRC_ADDR", "IPV4_DST_ADDR", "Attack"}
    rep["numeric_parse_failures"] = lf.select(
        *[(c(x).is_not_null() & c(x).cast(pl.Float64, strict=False).is_null()).sum().alias(x)
          for x in cols if x not in text_cols]).collect(engine="streaming").row(0, named=True)

    # Exact full-row duplicates via a 64-bit hash (collision odds ~n^2/2^65).
    d = (lf.select(pl.concat_str(pl.all(), separator="\x1f").hash().alias("h"))
         .select(pl.len().alias("rows"), c("h").n_unique().alias("distinct_rows"))
         .collect(engine="streaming").row(0, named=True))
    rep["duplicates"] = {**d, "duplicate_rows": d["rows"] - d["distinct_rows"]}
    rep["distinct_ips"] = lf.select(
        n_src_ip=c("IPV4_SRC_ADDR").n_unique(), n_dst_ip=c("IPV4_DST_ADDR").n_unique(),
    ).collect(engine="streaming").row(0, named=True)
    rep["label_blind_invariant_violations"] = invariant_violations(lf)
    rep["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "preflight_inventory_finegrained.json").write_text(json.dumps(rep, indent=1))

    big, doc = rep["files"][BIG.name], rep["files"][DOC.name]
    base = dict(label_column="Label (binary) + Attack (fine CIC label)", timestamp_column="NONE",
                src_ip_column="IPV4_SRC_ADDR", dst_ip_column="IPV4_DST_ADDR",
                candidate_fwd_bytes="IN_BYTES", candidate_bwd_bytes="OUT_BYTES",
                candidate_fwd_packets="IN_PKTS", candidate_bwd_packets="OUT_PKTS")
    write_manifest([
        dict(dataset="NetFlow-v2 feature description (documentation, standalone CIC bag)",
             filename=DOC.name, absolute_source_path=str(DOC), size_bytes=doc["size_bytes"],
             sha256=doc["sha256"], rows=rep["doc_rows"], columns="Feature;Description",
             **{k: "N/A" for k in base}),
        dict(dataset="NF-CSE-CIC-IDS2018-v2 (standalone, fine labels; PRIMARY A4 NF input)",
             filename=BIG.name, absolute_source_path=str(BIG), size_bytes=big["size_bytes"],
             sha256=big["sha256"], rows=rep["rows"], columns=";".join(cols), **base),
    ])
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    main()
