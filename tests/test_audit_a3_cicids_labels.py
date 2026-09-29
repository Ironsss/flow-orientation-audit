"""scripts/audit_a3_cicids_labels.py: per_file must produce one row per
distinct non-benign label: whitespace variants of the same label must be
merged into one row (not split into two), while genuinely distinct labels
stay separate (merging those is the failure mode this audit exists to
avoid)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_p = Path(__file__).resolve().parents[1] / "scripts" / "audit_a3_cicids_labels.py"
_spec = importlib.util.spec_from_file_location("a3", _p)
a3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a3)


def test_per_file_separates_distinct_labels_and_strips_whitespace(tmp_path):
    csv_path = tmp_path / "sample.csv"
    header = ("Dst Port,Protocol,Timestamp,Label,Tot Fwd Pkts,Tot Bwd Pkts,"
              "TotLen Fwd Pkts,TotLen Bwd Pkts\n")
    # src.ingest.loader.load_csv's _clean_data() drops exact duplicate rows
    # (across ALL columns) before labels are even stripped, so every row
    # here varies Dst Port to stay distinct -- otherwise the repeated rows
    # collapse to one and the counts below would be wrong for reasons
    # unrelated to what this test checks.
    rows = (
        [f"{8000 + i},6,01/01/2018 00:00:00,Benign,5,5,500,500" for i in range(20)]
        + [f"{9000 + i},6,01/01/2018 00:00:00,DoS attacks-Hulk,10,0,1000,0" for i in range(10)]
        + [f"{9100 + i},6,01/01/2018 00:00:00, DoS attacks-Hulk,10,0,1000,0"  # leading space
           for i in range(5)]
        + [f"{9200 + i},6,01/01/2018 00:00:00,DDOS attack-HOIC,50,0,5000,0" for i in range(8)]
    )
    csv_path.write_text(header + "\n".join(rows) + "\n")

    out = a3.per_file(csv_path)
    labels = {r["label"] for r in out}
    assert labels == {"DoS attacks-Hulk", "DDOS attack-HOIC"}
    hulk = next(r for r in out if r["label"] == "DoS attacks-Hulk")
    assert hulk["n"] == 15  # the whitespace-variant rows must be merged in, not double-counted
    hoic = next(r for r in out if r["label"] == "DDOS attack-HOIC")
    assert hoic["n"] == 8
    assert hulk["reply_rate"] == 0.0  # Tot Bwd Pkts == 0 for every Hulk row here
