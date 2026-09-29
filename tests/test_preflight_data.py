"""Regression tests for scripts/preflight_data.py's header-reading step.

Both cases here reproduce real failures hit against actual CICIDS-2018 files
downloaded from the public bucket (see docs/onboarding/setup/SETUP-LOCAL.md),
not hypothetical edge cases.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_preflight(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "scripts/preflight_data.py", str(path)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_header_read_survives_int_to_float_schema_drift(tmp_path):
    """Reproduces a real failure on Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv.

    polars' pl.read_csv(n_rows=0) infers a column's dtype from the first rows;
    if those happen to be whole numbers ("0") it infers Int64, and a later
    float value ("7994261.5") crashes the parse with a ComputeError -- before
    the script even gets to check for Src IP / Dst IP. The header-only read
    must not depend on data-row type inference at all.
    """
    csv = tmp_path / "sample.csv"
    header = "Dst Port,Protocol,Timestamp,Active Mean,Label"
    rows = ["80,6,01/03/2018 10:00:00,0,Benign"] * 5 + [
        "80,6,01/03/2018 10:00:01,7994261.5,Benign"
    ]
    csv.write_text(header + "\n" + "\n".join(rows) + "\n")

    result = _run_preflight(csv)
    assert "cannot read the CSV header" not in result.stdout
    assert "Src IP / Dst IP MISSING" in result.stdout
    assert result.returncode == 1


def test_header_read_survives_embedded_duplicate_header(tmp_path):
    """Reproduces a real failure on Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv.

    That file is the concatenation of ~26 separate CICFlowMeter exports, each
    with its own header row repeated mid-file. polars' schema inference reads
    one of those repeated header rows as a data row and crashes trying to
    parse the column name "Dst Port" as an integer.
    """
    csv = tmp_path / "sample.csv"
    header = "Dst Port,Protocol,Timestamp,Active Mean,Label"
    body = "80,6,01/03/2018 10:00:00,0,Benign"
    csv.write_text("\n".join([header, body, header, body]) + "\n")

    result = _run_preflight(csv)
    assert "cannot read the CSV header" not in result.stdout
    assert "Src IP / Dst IP MISSING" in result.stdout
    assert result.returncode == 1
