"""Tests for CICIDS-2018 ingestion (src/ingest/loader.py)."""

from pathlib import Path

import polars as pl
import pytest

from src.ingest.loader import (
    CLASSIC_FEATURES,
    get_flow_schema,
    load_csv,
    load_directory,
)

# A small, realistic slice of a CICIDS-2018 CSV: real header names (including
# the trailing-space quirk the real files have), two timestamp formats, an
# infinite value, and both a benign and an attack row.
_HEADER = (
    "Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,"
    "TotLen Fwd Pkts,TotLen Bwd Pkts,Flow Byts/s,Label "  # trailing space, like real CICIDS
)
_ROWS = [
    "80,6,14/02/2018 08:31:01,1000,2,2,200,200,inf,Benign",
    "445,6,14/02/2018 08:31,50,10,0,4000,0,4000.0,DoS Hulk",
]


def _write_csv(path: Path) -> Path:
    csv_path = path / "sample.csv"
    csv_path.write_text(_HEADER + "\n" + "\n".join(_ROWS) + "\n")
    return csv_path


class TestLoadCsv:
    def test_strips_and_normalizes_column_names(self, tmp_path):
        df = load_csv(_write_csv(tmp_path)).collect()
        assert "dst_port" in df.columns
        assert "flow_byts_per_s" in df.columns
        assert "label" in df.columns
        # None of the raw CICIDS header names (with spaces) should survive
        assert "Dst Port" not in df.columns

    def test_infinite_values_replaced_with_zero(self, tmp_path):
        df = load_csv(_write_csv(tmp_path)).collect()
        # Row order isn't guaranteed after _clean_data's dedup (see its
        # docstring) — filter by an identifying column instead of index.
        benign_row = df.filter(pl.col("label") == "Benign")
        assert benign_row["flow_byts_per_s"][0] == 0.0

    def test_parses_both_timestamp_formats(self, tmp_path):
        df = load_csv(_write_csv(tmp_path)).collect()
        assert df["timestamp"].null_count() == 0
        assert df["timestamp"].dtype == pl.Datetime

    def test_encodes_binary_attack_label(self, tmp_path):
        df = load_csv(_write_csv(tmp_path)).collect()
        # Row order isn't guaranteed (or even stable run-to-run — see
        # _clean_data's docstring) after the dedup step, so match by label
        # rather than position.
        assert df.filter(pl.col("label") == "Benign")["is_attack"].to_list() == [0]
        assert df.filter(pl.col("label") == "DoS Hulk")["is_attack"].to_list() == [1]
        assert sorted(df["is_attack"].to_list()) == [0, 1]

    def test_label_matching_is_case_insensitive(self, tmp_path):
        csv_path = tmp_path / "case.csv"
        csv_path.write_text(_HEADER + "\n" + "80,6,14/02/2018 08:31:01,1,1,1,1,1,1.0,BENIGN\n")
        df = load_csv(csv_path).collect()
        assert df["is_attack"].to_list() == [0]

    def test_duplicate_rows_are_dropped(self, tmp_path):
        csv_path = tmp_path / "dupes.csv"
        row = "80,6,14/02/2018 08:31:01,1,1,1,1,1,1.0,Benign\n"
        csv_path.write_text(_HEADER + "\n" + row + row)
        df = load_csv(csv_path).collect()
        assert len(df) == 1

    def test_embedded_duplicate_header_does_not_corrupt_numeric_dtypes(self, tmp_path):
        """Reproduces a real bug found against Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv.

        That file is the concatenation of ~26 separate CICFlowMeter exports,
        each with its own header row repeated mid-file. Without an explicit
        numeric schema, polars' type inference saw the header text ("Dst
        Port", a non-numeric value) inside what it was inferring as a numeric
        column and fell back to String for *every* CLASSIC_FEATURES column in
        the whole file -- silently, with no exception -- which then made
        `_clean_data()`'s infinity/NaN cleaning a no-op, since it only touches
        numeric-dtype columns.
        """
        csv_path = tmp_path / "embedded_header.csv"
        row = "80,6,14/02/2018 08:31:01,1000,2,2,200,200,4.0,Benign\n"
        csv_path.write_text(_HEADER + "\n" + row + _HEADER + "\n" + row)

        df = load_csv(csv_path).collect()
        assert df.schema["dst_port"] == pl.Float64
        assert df.schema["flow_byts_per_s"] == pl.Float64
        benign = df.filter(pl.col("label") == "Benign")
        assert benign["dst_port"].to_list() == [80.0]
        assert benign["flow_byts_per_s"].to_list() == [4.0]


class TestLoadDirectory:
    def test_concatenates_multiple_csvs(self, tmp_path):
        _write_csv(tmp_path)
        (tmp_path / "sample2.csv").write_text(
            _HEADER + "\n" + "22,6,14/02/2018 09:00:00,5,1,1,10,10,2.0,FTP-BruteForce\n"
        )
        df = load_directory(tmp_path).collect()
        assert len(df) == 3  # 2 rows from sample.csv + 1 from sample2.csv

    def test_raises_on_empty_directory(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_directory(tmp_path)

    def test_ignores_non_csv_files(self, tmp_path):
        _write_csv(tmp_path)
        (tmp_path / "notes.txt").write_text("not a csv")
        df = load_directory(tmp_path).collect()
        assert len(df) == 2


class TestSchema:
    def test_get_flow_schema_includes_is_attack(self):
        schema = get_flow_schema()
        assert "is_attack" in schema
        assert "dst_port" in schema
        assert "src_ip" in schema

    def test_classic_features_are_all_lowercase_snake_case(self):
        assert len(CLASSIC_FEATURES) > 0
        for col in CLASSIC_FEATURES:
            assert col == col.lower()
            assert " " not in col

    def test_classic_features_excludes_label_and_ip_columns(self):
        # CLASSIC_FEATURES is meant as a numeric baseline feature set — it
        # shouldn't include the label or identity columns.
        assert "label" not in CLASSIC_FEATURES
        assert "is_attack" not in CLASSIC_FEATURES
        assert "src_ip" not in CLASSIC_FEATURES
        assert "dst_ip" not in CLASSIC_FEATURES
