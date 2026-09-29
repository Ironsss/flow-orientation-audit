"""Permanent regression test for a Phase I reviewer-audit finding
(docs/reviewer_audit/A3_FEATURE_SEMANTICS_REPORT.md): the per-capture
CICIDS-2018 AUCs reported in docs/datos-reales/ANALISIS-DATOS-REALES.tex
(around line 841) are the count-weighted mean of that capture's per-label
AUCs in results/audit/a3_cicids_labels.csv -- not a separate measurement,
and not evidence of a mixed/ambiguous capture. This guards the committed
CSV against silent edits, not the pipeline that produced it: it does not
rerun scripts/audit_a3_cicids_labels.py, so a pipeline change that isn't
followed by regenerating that CSV won't be caught here.

The three "Label" rows (n=1) are a known CSV-header-parsed-as-data artifact
(disclosed in A3_FEATURE_SEMANTICS_REPORT.md) and are excluded, matching
the convention already used elsewhere in this audit.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "results" / "audit" / "a3_cicids_labels.csv"

# docs/datos-reales/ANALISIS-DATOS-REALES.tex, per-capture AUC table (~line 841).
PUBLISHED = {
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv": 0.838,
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv": 0.023,
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv": 0.694,
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv": 0.381,
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv": 0.537,
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv": 0.590,
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv": 0.633,
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv": 0.631,
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv": 0.003,
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv": 0.494,
}


def weighted_mean_by_capture() -> dict[str, float]:
    df = pl.read_csv(CSV).filter(pl.col("label") != "Label")
    out = (
        df.group_by("capture_file")
        .agg(
            (pl.col("auc_signed_bytes") * pl.col("n")).sum() / pl.col("n").sum()
        )
        .rename({"auc_signed_bytes": "weighted_auc"})
    )
    return dict(zip(out["capture_file"], out["weighted_auc"]))


def test_a3_committed_csv_has_a_row_for_every_published_capture():
    computed = weighted_mean_by_capture()
    assert set(computed) == set(PUBLISHED)


def test_count_weighted_mean_of_per_label_aucs_reproduces_published_figures():
    computed = weighted_mean_by_capture()
    for capture, published in PUBLISHED.items():
        got = computed[capture]
        assert abs(got - published) < 6e-4, (
            f"{capture}: count-weighted per-label AUC {got:.4f} no longer "
            f"reproduces the published per-capture figure {published} "
            "(docs/datos-reales/ANALISIS-DATOS-REALES.tex) -- check whether "
            "scripts/audit_a3_cicids_labels.py's per-label pipeline changed."
        )


if __name__ == "__main__":
    for capture, auc in sorted(weighted_mean_by_capture().items()):
        print(f"{capture}: {auc:.4f} (published {PUBLISHED[capture]})")
