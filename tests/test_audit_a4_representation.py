"""scripts/audit_a4_representation.py + src/ingest/nf_cse_cicids2018_v2.py
(reviewer audit A4). Synthetic data only; no NF or canonical file is read."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from src.ingest.nf_cse_cicids2018_v2 import load_nf_cse_cicids2018_v2

_p = Path(__file__).resolve().parents[1] / "scripts" / "audit_a4_representation.py"
_spec = importlib.util.spec_from_file_location("a4", _p)
a4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a4)

NF_HEADER = ["IPV4_SRC_ADDR", "L4_SRC_PORT", "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
             "Label", "Attack"]


def _nf_csv(tmp_path: Path, rows: list[list]) -> Path:
    p = tmp_path / "nf.csv"
    p.write_text("\n".join(",".join(map(str, r)) for r in [NF_HEADER, *rows]) + "\n")
    return p


def _side(name, groups: dict[str, np.ndarray], bwd=None):
    """groups: label -> forward values ('Benign' = benign). bwd defaults to 0."""
    lab = np.concatenate([[k] * len(v) for k, v in groups.items()])
    fwd = np.concatenate(list(groups.values())).astype(float)
    bwd = np.zeros_like(fwd) if bwd is None else bwd
    return a4.Side(name, lab, lab == "Benign", fwd, bwd, fwd, bwd)


def _sk(benign, attack):
    return roc_auc_score(np.r_[np.zeros(len(benign)), np.ones(len(attack))], np.r_[benign, attack])


# ---- feature mapping / A_bytes / A_packets / benign identification -----------
def test_nf_loader_keeps_nf_names_and_maps_in_to_forward(tmp_path):
    p = _nf_csv(tmp_path, [
        ["1.1.1.1", 1, 100, 2, 0, 0, 1, "DDOS attack-HOIC"],
        ["1.1.1.2", 2, 60, 1, 400, 3, 0, "Benign"],
    ])
    df, info = load_nf_cse_cicids2018_v2(p)
    assert {"IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "Attack", "Label"} <= set(df.columns)
    assert not {"fwd_bytes", "bwd_bytes", "totlen_fwd_pkts"} & set(df.columns)
    assert info == {"n_raw": 2, "n_benign_raw": 1, "n_attack_raw": 1,
                    "n_exact_duplicates_removed": 0}
    side, _ = a4.load_nf(p)
    assert side.x["A_bytes"][0] == pytest.approx(np.log1p(100) - np.log1p(0))
    assert side.x["A_bytes"][1] == pytest.approx(np.log1p(60) - np.log1p(400))
    assert side.x["A_packets"][1] == pytest.approx(np.log1p(1) - np.log1p(3))
    assert side.benign.tolist() == [False, True]  # Label == 0


def test_directional_is_log1p_fwd_minus_log1p_bwd():
    got = a4.directional(np.array([0, 9, 99]), np.array([0, 99, 9]))
    assert np.allclose(got, [0.0, np.log(10) - np.log(100), np.log(100) - np.log(10)])


def test_zero_backward_bytes_gives_log1p_fwd_and_no_reply():
    s = _side("s", {"Benign": np.array([5.0]), "X": np.array([7.0])})
    assert s.x["A_bytes"][1] == pytest.approx(np.log1p(7))
    assert not s.reply["bytes"].any() and not s.reply["packets"].any()


def test_canonical_benign_is_is_attack_zero(monkeypatch, tmp_path):
    import polars as pl

    import src.ingest.loader as loader
    frame = pl.DataFrame({
        "label": ["Benign", "Bot ", "Label"], "is_attack": [0, 1, 1],
        "totlen_fwd_pkts": [1.0, 2.0, None], "totlen_bwd_pkts": [0.0, 0.0, None],
        "tot_fwd_pkts": [1.0, 1.0, None], "tot_bwd_pkts": [0.0, 0.0, None]})
    (tmp_path / "a.csv").write_text("x\n")
    monkeypatch.setattr(loader, "load_csv", lambda p: frame.lazy())
    s = a4.load_canonical(tmp_path)
    assert s.label.tolist() == ["Benign", "Bot"]  # stripped, header artifact dropped
    assert s.benign.tolist() == [True, False]
    assert s.capture.tolist() == ["a.csv", "a.csv"]


# ---- labels / categories / weights ---------------------------------------------
def test_label_and_category_mapping_is_the_frozen_one():
    assert len(a4.LABELS) == 14
    assert set(a4.WELL_SUPPORTED) == set(a4.LABELS) - {
        "Brute Force -Web", "Brute Force -XSS", "SQL Injection"}
    assert "injection" not in a4.DIAGNOSTIC
    assert set(a4.DIAGNOSTIC["Brute Force"]) == {
        "FTP-BruteForce", "SSH-Bruteforce", "Brute Force -Web", "Brute Force -XSS"}
    assert a4.SECONDARY["Brute Force"] == ["SSH-Bruteforce", "FTP-BruteForce"]
    for cat, labs in a4.DIAGNOSTIC.items():
        assert all(a4.LABELS[lab][0] == cat for lab in labs)
    assert len(a4.PAIRS) == 4


def test_weights_reproduce_the_frozen_percentages():
    w = a4.weights(a4.SECONDARY["DDoS"], "canonical_row_share")
    assert round(100 * w["DDOS attack-HOIC"], 2) == 53.63
    w = a4.weights(a4.SECONDARY["DDoS"], "nf_row_share")
    assert round(100 * w["DDOS attack-HOIC"], 2) == 77.74
    w = a4.weights(a4.SECONDARY["DoS"], "canonical_row_share")
    assert round(100 * w["DoS attacks-Hulk"], 2) == 85.93
    w = a4.weights(a4.SECONDARY["Brute Force"], "nf_row_share")
    assert round(100 * w["SSH-Bruteforce"], 2) == 78.55
    for cat, labs in a4.SECONDARY.items():
        for scheme in a4.WEIGHTINGS:
            assert sum(a4.weights(labs, scheme).values()) == pytest.approx(1.0)
    assert a4.weights(a4.SECONDARY["DoS"], "equal_mechanism")["DoS attacks-Hulk"] == 0.25


# ---- AUC ---------------------------------------------------------------------------
def test_counting_auc_matches_sklearn_with_ties():
    rng = np.random.default_rng(1)
    b, a = rng.integers(0, 20, 700).astype(float), rng.integers(3, 25, 400).astype(float)
    s = _side("s", {"Benign": b, "X": a})
    auc, n = s.pooled_auc(["X"], "A_bytes")
    assert n == 400
    assert auc == pytest.approx(_sk(np.log1p(b), np.log1p(a)), abs=1e-12)


def test_category_auc_is_pooled_not_averaged():
    """Labels of very different size and AUC: the unweighted mean differs
    from the pooled AUC; the implementation must return the pooled one."""
    rng = np.random.default_rng(2)
    b = rng.normal(0, 1, 3000)
    big, small = rng.normal(-1, 1, 5000), rng.normal(3, 1, 50)
    s = _side("s", {"Benign": np.exp(b), "BIG": np.exp(big), "SMALL": np.exp(small)})
    auc_big, _ = s.pooled_auc(["BIG"], "A_bytes")
    auc_small, _ = s.pooled_auc(["SMALL"], "A_bytes")
    pooled, n = s.pooled_auc(["BIG", "SMALL"], "A_bytes")
    xb, xa = s.x["A_bytes"][s.benign], s.x["A_bytes"][s.mask(["BIG", "SMALL"])]
    assert n == 5050
    assert pooled == pytest.approx(_sk(xb, xa), abs=1e-12)
    mean = (auc_big + auc_small) / 2
    assert abs(pooled - mean) > 0.2
    # the identity the freeze uses as a gate: pooled == n-weighted mean
    assert pooled == pytest.approx((5000 * auc_big + 50 * auc_small) / 5050, abs=1e-12)
    d = s.describe(["BIG", "SMALL"], "A_bytes")
    assert d["auc_signed"] == pooled


def test_no_sign_flip_attack_role_is_fixed():
    s = _side("s", {"Benign": np.array([1.0, 2, 3]), "HI": np.array([50.0, 60]),
                    "LO": np.array([0.0, 0])})
    assert s.pooled_auc(["HI"], "A_bytes")[0] == 1.0
    assert s.pooled_auc(["LO"], "A_bytes")[0] == 0.0
    assert a4.orientation(0.0) == "negative"  # not folded to separability
    assert s.pair_auc("HI", "LO", "A_bytes") == 1.0
    assert s.pair_auc("LO", "HI", "A_bytes") == 0.0
    assert a4.auc_sep(0.0) == 1.0


def test_ties_and_tie_share():
    x, y = np.array([1.0, 1, 2, 3]), np.array([1.0, 2, 5])
    # pairs equal: (1,1)x2 + (2,2)x1 = 3 of 12
    assert a4.tie_share(x, y) == pytest.approx(3 / 12)
    s = _side("s", {"X": np.full(10, 4.0), "Y": np.full(7, 4.0)})
    assert s.pair_auc("X", "Y", "A_bytes") == 0.5
    assert a4.tie_share(s.x["A_bytes"][s.mask(["X"])], s.x["A_bytes"][s.mask(["Y"])]) == 1.0


def test_tertiary_reports_tie_share_and_cross_label_identical_rows():
    labs = {"Benign": np.array([1.0])}
    for x_lab, y_lab in a4.PAIRS:
        labs[x_lab] = np.array([5.0, 5.0, 9.0])
        labs[y_lab] = np.array([5.0, 1.0])
    can, nf = _side("canonical", labs), _side("nf", labs)
    nf.fhash = np.arange(len(nf.label), dtype=np.uint64)
    x0, y0 = a4.PAIRS[0]
    nf.fhash[np.flatnonzero(nf.label == y0)[0]] = nf.fhash[np.flatnonzero(nf.label == x0)[0]]
    rows = a4.tertiary(can, nf)
    assert len(rows) == 4 * 2 * 2
    r = next(r for r in rows if r["X"] == x0 and r["side"] == "nf" and r["feature"] == "A_bytes")
    assert r["tie_share"] == pytest.approx(2 / 6)
    assert r["auc_pair"] == pytest.approx((4 + 2 * 0.5) / 6)  # 4 wins + 2 ties
    assert r["n_X_rows_feature_identical_to_a_Y_row"] == 1
    assert r["n_Y_rows_feature_identical_to_an_X_row"] == 1
    assert r["assigns_case"] is False
    c = next(r for r in rows if r["X"] == x0 and r["side"] == "canonical")
    assert c["n_X_rows_feature_identical_to_a_Y_row"] is None


# ---- missing values / duplicates -------------------------------------------------
def test_missing_values_raise():
    with pytest.raises(ValueError):
        a4.directional(np.array([1.0, np.nan]), np.array([0.0, 0.0]))


def test_nf_loader_raises_on_missing_field(tmp_path):
    p = _nf_csv(tmp_path, [["1.1.1.1", 1, "", 2, 0, 0, 1, "Bot"]])
    with pytest.raises(ValueError):
        load_nf_cse_cicids2018_v2(p)


def test_duplicate_policy_exact_removed_feature_only_kept(tmp_path):
    row = ["1.1.1.1", 1, 100, 2, 0, 0, 1]
    p = _nf_csv(tmp_path, [row + ["Bot"], row + ["Bot"], row + ["Infilteration"]])
    df, info = load_nf_cse_cicids2018_v2(p)
    assert info["n_raw"] == 3 and info["n_exact_duplicates_removed"] == 1
    assert sorted(df["Attack"].to_list()) == ["Bot", "Infilteration"]
    assert df["feature_hash"].n_unique() == 1  # cross-label feature-identical, kept


# ---- classification / case rules ---------------------------------------------------
def test_cross_status_all_five():
    P, N, Z = "positive", "negative", "near-neutral"
    assert a4.cross_status(P, P) == "PRESERVED"
    assert a4.cross_status(P, N) == "REVERSED"
    assert a4.cross_status(N, Z) == "NEUTRALIZED"
    assert a4.cross_status(Z, P) == "EMERGED"
    assert a4.cross_status(Z, Z) == "BOTH NEUTRAL"


def test_band_edges_and_magnitude():
    assert a4.orientation(0.55) == "positive" and a4.orientation(0.45) == "negative"
    assert a4.orientation(0.5499) == "near-neutral"
    assert a4.magnitude_change(0.60, 0.65) and not a4.magnitude_change(0.60, 0.6499)


def _r(status, mag=False, can="positive"):
    return {"status": status, "magnitude_change": mag, "canonical_orientation": can}


def test_assign_case_order():
    conf8 = [_r("PRESERVED")] * 8
    neutral3 = [_r("BOTH NEUTRAL", can="near-neutral")] * 3
    assert a4.assign_case(conf8 + neutral3) == "A"
    assert a4.assign_case(conf8[:-1] + [_r("PRESERVED", True)] + neutral3) == "B"
    assert a4.assign_case(conf8 + neutral3[:-1] + [_r("EMERGED", can="near-neutral")]) == "E"
    assert a4.assign_case([_r("REVERSED")] + conf8[1:] + neutral3) == "C"
    assert a4.assign_case([_r("REVERSED")] * 4 + conf8[4:] + neutral3) == "C"  # 4 of 8
    assert a4.assign_case([_r("NEUTRALIZED")] * 5 + conf8[5:] + neutral3) == "D"  # 5 of 8


def test_gap_readout_relative_to_canonical_sign():
    assert a4.gap_readout(0.42, 0.30) == "ORDER PRESERVED"
    assert a4.gap_readout(0.42, 0.01) == "CONVERGED"
    assert a4.gap_readout(0.42, -0.2) == "INVERTED"
    assert a4.gap_readout(-0.22, -0.10) == "ORDER PRESERVED"
    assert a4.gap_readout(-0.22, 0.10) == "INVERTED"


# ---- output schema -----------------------------------------------------------------
def test_comparison_schema_and_tiers_on_synthetic_sides():
    rng = np.random.default_rng(3)
    groups = {"Benign": rng.integers(1, 100, 500).astype(float)}
    for i, lab in enumerate(a4.LABELS):
        groups[lab] = rng.integers(1 + i, 100 + 5 * i, 40).astype(float)
    can = _side("canonical", groups, bwd=rng.integers(0, 50, 500 + 40 * 14).astype(float))
    nf = _side("nf", groups)
    fine, desc = a4.primary(can, nf)
    comp = a4.comparison(desc)
    assert list(comp[0]) == [
        "category", "canonical_auc_signed", "nfv2_auc_signed", "delta_auc_signed",
        "canonical_orientation", "nfv2_orientation", "same_side_0_5", "canonical_auc_sep",
        "nfv2_auc_sep", "delta_auc_sep", "canonical_reply_attack", "nfv2_reply_attack",
        "canonical_reply_benign", "nfv2_reply_benign"]
    assert [r["category"] for r in comp] == a4.WELL_SUPPORTED
    assert len(fine) == 14 * 2 * 2
    assert {r["per_label_reading"] for r in fine if not r["well_supported"]} == {
        "UNDER-SUPPORTED"}
    sec = a4.secondary(desc)
    assert len(sec) == 3 * 2 * 3 * 2 and not any(r["assigns_case"] for r in sec)
    diag = a4.diagnostic(can, nf, desc, fine)
    assert len(diag) == 5 * 2
    d = diag[0]
    assert d["envelope_min"] <= d["envelope_max"] and "DIAGNOSTIC" in d["label"]
    assert len(a4.ddos_ordering(desc)) == 4
