"""scripts/run_unsw_external_validation.py: the counting AUC/quantile primitives
must equal their sklearn/numpy references (ties included), and the frozen
decision rule (FREEZE SS7.6) must map tables to the pre-registered verdicts."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

_p = Path(__file__).resolve().parents[1] / "scripts" / "run_unsw_external_validation.py"
_spec = importlib.util.spec_from_file_location("unsw_run", _p)
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)


def test_counting_auc_and_quantiles_match_references():
    rng = np.random.default_rng(0)
    benign = rng.integers(-5, 6, 3000).astype(float)  # heavy ties on purpose
    attack = rng.integers(-3, 9, 700).astype(float)
    values, inv = np.unique(np.r_[benign, attack], return_inverse=True)
    bc = np.bincount(inv[: len(benign)], minlength=len(values))
    auc = run.auc_from_codes(run.auc_lookup(bc), inv[len(benign):], len(benign))
    y = np.r_[np.zeros(len(benign)), np.ones(len(attack))]
    assert abs(auc - roc_auc_score(y, np.r_[benign, attack])) < 1e-12
    for q in (0.1, 0.25, 0.5, 0.75, 0.9):
        assert run.quantile_from_counts(bc, values, q) == np.quantile(
            benign, q, method="inverted_cdf")


def _row(cat, auc, lo, hi, src=1.0, feature="A_bytes"):
    return {"feature": feature, "category": cat, "auc_signed": auc, "computed": True,
            "orientation": run.orientation(auc), "confident": run.confident(auc, lo, hi),
            "src_is_attacker": src}


def _table(bytes_rows, packet_rows):
    base = {c: _row(c, 0.5, 0.49, 0.51) for c in run.CATEGORIES}
    out = []
    for feat, rows in (("A_bytes", bytes_rows), ("A_packets", packet_rows)):
        merged = base | {r["category"]: r for r in rows}
        out += [r | {"feature": feat} for r in merged.values()]
    return out


def test_decision_rule():
    pos, neg = _row("Exploits", 0.8, 0.78, 0.82), _row("DoS", 0.2, 0.18, 0.22)
    assert run.verdict(_table([pos, neg], [pos, neg]))["verdict"] == "STRONG REPLICATION"
    assert run.verdict(_table([pos, neg], []))["verdict"] == "PARTIAL REPLICATION"
    assert run.verdict(_table([pos], [pos, neg]))["verdict"] == "NO REPLICATION"
    # CI straddling 0.5 is not confident even with a large point estimate.
    wide = _row("DoS", 0.2, 0.1, 0.6)
    assert run.verdict(_table([pos, wide], []))["verdict"] == "NO REPLICATION"
    # Opposite signs but the attacker is not the source: not a replication.
    flipped = _row("DoS", 0.2, 0.18, 0.22, src=0.3)
    assert run.verdict(_table([pos, flipped], []))["verdict"] == "INCONCLUSIVE (ROLE)"
    v = run.verdict(_table([pos, neg], []))["H3_dir"]
    assert v["DoS_negative_confident"] and v["Exploits_positive_confident"]
    assert run.orientation(0.54) == "near-neutral" and run.orientation(0.45) == "negative"
