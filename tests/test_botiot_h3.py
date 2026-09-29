"""scripts/run_botiot_h3.py: the count-weighted AUC used in the bootstrap must
equal the imported auc_from_codes, the imported criterion must see the ten
BoT-IoT groups, and the SS6/SS7 rules must map tables to the frozen outcomes."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

_p = Path(__file__).resolve().parents[1] / "scripts" / "run_botiot_h3.py"
_spec = importlib.util.spec_from_file_location("botiot_run", _p)
bot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bot)


def test_weighted_auc_equals_row_form_and_sklearn():
    rng = np.random.default_rng(0)
    benign = rng.integers(-4, 5, 500).astype(float)
    attack = rng.integers(-2, 8, 3000).astype(float)
    values, inv = np.unique(np.r_[benign, attack], return_inverse=True)
    bc = np.bincount(inv[:500], minlength=len(values))
    lk = bot.run.auc_lookup(bc)
    codes = inv[500:]
    u, k = np.unique(codes, return_counts=True)
    weighted = float((lk[u] * k).sum() / k.sum() / 500)
    assert abs(weighted - bot.run.auc_from_codes(lk, codes, 500)) < 1e-12
    y = np.r_[np.zeros(500), np.ones(3000)]
    assert abs(weighted - roc_auc_score(y, np.r_[benign, attack])) < 1e-12


def _row(g, auc, lo, hi, src=1.0, feature="A_bytes"):
    return {"feature": feature, "category": g, "computed": True, "auc_signed": auc,
            "orientation": bot.run.orientation(auc), "confident": bot.run.confident(auc, lo, hi),
            "src_is_attacker": src}


def _table(overrides_bytes, overrides_pkts=()):
    out = []
    for feat, ov in (("A_bytes", overrides_bytes), ("A_packets", overrides_pkts)):
        rows = {g: _row(g, 0.5, 0.49, 0.51, feature=feat) for g in bot.GROUPS}
        rows |= {r["category"]: r | {"feature": feat} for r in ov}
        out += rows.values()
    return out


def test_criterion_sees_botiot_groups_and_rules_map():
    neg = _row("DoS/HTTP", 0.2, 0.18, 0.22)
    pos = _row("DDoS/TCP", 0.9, 0.88, 0.92)
    assert bot.verdict(_table([neg, pos], [neg, pos]))["verdict"] == "STRONG REPLICATION"
    assert bot.verdict(_table([neg, pos]))["verdict"] == "PARTIAL REPLICATION"
    assert bot.verdict(_table([pos]))["verdict"] == "NO REPLICATION"
    # Victim-sourced pair: opposite signs but the role condition fails.
    v = bot.verdict(_table([_row("DoS/HTTP", 0.2, 0.18, 0.22, src=0.1), pos]))
    assert v["verdict"] == "INCONCLUSIVE (ROLE)"


def test_secondary_predictions_and_abandonment():
    v = bot.verdict(_table([_row("DDoS/TCP", 0.9, 0.88, 0.92), _row("DoS/HTTP", 0.2, 0.18, 0.22)]))
    assert v["H3_env"]["DDoS/TCP"]["held_confident"]
    assert not v["H3_dir"]["DDoS/TCP"]["held"]
    assert v["H3_dir"]["DoS/HTTP"]["held_confident"] and not v["abandon_H3_env"]
    v = bot.verdict(_table([_row("DoS/UDP", 0.1, 0.08, 0.12), _row("DDoS/HTTP", 0.9, 0.88, 0.92)]))
    assert v["abandon_H3_env"] and v["abandon_H3_dir"]
