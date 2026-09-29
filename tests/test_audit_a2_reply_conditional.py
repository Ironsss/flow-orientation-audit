"""scripts/audit_a2_reply_conditional.py: counting_auc must match
sklearn.roc_auc_score, and answered-only slicing must actually change the
AUC when the unanswered rows are the only ones separating the classes
(the collapse case A2 is designed to detect)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

_p = Path(__file__).resolve().parents[1] / "scripts" / "audit_a2_reply_conditional.py"
_spec = importlib.util.spec_from_file_location("a2", _p)
a2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a2)


def test_counting_auc_matches_sklearn():
    rng = np.random.default_rng(0)
    benign = rng.normal(0, 1, 500)
    attack = rng.normal(1, 1, 300)
    got = a2.counting_auc(benign, attack)
    want = roc_auc_score(np.r_[np.zeros(500), np.ones(300)], np.r_[benign, attack])
    assert abs(got - want) < 1e-9


def test_counting_auc_none_on_empty_side():
    assert a2.counting_auc(np.array([]), np.array([1.0])) is None
    assert a2.counting_auc(np.array([1.0]), np.array([])) is None


def test_answered_only_collapses_when_signal_is_purely_reply_presence():
    """Construct a case where attack differs from benign only in reply rate
    -- among rows that DO reply, the value distribution is identical. The
    all-flows AUC should be > 0.5 (driven by reply presence via a_bytes'
    definition of "no reply -> positive"), the answered-only AUC should
    collapse to ~0.5."""
    rng = np.random.default_rng(0)
    n = 2000
    reply_attack = rng.random(n) > 0.8    # attack rarely gets a reply
    reply_benign = rng.random(n) > 0.2    # benign usually gets a reply
    # When answered, both classes draw from the same distribution.
    val_attack = np.where(reply_attack, rng.normal(0, 1, n), 5.0)
    val_benign = np.where(reply_benign, rng.normal(0, 1, n), 5.0)

    auc_all = a2.counting_auc(val_benign, val_attack)
    auc_answered = a2.counting_auc(val_benign[reply_benign], val_attack[reply_attack])
    assert auc_all > 0.6
    assert abs(auc_answered - 0.5) < 0.05
