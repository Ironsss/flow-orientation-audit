"""scripts/audit_a1_benign_concentration.py: concentration shares and the
(pair, code) collapse used to make side-isolated bootstraps fast must match
their literal definitions."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np

_p = Path(__file__).resolve().parents[1] / "scripts" / "audit_a1_benign_concentration.py"
_spec = importlib.util.spec_from_file_location("a1bc", _p)
bc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bc)


def test_top_shares():
    cid = np.array([0] * 5 + [1] * 3 + [2] * 1 + [3] * 1)
    top1, top2 = bc.top_shares(cid, k=2)
    assert top1 == 0.5 and top2 == 0.8


def test_collapsed_attack_side_gives_identical_bootstrap_to_row_level():
    """Resampling benign pairs with the attack side either row-level (weight 1
    per row) or collapsed to (pair, code) cells (weight = count) must give
    the same AUC on every draw, hence the same CI for the same seed. The
    same must hold when the attack side is the one resampled."""
    rng = np.random.default_rng(0)
    n_values = 6
    codes_b, cid_b = rng.integers(0, n_values, 40), rng.integers(0, 8, 40)
    codes_a, cid_a = rng.integers(0, n_values, 300), rng.integers(0, 12, 300)
    cid_b, _ = bc.a1.dense(cid_b)
    cid_a, _ = bc.a1.dense(cid_a)
    ones_b, ones_a = np.ones(40), np.ones(300)
    cc, ccid, ccnt = bc.collapse(codes_a, cid_a, n_values)
    assert ccnt.sum() == 300 and len(cc) < 300
    for side in ("benign", "attack"):
        row = bc.side_bootstrap_ci(codes_b, ones_b, cid_b, codes_a, ones_a, cid_a, n_values,
                                   side, np.random.default_rng(1))
        cell = bc.side_bootstrap_ci(codes_b, ones_b, cid_b, cc, ccnt, ccid, n_values,
                                    side, np.random.default_rng(1))
        assert np.allclose(row, cell, atol=1e-12)
