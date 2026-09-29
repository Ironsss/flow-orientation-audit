"""scripts/multiplicity_holm_sensitivity.py: the Holm step-down adjustment
must match a hand-worked reference example, and the bootstrap p-value must
behave correctly at its two extremes (all draws on one side -> floored at
1/B, draws straddling 0.5 -> not significant)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np

_p = Path(__file__).resolve().parents[1] / "scripts" / "multiplicity_holm_sensitivity.py"
_spec = importlib.util.spec_from_file_location("holm_mod", _p)
holm_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(holm_mod)


def test_holm_matches_hand_worked_example():
    # Standard textbook example, m=4: raw p = [.01, .04, .03, .005].
    # Sorted ascending -> (m-rank+1)*p, cumulative max, mapped back:
    # .005->.02, .01->.03, .03->.06, .04->.06 (cummax caps it at .06).
    p = np.array([0.01, 0.04, 0.03, 0.005])
    adjusted = holm_mod.holm(p)
    expected = np.array([0.03, 0.06, 0.06, 0.02])
    assert np.allclose(adjusted, expected)


def test_holm_adjusted_never_below_raw_and_monotone_in_rank():
    rng = np.random.default_rng(0)
    p = rng.uniform(0, 1, 20)
    adjusted = holm_mod.holm(p)
    assert np.all(adjusted >= p - 1e-12)
    order = np.argsort(p)
    assert np.all(np.diff(adjusted[order]) >= -1e-12)  # non-decreasing by raw-p rank


def test_bootstrap_p_extremes():
    all_positive = np.full(2000, 0.8)
    assert holm_mod.bootstrap_p(all_positive) == 1.0 / 2000  # floored, not 0
    straddling = np.concatenate([np.full(1000, 0.49), np.full(1000, 0.51)])
    assert holm_mod.bootstrap_p(straddling) == 1.0  # evenly split -> not significant
