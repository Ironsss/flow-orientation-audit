"""scripts/audit_a1_bot_dependence.py: the two-stage bootstrap's multinomial-
additivity shortcut and the cluster-weighted point estimate must match their
literal (slow) definitions on small synthetic data."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np

_p = Path(__file__).resolve().parents[1] / "scripts" / "audit_a1_bot_dependence.py"
_spec = importlib.util.spec_from_file_location("a1", _p)
a1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a1)


def test_dense_maps_arbitrary_ids_to_zero_based_codes():
    ids = np.array([7, 7, 3, 3, 3, 9])
    codes, k = a1.dense(ids)
    assert k == 3
    assert codes.min() == 0 and codes.max() == k - 1
    assert (codes[ids == 7] == codes[ids == 7][0]).all()
    assert len({codes[ids == 7][0], codes[ids == 3][0], codes[ids == 9][0]}) == 3


def test_cluster_weighted_point_matches_hand_weighted_average():
    """Value codes 0 < 1 < 2 < 3, no ties.
    Benign: pair A = 1 row at code 1; pair B = 3 rows at code 3.
    Attack: pair 0 = 3 rows at code 2; pair 1 = 1 row at code 0.

    Unweighted (row-weighted) AUC: a code-2 attack row beats 1 of 4 benign
    rows; a code-0 attack row beats none -> (3 * 1/4 + 1 * 0) / 4 = 0.1875.

    Cluster-weighted (each pair weighted 1/n_pair_rows, so each pair has
    total weight 1): benign mass is 1/2 at code 1 and 1/2 at code 3, so a
    code-2 attack row beats 1/2 of it; attack pairs each carry weight 1
    -> (1 * 1/2 + 1 * 0) / 2 = 0.25."""
    codes_b = np.array([1, 3, 3, 3])
    codes_a = np.array([2, 2, 2, 0])
    cid_b, k_b = a1.dense(np.array([0, 1, 1, 1]))
    cid_a, k_a = a1.dense(np.array([0, 0, 0, 1]))
    point = a1.cluster_weighted_point(codes_b, codes_a, 4, cid_b, cid_a, k_b, k_a)
    unweighted = a1.cluster_weighted_point(codes_b, codes_a, 4, np.arange(4), np.arange(4), 4, 4)
    assert abs(unweighted - 0.1875) < 1e-12  # one row per "pair" == ordinary AUC
    assert abs(point - 0.25) < 1e-12


def test_two_stage_bootstrap_reduces_to_flow_bootstrap_for_one_row_per_pair():
    """If every pair has exactly one row, drawing pairs m times and then
    doing an inner multinomial(m*1, uniform-over-1-row) draw always
    assigns weight m to that single row -- identical to drawing that row m
    times directly, i.e. the ordinary flow bootstrap."""
    rng = np.random.default_rng(0)
    n = 50
    codes_b = rng.integers(0, 5, n)
    codes_a = rng.integers(0, 5, 15)
    cid_b = np.arange(n)  # one row per "pair"
    cid_a = np.arange(15)
    lo, hi = a1.two_stage_bootstrap_ci(codes_b, codes_a, 5, cid_b, cid_a, n, 15,
                                        np.random.default_rng(1))
    lo2, hi2 = a1.cluster_bootstrap_ci(codes_b, codes_a, 5, cid_b, cid_a, n, 15,
                                        np.random.default_rng(1))
    assert abs(lo - lo2) < 0.05 and abs(hi - hi2) < 0.05


def _row(flow, hostpair, two_stage, timeblock=None):
    r = {
        "flow_auc_signed": 0.7, "flow_ci_lo": flow[0], "flow_ci_hi": flow[1],
        "hostpair_ci_lo": hostpair[0], "hostpair_ci_hi": hostpair[1],
        "two_stage_ci_lo": two_stage[0], "two_stage_ci_hi": two_stage[1],
    }
    if timeblock is not None:
        r["timeblock_300s_ci_lo"], r["timeblock_300s_ci_hi"] = timeblock
    return r


def test_stable_is_false_when_computed_cis_disagree_in_sign():
    """Regression test for the same_side no-op bug: the original code was
    `len({r["flow_auc_signed"] > 0.5 for _ in cis}) == 1`, which iterates
    over cis but re-evaluates the same constant boolean every time, so it
    was unconditionally True regardless of the CIs. Here every CI is
    individually confident (none straddles 0.5), but they disagree in
    direction -- flow and host-pair are positive, two-stage is negative.
    The no-op bug would return True; the fix must return False."""
    row = _row(flow=(0.6, 0.8), hostpair=(0.55, 0.75), two_stage=(0.2, 0.4))
    assert a1.stable(row) is False


def test_stable_is_true_when_all_computed_cis_agree_and_are_confident():
    """Same shape of row as above, but all CIs agree (all positive) and are
    all confident. This is the case that actually distinguishes the fix from
    the no-op bug: the no-op also returns True here, so this test alone
    would not have caught the regression -- paired with the disagreeing case
    above, the two together do."""
    row = _row(flow=(0.6, 0.8), hostpair=(0.55, 0.75), two_stage=(0.58, 0.9),
               timeblock=(0.52, 0.7))
    assert a1.stable(row) is True


def test_stable_is_false_when_any_computed_ci_straddles_neutral():
    """A CI that straddles 0.5 is not confident, regardless of agreement
    elsewhere -- distinct from the sign-disagreement case above."""
    row = _row(flow=(0.6, 0.8), hostpair=(0.4, 0.6), two_stage=(0.58, 0.9))
    assert a1.stable(row) is False


def test_stable_is_none_when_group_was_not_verifiable():
    row = {"flow_auc_signed": 0.3, "flow_ci_lo": 0.2, "flow_ci_hi": 0.4,
           "hostpair_ci_lo": None, "hostpair_ci_hi": None,
           "two_stage_ci_lo": None, "two_stage_ci_hi": None}
    assert a1.stable(row) is None
