"""scripts/dependence_cluster_bootstrap.py: weighted_auc must reduce to the
existing unweighted AUC engine when every weight is 1, and must match a
hand-computed value when cluster weights are unequal (the actual behavior a
cluster bootstrap relies on -- a cluster drawn twice must count twice)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

_p = Path(__file__).resolve().parents[1] / "scripts" / "dependence_cluster_bootstrap.py"
_spec = importlib.util.spec_from_file_location("dep_boot", _p)
dep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dep)


def test_weight_one_matches_unweighted_reference():
    rng = np.random.default_rng(0)
    benign = rng.integers(-5, 6, 3000).astype(float)
    attack = rng.integers(-3, 9, 700).astype(float)
    values, inv = np.unique(np.r_[benign, attack], return_inverse=True)
    codes_b, codes_a = inv[: len(benign)], inv[len(benign):]
    auc = dep.weighted_auc(np.ones(len(benign)), codes_b, np.ones(len(attack)), codes_a,
                            len(values))
    y = np.r_[np.zeros(len(benign)), np.ones(len(attack))]
    assert abs(auc - roc_auc_score(y, np.r_[benign, attack])) < 1e-12


def test_duplicated_cluster_weight_matches_expanded_rows():
    """Weighting row i by w[i] must equal literally repeating that row w[i]
    times -- the property the whole cluster bootstrap depends on."""
    rng = np.random.default_rng(1)
    benign = rng.integers(-5, 6, 50).astype(float)
    attack = rng.integers(-3, 9, 20).astype(float)
    w_b = rng.integers(1, 4, len(benign))
    w_a = rng.integers(1, 4, len(attack))

    values, inv = np.unique(np.r_[benign, attack], return_inverse=True)
    codes_b, codes_a = inv[: len(benign)], inv[len(benign):]
    weighted = dep.weighted_auc(w_b.astype(float), codes_b, w_a.astype(float), codes_a,
                                 len(values))

    expanded_b = np.repeat(benign, w_b)
    expanded_a = np.repeat(attack, w_a)
    values2, inv2 = np.unique(np.r_[expanded_b, expanded_a], return_inverse=True)
    c_b2, c_a2 = inv2[: len(expanded_b)], inv2[len(expanded_b):]
    expanded = dep.weighted_auc(np.ones(len(expanded_b)), c_b2, np.ones(len(expanded_a)), c_a2,
                                 len(values2))
    assert abs(weighted - expanded) < 1e-12


def test_min_clusters_gate_blocks_degenerate_groups():
    assert dep.MIN_CLUSTERS >= 10  # the call this project made; see cluster_inventory findings
