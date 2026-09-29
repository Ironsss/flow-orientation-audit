"""Tests for the feature attribution audit protocol (src/audit/)."""

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score

from src.audit import (
    correlation_groups,
    independence_probe,
    leave_group_out,
    probe_suite,
)

# ---------------------------------------------------------------- fixtures


def _rf_fit_predict(X_train, y_train, X_test):
    clf = RandomForestClassifier(n_estimators=60, random_state=0)
    clf.fit(X_train, y_train)
    return clf.predict_proba(X_test)[:, 1]


def _make_redundant_dataset(n=3000, imbalance=0.05, n_copies=3, seed=0):
    """y depends only on x0 and x1. x2..x9 are noise. Then n_copies
    near-duplicates of x0 are appended -- they add no information at all.

    This is the configuration that breaks per-column permutation importance:
    x0 is the strongest true feature, but with copies present its measured
    importance collapses to ~0 because permuting it leaves an identical copy
    for the model to read.
    """
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, 10))
    logit = 2.5 * X[:, 0] + 2.0 * X[:, 1]
    p = 1.0 / (1.0 + np.exp(-(logit - np.quantile(logit, 1 - imbalance))))
    y = (rng.random(n) < p).astype(int)
    copies = np.column_stack(
        [X[:, 0] + rng.normal(scale=0.03, size=n) for _ in range(n_copies)]
    )
    return np.hstack([X, copies]), y


# ---------------------------------------------------------- correlation_groups


class TestCorrelationGroups:
    def test_independent_features_are_all_singletons(self):
        X = np.random.default_rng(0).normal(size=(500, 6))
        groups = correlation_groups(X)
        assert groups == [[0], [1], [2], [3], [4], [5]]

    def test_near_duplicates_are_grouped(self):
        rng = np.random.default_rng(0)
        base = rng.normal(size=500)
        X = np.column_stack([base, base + rng.normal(scale=0.01, size=500), rng.normal(size=500)])
        groups = correlation_groups(X)
        assert [0, 1] in groups
        assert [2] in groups

    def test_grouping_is_transitive_single_linkage(self):
        """a~b and b~c must put a, b, c in one group even if a~c is weaker:
        redundancy chains the way that matters for ablation."""
        rng = np.random.default_rng(1)
        a = rng.normal(size=800)
        b = a + rng.normal(scale=0.05, size=800)
        c = b + rng.normal(scale=0.05, size=800)
        groups = correlation_groups(np.column_stack([a, b, c]), threshold=0.9)
        assert groups == [[0, 1, 2]]

    def test_every_column_appears_exactly_once(self):
        rng = np.random.default_rng(2)
        base = rng.normal(size=400)
        X = np.column_stack([base, base * 1.001, rng.normal(size=400), rng.normal(size=400)])
        seen = sorted(i for g in correlation_groups(X) for i in g)
        assert seen == list(range(X.shape[1]))

    def test_constant_column_stays_a_singleton(self):
        """A constant column has undefined correlation; it must not silently
        absorb other features through nan comparisons."""
        rng = np.random.default_rng(3)
        X = np.column_stack([np.ones(300), rng.normal(size=300), rng.normal(size=300)])
        assert [0] in correlation_groups(X)

    def test_rejects_mismatched_feature_names(self):
        X = np.random.default_rng(0).normal(size=(50, 3))
        with pytest.raises(ValueError, match="feature_names"):
            correlation_groups(X, feature_names=["a", "b"])

    def test_rejects_out_of_range_threshold(self):
        X = np.random.default_rng(0).normal(size=(50, 3))
        with pytest.raises(ValueError, match="threshold"):
            correlation_groups(X, threshold=1.5)


# ------------------------------------------------------------- leave_group_out


class TestLeaveGroupOut:
    def test_recovers_truth_where_per_column_importance_fails(self):
        """The protocol's central claim, as an executable test.

        x0's group (x0 + its copies) genuinely drives the label, and the
        audit must rank it above the noise features -- in the exact setup
        where per-column permutation importance ranks x0 near-last.
        """
        X, y = _make_redundant_dataset(seed=1)
        split = int(0.7 * len(y))
        groups = correlation_groups(X, threshold=0.95)
        results = leave_group_out(
            _rf_fit_predict,
            average_precision_score,
            X[:split], y[:split], X[split:], y[split:],
            groups,
        )
        top = results[0]
        assert 0 in top.indices, "the group containing x0 should rank first"
        assert top.drop > 0.0

        by_idx = {r.indices: r for r in results}
        noise = [r.drop for idx, r in by_idx.items() if set(idx).issubset({2, 3, 4, 5, 6, 7, 8, 9})]
        assert top.drop > max(noise), "signal group must beat every noise feature"

    def test_redundant_singleton_shows_no_drop(self):
        """Auditing one copy alone, while its twins remain, must report ~no
        loss. That is the correct answer to 'is this column, by itself,
        irreplaceable?' and it is why grouping is required to get the
        practitioner's intended answer instead."""
        X, y = _make_redundant_dataset(seed=2)
        split = int(0.7 * len(y))
        results = leave_group_out(
            _rf_fit_predict,
            average_precision_score,
            X[:split], y[:split], X[split:], y[split:],
            groups=[[10]],  # a single copy of x0; x0 and two more copies remain
        )
        assert results[0].drop < 0.05

    def test_results_are_sorted_by_drop_descending(self):
        X, y = _make_redundant_dataset(n=1200, seed=3)
        split = int(0.7 * len(y))
        results = leave_group_out(
            _rf_fit_predict, average_precision_score,
            X[:split], y[:split], X[split:], y[split:],
            groups=[[0], [1], [2], [3]],
        )
        drops = [r.drop for r in results]
        assert drops == sorted(drops, reverse=True)

    def test_drop_equals_full_minus_without(self):
        X, y = _make_redundant_dataset(n=1000, seed=4)
        split = int(0.7 * len(y))
        for r in leave_group_out(
            _rf_fit_predict, average_precision_score,
            X[:split], y[:split], X[split:], y[split:], groups=[[0], [5]],
        ):
            assert r.drop == pytest.approx(r.score_full - r.score_without)

    def test_names_are_attached(self):
        X, y = _make_redundant_dataset(n=800, seed=5)
        split = int(0.7 * len(y))
        names = [f"feat{i}" for i in range(X.shape[1])]
        results = leave_group_out(
            _rf_fit_predict, average_precision_score,
            X[:split], y[:split], X[split:], y[split:],
            groups=[[0, 10]], feature_names=names,
        )
        assert results[0].names == ("feat0", "feat10")

    def test_rejects_group_index_out_of_range(self):
        X, y = _make_redundant_dataset(n=400, seed=6)
        split = int(0.7 * len(y))
        with pytest.raises(ValueError, match="outside"):
            leave_group_out(
                _rf_fit_predict, average_precision_score,
                X[:split], y[:split], X[split:], y[split:], groups=[[99]],
            )

    def test_rejects_train_test_column_mismatch(self):
        X, y = _make_redundant_dataset(n=400, seed=7)
        split = int(0.7 * len(y))
        with pytest.raises(ValueError, match="columns"):
            leave_group_out(
                _rf_fit_predict, average_precision_score,
                X[:split], y[:split], X[split:, :-1], y[split:], groups=[[0]],
            )


# ---------------------------------------------------------- independence_probe


class TestIndependenceProbe:
    def test_passes_when_candidate_separates_a_valid_control_pair(self):
        existing = {"sum": lambda v: v[0] + v[1]}
        candidate = lambda v: v[0] - v[1]  # noqa: E731
        r = independence_probe(candidate, existing, ((1.0, 3.0), (3.0, 1.0)), min_separation=1.0)
        assert r.passed and r.controls_held
        assert r.candidate_separation == pytest.approx(4.0)

    def test_fails_when_candidate_is_redundant(self):
        """A candidate that is a deterministic function of an existing feature
        cannot separate a pair the existing feature scores equally."""
        existing = {"sum": lambda v: v[0] + v[1]}
        candidate = lambda v: 2.0 * (v[0] + v[1]) + 1.0  # noqa: E731
        r = independence_probe(candidate, existing, ((1.0, 3.0), (3.0, 1.0)), min_separation=0.5)
        assert not r.passed
        assert r.controls_held, "the control pair was valid; this is a real failure"
        assert "redundant" in r.reason

    def test_void_when_control_pair_is_broken(self):
        """If an existing feature already separates the pair, the probe proves
        nothing -- and must say so rather than reporting a pass."""
        existing = {"first": lambda v: v[0]}
        candidate = lambda v: v[0] - v[1]  # noqa: E731
        r = independence_probe(candidate, existing, ((1.0, 3.0), (3.0, 1.0)), min_separation=0.5)
        assert not r.passed
        assert not r.controls_held
        assert r.violating_controls == ("first",)
        assert "VOID" in r.reason

    def test_non_finite_candidate_fails_cleanly(self):
        existing = {"sum": lambda v: v[0] + v[1]}
        r = independence_probe(
            lambda v: float("nan"), existing, ((1.0, 3.0), (3.0, 1.0)), min_separation=0.5
        )
        assert not r.passed and "non-finite" in r.reason

    def test_requires_min_separation_declared_positive(self):
        """Guards the protocol's one procedural rule: the threshold is
        declared before the run, so a zero or negative value is a misuse."""
        with pytest.raises(ValueError, match="min_separation"):
            independence_probe(lambda v: v[0], {"a": lambda v: v[1]}, ((1, 2), (3, 4)),
                               min_separation=0.0)

    def test_all_existing_features_are_checked(self):
        existing = {"sum": lambda v: v[0] + v[1], "leak": lambda v: v[0]}
        candidate = lambda v: v[0] - v[1]  # noqa: E731
        r = independence_probe(candidate, existing, ((1.0, 3.0), (3.0, 1.0)), min_separation=0.5)
        assert r.violating_controls == ("leak",)

    def test_probe_suite_returns_one_result_per_pair_including_void(self):
        existing = {"sum": lambda v: v[0] + v[1]}
        candidate = lambda v: v[0] - v[1]  # noqa: E731
        pairs = [((1.0, 3.0), (3.0, 1.0)), ((0.0, 0.0), (0.0, 0.0))]
        results = probe_suite(candidate, existing, pairs, min_separation=1.0)
        assert len(results) == 2
        assert results[0].passed
        assert not results[1].passed  # identical inputs cannot be separated


class TestProbeOnThisProjectsHistory:
    """The probe reproduced on the case that produced it.

    A DDoS-like star and a directed cycle both have directional asymmetry
    exactly 1.0, so they form a valid control pair for any feature claiming to
    measure structure beyond edge reciprocity. Entropic asymmetry separates
    them; the retired spectral formulations did not.
    """

    def test_entropic_asymmetry_passes_the_star_vs_cycle_probe(self):
        import torch
        from torch_geometric.data import Data

        from src.iag.index import directional_asymmetry, entropic_asymmetry

        n = 8
        star = Data(
            edge_index=torch.tensor([[0] * (n - 1), list(range(1, n))], dtype=torch.long),
            edge_attr=torch.ones(n - 1, 1), num_nodes=n,
        )
        cycle = Data(
            edge_index=torch.tensor(
                [list(range(n)), [(i + 1) % n for i in range(n)]], dtype=torch.long
            ),
            edge_attr=torch.ones(n, 1), num_nodes=n,
        )
        result = independence_probe(
            entropic_asymmetry,
            {"A_dir": directional_asymmetry},
            (star, cycle),
            min_separation=0.5,
            control_tolerance=1e-6,
            candidate_name="A_ent",
        )
        assert result.controls_held, "star and cycle must both have A_dir = 1.0"
        assert result.passed

    def test_a_transpose_style_feature_fails_the_same_probe(self):
        """Stand-in for the original spectral formulation, whose defect was
        that eigenvalues of A and A^T coincide for every matrix, making the
        feature a constant. A constant cannot separate any pair."""
        import torch
        from torch_geometric.data import Data

        from src.iag.index import directional_asymmetry

        n = 8
        star = Data(
            edge_index=torch.tensor([[0] * (n - 1), list(range(1, n))], dtype=torch.long),
            edge_attr=torch.ones(n - 1, 1), num_nodes=n,
        )
        cycle = Data(
            edge_index=torch.tensor(
                [list(range(n)), [(i + 1) % n for i in range(n)]], dtype=torch.long
            ),
            edge_attr=torch.ones(n, 1), num_nodes=n,
        )
        result = independence_probe(
            lambda g: 0.0,  # what lambda(A) vs lambda(A^T) actually returns
            {"A_dir": directional_asymmetry},
            (star, cycle),
            min_separation=0.05,
            control_tolerance=1e-6,
            candidate_name="A_spec (original)",
        )
        assert result.controls_held
        assert not result.passed


class TestCorrelationThresholdDefault:
    """The 0.80 default is a measured choice, not a convention.

    Injecting copies at a controlled correlation and reading back the
    strongest feature's permutation importance as a fraction of its
    uncontaminated value gives roughly: 0.99 -> 0% retained, 0.96 -> 13%,
    0.85 -> 42%, 0.70 -> 75%. Damage is already severe well below 0.95, which
    is why the default sits at 0.80 rather than there. These tests pin the
    consequence so the default cannot drift back without the docstring table
    and docs/protocolo/ being revisited too.
    """

    def _pair_at_correlation(self, target_noise, n=4000, seed=0):
        rng = np.random.default_rng(seed)
        base = rng.normal(size=n)
        return np.column_stack([base, base + rng.normal(scale=target_noise, size=n)])

    def test_default_groups_a_pair_that_loses_most_of_its_signal(self):
        """A pair near r=0.85 retains only ~42% of measured importance, so the
        default must group it. At the previous 0.95 default it would not have."""
        X = self._pair_at_correlation(0.6, seed=1)
        r = abs(np.corrcoef(X[:, 0], X[:, 1])[0, 1])
        assert 0.80 <= r < 0.95, f"fixture drifted: r={r:.4f}"
        assert correlation_groups(X) == [[0, 1]]
        assert correlation_groups(X, threshold=0.95) == [[0], [1]]

    def test_default_leaves_weakly_correlated_features_separate(self):
        """Around r=0.44 roughly 91% of the signal survives, so grouping there
        would merge features the audit can still separate cleanly."""
        X = self._pair_at_correlation(2.0, seed=1)
        r = abs(np.corrcoef(X[:, 0], X[:, 1])[0, 1])
        assert r < 0.80, f"fixture drifted: r={r:.4f}"
        assert correlation_groups(X) == [[0], [1]]
