"""Tests for IAG computation."""

import numpy as np
import pytest
import torch
from torch_geometric.data import Data

from src.iag.index import (
    compute_iag,
    compute_iag_batch,
    directional_asymmetry,
    entropic_asymmetry,
    fit_iag_weights,
)


def _make_symmetric_graph() -> Data:
    """Create a simple symmetric graph: A<->B, B<->C, A<->C."""
    edge_index = torch.tensor(
        [[0, 1, 1, 2, 0, 2], [1, 0, 2, 1, 2, 0]], dtype=torch.long
    )
    edge_attr = torch.ones(6, 1)
    return Data(x=torch.zeros(3, 2), edge_index=edge_index, edge_attr=edge_attr, num_nodes=3)


def _make_asymmetric_graph() -> Data:
    """Create a highly asymmetric graph: A->B, A->C, A->D (star, all outgoing)."""
    edge_index = torch.tensor(
        [[0, 0, 0], [1, 2, 3]], dtype=torch.long
    )
    edge_attr = torch.ones(3, 1)
    return Data(x=torch.zeros(4, 2), edge_index=edge_index, edge_attr=edge_attr, num_nodes=4)


def _make_empty_graph() -> Data:
    """Create an empty graph."""
    edge_index = torch.zeros(2, 0, dtype=torch.long)
    return Data(x=torch.zeros(1, 2), edge_index=edge_index, num_nodes=1)


class TestDirectionalAsymmetry:
    def test_symmetric_graph(self):
        g = _make_symmetric_graph()
        a_dir = directional_asymmetry(g)
        assert a_dir == pytest.approx(0.0, abs=0.01)

    def test_asymmetric_graph(self):
        g = _make_asymmetric_graph()
        a_dir = directional_asymmetry(g)
        assert a_dir == pytest.approx(1.0, abs=0.01)

    def test_empty_graph(self):
        g = _make_empty_graph()
        a_dir = directional_asymmetry(g)
        assert a_dir == 0.0


class TestEntropicAsymmetry:
    def test_symmetric_graph(self):
        g = _make_symmetric_graph()
        a_ent = entropic_asymmetry(g)
        assert a_ent == pytest.approx(0.0, abs=0.1)

    def test_asymmetric_graph(self):
        g = _make_asymmetric_graph()
        a_ent = entropic_asymmetry(g)
        assert a_ent > 0.0  # Should detect the in/out degree imbalance

    def test_empty_graph(self):
        g = _make_empty_graph()
        a_ent = entropic_asymmetry(g)
        assert a_ent == 0.0


class TestComputeIAG:
    def test_returns_all_keys(self):
        g = _make_symmetric_graph()
        result = compute_iag(g)
        assert "iag_directional" in result
        assert "iag_entropic" in result
        assert "iag_combined" in result

    def test_symmetric_has_low_combined(self):
        g = _make_symmetric_graph()
        result = compute_iag(g)
        assert result["iag_combined"] < 0.2

    def test_asymmetric_has_high_directional(self):
        g = _make_asymmetric_graph()
        result = compute_iag(g)
        assert result["iag_directional"] > 0.8

    def test_rejects_wrong_number_of_weights(self):
        g = _make_symmetric_graph()
        with pytest.raises(ValueError):
            compute_iag(g, weights=(1 / 3, 1 / 3, 1 / 3))

    def test_custom_weights_change_combined(self):
        g = _make_asymmetric_graph()
        equal = compute_iag(g, weights=(0.5, 0.5))
        dir_only = compute_iag(g, weights=(1.0, 0.0))
        # With all weight on the directional component, combined should
        # equal the directional value exactly.
        assert dir_only["iag_combined"] == pytest.approx(dir_only["iag_directional"])
        assert dir_only["iag_combined"] != pytest.approx(equal["iag_combined"])


class TestFitIagWeights:
    def test_returns_normalized_nonnegative_weights(self):
        graphs = [_make_symmetric_graph() for _ in range(10)] + [
            _make_asymmetric_graph() for _ in range(10)
        ]
        labels = [0] * 10 + [1] * 10
        records = compute_iag_batch(graphs)

        weights = fit_iag_weights(records, labels)

        assert set(weights) == {"iag_directional", "iag_entropic"}
        assert all(w >= 0.0 for w in weights.values())
        assert sum(weights.values()) == pytest.approx(1.0)

    def test_fitted_weights_favor_directional_for_this_synthetic_split(self):
        # Symmetric vs. star-asymmetric graphs differ starkly in directional
        # asymmetry (0.0 vs ~1.0) — the fit should pick that up as the
        # dominant, positively-associated component.
        graphs = [_make_symmetric_graph() for _ in range(10)] + [
            _make_asymmetric_graph() for _ in range(10)
        ]
        labels = [0] * 10 + [1] * 10
        records = compute_iag_batch(graphs)

        weights = fit_iag_weights(records, labels)

        assert weights["iag_directional"] > 0.0

    def test_requires_both_classes(self):
        graphs = [_make_symmetric_graph() for _ in range(5)]
        labels = [0] * 5
        records = compute_iag_batch(graphs)

        with pytest.raises(ValueError):
            fit_iag_weights(records, labels)

    def test_fitted_weights_are_usable_in_compute_iag(self):
        graphs = [_make_symmetric_graph() for _ in range(10)] + [
            _make_asymmetric_graph() for _ in range(10)
        ]
        labels = [0] * 10 + [1] * 10
        records = compute_iag_batch(graphs)
        weights = fit_iag_weights(records, labels)

        w_tuple = (
            weights["iag_directional"],
            weights["iag_entropic"],
        )
        result = compute_iag(_make_asymmetric_graph(), weights=w_tuple)
        assert "iag_combined" in result
        assert np.isfinite(result["iag_combined"])


class TestDegenerateGraphs:
    """Regression tests for graph shapes that crashed or saturate the metrics.

    Found by the critical review (docs/review/): a single-edge window raised
    IndexError inside entropic_asymmetry(), and the whole pipeline aborted.
    Sparse real traffic produces such windows routinely (quiet hours, the
    first/last time bucket of a capture), so these are not synthetic cases.
    """

    def test_single_edge_graph_does_not_crash(self):
        g = Data(
            edge_index=torch.tensor([[0], [1]], dtype=torch.long),
            edge_attr=torch.ones(1, 1),
            num_nodes=2,
        )
        assert np.isfinite(entropic_asymmetry(g))
        assert np.isfinite(compute_iag(g)["iag_combined"])

    def test_single_edge_without_edge_attr(self):
        g = Data(edge_index=torch.tensor([[0], [1]], dtype=torch.long), num_nodes=2)
        assert np.isfinite(entropic_asymmetry(g))

    def test_entropic_asymmetry_saturates_at_epsilon_ceiling(self):
        """A_ent is documented as [0, inf) but is in fact bounded above by
        -ln(eps) ~= 23.026, an implementation constant rather than a property
        of the traffic. Pinned here so the bound is not silently changed by an
        edit to eps without the docs and paper being updated too.
        """
        g = Data(
            edge_index=torch.tensor([[0], [1]], dtype=torch.long),
            edge_attr=torch.ones(1, 1),
            num_nodes=2,
        )
        assert entropic_asymmetry(g) == pytest.approx(-np.log(1e-10), rel=1e-6)
