"""Tests for information tiers, feature extractors and restriction operators."""

import numpy as np
import polars as pl
import pytest

from src.features import (
    FEATURE_TIERS,
    PERFLOW_FEATURES,
    SIZE_FEATURES,
    TOPOLOGY_FEATURES,
    InfoTier,
    features_at_tier,
    perflow_features,
    size_features,
    topology_features,
    window_features,
)
from src.restriction import enforce_tier, sample, truncate


def _flow_frame(n=600, n_hosts=20, attack_from=None, seed=0, n_windows=10):
    """Synthetic flow frame in the shape the loader produces.

    `attack_from` marks flows after that index as attack, so positives and
    negatives come from one frame -- control C2 by construction.

    Flows are spread evenly over `n_windows` 60-second windows, so each window
    holds n/n_windows flows. That has to stay comfortably above the `min_flows`
    default or every window is discarded as degenerate (C4) and the frame comes
    back empty.
    """
    rng = np.random.default_rng(seed)
    hosts = [f"10.0.0.{i}" for i in range(n_hosts)]
    # Build as a numpy datetime64 array so polars infers a Datetime column: a
    # Python list of np.datetime64 arrives as Object and cannot cast. Polars
    # accepts only D/ms/us/ns resolutions, so seconds are widened to us.
    span_seconds = max(n_windows * 60, 1)
    offsets = np.linspace(0, span_seconds - 1, n).astype("int64").astype("timedelta64[s]")
    return pl.DataFrame({
        "timestamp": (np.datetime64("2024-01-01T00:00:00") + offsets).astype("datetime64[us]"),
        "src_ip": rng.choice(hosts, n),
        "dst_ip": rng.choice(hosts, n),
        "totlen_fwd_pkts": rng.random(n) * 1e4,
        "totlen_bwd_pkts": rng.random(n) * 1e4,
        "tot_fwd_pkts": rng.integers(1, 50, n),
        "tot_bwd_pkts": rng.integers(1, 50, n),
        "is_attack": np.array([1 if (attack_from is not None and i >= attack_from) else 0
                               for i in range(n)]),
    })


class TestInfoTier:
    def test_tiers_are_ordered_so_comparison_selects_features(self):
        """The ordering is load-bearing: `tier <= X` is how an arm is built."""
        assert InfoTier.TUPLES < InfoTier.COUNTS < InfoTier.DIRECTIONAL < InfoTier.FULL

    def test_tuples_tier_excludes_perflow_features(self):
        available = features_at_tier(InfoTier.TUPLES)
        assert not any(f in available for f in PERFLOW_FEATURES)
        assert all(f in available for f in TOPOLOGY_FEATURES)

    def test_directional_tier_includes_perflow(self):
        available = features_at_tier(InfoTier.DIRECTIONAL)
        assert all(f in available for f in PERFLOW_FEATURES)
        assert all(f in available for f in TOPOLOGY_FEATURES)

    def test_every_feature_declares_a_tier(self):
        for name in TOPOLOGY_FEATURES + PERFLOW_FEATURES + SIZE_FEATURES:
            assert name in FEATURE_TIERS, f"{name} has no declared tier"

    def test_feature_selection_is_deterministic(self):
        assert features_at_tier(InfoTier.FULL) == features_at_tier(InfoTier.FULL)


class TestTopologyFeatures:
    def test_star_concentrates_indegree(self):
        """A many-to-one flood: every source hits one destination."""
        f = topology_features([f"h{i}" for i in range(10)], ["victim"] * 10)
        assert f["top_maxindeg_frac"] == pytest.approx(1.0)
        assert f["top_reciprocity"] == 0.0

    def test_fanout_concentrates_outdegree(self):
        """A scanner: one source hits every destination."""
        f = topology_features(["scanner"] * 10, [f"h{i}" for i in range(10)])
        assert f["top_fanout_max_frac"] == pytest.approx(1.0)

    def test_symmetric_graph_is_fully_reciprocal(self):
        f = topology_features(["a", "b"], ["b", "a"])
        assert f["top_reciprocity"] == pytest.approx(1.0)

    def test_concentration_features_are_scale_invariant(self):
        """The property that keeps topology from being a node count in disguise.

        A 10-source flood and a 100-source flood have the same *shape* -- one
        victim absorbing everything -- so the concentration features agree
        while the size features differ tenfold.
        """
        small = topology_features([f"h{i}" for i in range(10)], ["v"] * 10)
        large = topology_features([f"h{i}" for i in range(100)], ["v"] * 100)
        for name in ("top_maxindeg_frac", "top_reciprocity", "top_indeg_gini"):
            assert small[name] == pytest.approx(large[name]), name
        assert (
            size_features([f"h{i}" for i in range(10)], ["v"] * 10)["sz_nodes"]
            != size_features([f"h{i}" for i in range(100)], ["v"] * 100)["sz_nodes"]
        )

    def test_fanout_fraction_is_not_scale_invariant_for_distributed_senders(self):
        """A documented limitation rather than a bug.

        `top_fanout_max_frac` is max out-degree over edge count. When every
        sender sends exactly once it is 1/n_edges, so it shrinks as the flood
        widens. That is arguably the honest answer -- one sender owning all ten
        edges is a different shape from ten senders owning one each -- but it
        does mean this particular feature carries some size information, and
        the C1 control exists partly to catch that.
        """
        small = topology_features([f"h{i}" for i in range(10)], ["v"] * 10)
        large = topology_features([f"h{i}" for i in range(100)], ["v"] * 100)
        assert small["top_fanout_max_frac"] == pytest.approx(0.1)
        assert large["top_fanout_max_frac"] == pytest.approx(0.01)

        # A single scanner, by contrast, pins it at 1.0 at any size.
        for k in (10, 100):
            f = topology_features(["scanner"] * k, [f"h{i}" for i in range(k)])
            assert f["top_fanout_max_frac"] == pytest.approx(1.0)

    def test_empty_input_returns_zeros_not_an_error(self):
        """Sparse windows are ordinary in real captures."""
        f = topology_features([], [])
        assert set(f) == set(TOPOLOGY_FEATURES)
        assert all(v == 0.0 for v in f.values())

    def test_gini_is_zero_when_load_is_even(self):
        f = topology_features(["a", "b", "c"], ["x", "y", "z"])
        assert f["top_indeg_gini"] == pytest.approx(0.0, abs=1e-9)


class TestPerflowFeatures:
    def test_detects_outbound_dominance(self):
        f = perflow_features(np.full(50, 1e5), np.full(50, 1.0))
        assert f["fl_mean"] > 5
        assert f["fl_frac_gt1"] == pytest.approx(1.0)

    def test_balanced_traffic_scores_near_zero(self):
        f = perflow_features(np.full(50, 1e3), np.full(50, 1e3))
        assert f["fl_mean"] == pytest.approx(0.0, abs=1e-9)

    def test_empty_input_returns_zeros(self):
        assert all(v == 0.0 for v in perflow_features(np.array([]), np.array([])).values())


class TestRestrictionOperators:
    def test_sampling_keeps_roughly_one_in_rate(self):
        df = _flow_frame(n=10000)
        kept = len(sample(df, rate=10, seed=0))
        assert 800 < kept < 1200, f"expected ~1000, got {kept}"

    def test_sampling_rate_one_is_identity(self):
        df = _flow_frame(n=100)
        assert len(sample(df, rate=1)) == len(df)

    def test_sampling_is_reproducible_under_a_seed(self):
        df = _flow_frame(n=2000)
        assert len(sample(df, rate=5, seed=7)) == len(sample(df, rate=5, seed=7))

    def test_sampling_rejects_rate_below_one(self):
        with pytest.raises(ValueError, match="rate"):
            sample(_flow_frame(n=10), rate=0)

    def test_truncation_keeps_only_early_flows(self):
        df = _flow_frame(n=1000)
        full, early = len(df), len(truncate(df, window_seconds=60, observed_fraction=0.25))
        assert early < full

    def test_truncation_at_one_is_identity(self):
        df = _flow_frame(n=100)
        assert len(truncate(df, 60, 1.0)) == len(df)

    def test_truncation_rejects_out_of_range_fraction(self):
        with pytest.raises(ValueError, match="observed_fraction"):
            truncate(_flow_frame(n=10), 60, 1.5)

    def test_enforce_tier_removes_the_columns_a_tier_cannot_see(self):
        """The strict restriction: per-flow features become uncomputable
        because the data is gone, not because they were skipped."""
        restricted = enforce_tier(_flow_frame(n=100), InfoTier.TUPLES)
        assert "totlen_fwd_pkts" not in restricted.columns
        assert {"src_ip", "dst_ip", "timestamp"} <= set(restricted.columns)

    def test_enforce_tier_always_keeps_the_label(self):
        """Telemetry poverty says nothing about whether ground truth was known."""
        assert "is_attack" in enforce_tier(_flow_frame(n=100), InfoTier.TUPLES).columns

    def test_enforce_tier_full_keeps_everything(self):
        df = _flow_frame(n=50)
        assert set(enforce_tier(df, InfoTier.FULL).columns) == set(df.columns)

    def test_enforce_tier_raises_when_a_required_column_is_absent(self):
        df = _flow_frame(n=50).drop("totlen_fwd_pkts")
        with pytest.raises(ValueError, match="lacks columns"):
            enforce_tier(df, InfoTier.DIRECTIONAL)


class TestWindowFeatures:
    def test_produces_one_row_per_window_with_a_label(self):
        out = window_features(_flow_frame(n=2000, attack_from=1000), tier=InfoTier.DIRECTIONAL)
        assert len(out) > 0
        assert {"y", "attack_ratio", "n_flows"} <= set(out.columns)

    def test_tuples_tier_omits_perflow_columns(self):
        out = window_features(_flow_frame(n=2000), tier=InfoTier.TUPLES)
        assert not any(f in out.columns for f in PERFLOW_FEATURES)
        assert all(f in out.columns for f in TOPOLOGY_FEATURES)

    def test_size_features_are_always_present_as_the_c1_control(self):
        """C1 is not optional -- every comparison must be able to report it."""
        for tier in (InfoTier.TUPLES, InfoTier.DIRECTIONAL):
            out = window_features(_flow_frame(n=2000), tier=tier)
            assert all(f in out.columns for f in SIZE_FEATURES), tier

    def test_degenerate_windows_are_dropped(self):
        """C4. A 4-node, 2-flow window once flipped Cohen's d negative for
        every IAG component."""
        out = window_features(_flow_frame(n=2000), tier=InfoTier.TUPLES, min_flows=50)
        assert (out["n_flows"] >= 50).all()

    def test_label_threshold_is_applied(self):
        """C5. attack_ratio > 0 once let a 99.3%-benign window count as attack."""
        df = _flow_frame(n=2000, attack_from=1990)  # a sliver of attack at the end
        loose = window_features(df, tier=InfoTier.TUPLES, tau=0.001)
        strict = window_features(df, tier=InfoTier.TUPLES, tau=0.5)
        assert loose["y"].sum() >= strict["y"].sum()

    def test_raises_when_the_tier_needs_a_column_restriction_removed(self):
        restricted = enforce_tier(_flow_frame(n=500), InfoTier.TUPLES)
        with pytest.raises(ValueError, match="requires"):
            window_features(restricted, tier=InfoTier.DIRECTIONAL)

    def test_rejects_a_frame_missing_required_columns(self):
        with pytest.raises(ValueError, match="missing required columns"):
            window_features(_flow_frame(n=100).drop("src_ip"), tier=InfoTier.TUPLES)

    def test_rejects_out_of_range_tau(self):
        with pytest.raises(ValueError, match="tau"):
            window_features(_flow_frame(n=100), tier=InfoTier.TUPLES, tau=0.0)

    def test_empty_frame_returns_empty_not_an_error(self):
        assert len(window_features(_flow_frame(n=0), tier=InfoTier.TUPLES)) == 0

    def test_restriction_then_extraction_composes(self):
        """The pipeline the experiment actually runs: restrict, then extract."""
        df = sample(_flow_frame(n=8000, attack_from=4000), rate=2, seed=0)
        out = window_features(df, tier=InfoTier.TUPLES, min_flows=5)
        assert len(out) > 0
        assert all(f in out.columns for f in TOPOLOGY_FEATURES)
