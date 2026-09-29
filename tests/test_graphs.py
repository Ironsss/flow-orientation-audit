"""Tests for graph construction."""

from datetime import datetime, timedelta

import polars as pl
import pytest

from src.graphs.builder import WindowConfig, build_temporal_graphs


def _make_sample_flows(with_bytes: bool = False) -> pl.DataFrame:
    """Create a small sample flow DataFrame."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    records = []
    for i in range(100):
        record = {
            "timestamp": base_time + timedelta(seconds=i),
            "src_ip": f"10.0.0.{i % 5 + 1}",
            "dst_ip": f"10.0.0.{(i + 1) % 5 + 1}",
            "is_attack": 0 if i < 80 else 1,
            "label": "Benign" if i < 80 else "DDoS",
        }
        if with_bytes:
            # Deliberately non-uniform so byte-weighted and count-weighted
            # graphs are distinguishable in tests.
            record["totlen_fwd_pkts"] = float(100 + i * 10)
        records.append(record)
    return pl.DataFrame(records)


class TestBuildTemporalGraphs:
    def test_produces_graphs(self):
        df = _make_sample_flows()
        config = WindowConfig(window_seconds=30)
        graphs = build_temporal_graphs(df, config)
        assert len(graphs) > 0

    def test_graph_has_expected_attributes(self):
        df = _make_sample_flows()
        config = WindowConfig(window_seconds=120)
        graphs = build_temporal_graphs(df, config)
        g = graphs[0]
        assert g.num_nodes > 0
        assert g.edge_index.size(1) > 0
        assert hasattr(g, "has_attack")
        assert hasattr(g, "num_flows")

    def test_window_config_defaults(self):
        config = WindowConfig()
        assert config.window_seconds == 60
        assert config.stride_seconds == 60
        assert config.weight_by == "count"

    def test_window_config_rejects_invalid_weight_by(self):
        with pytest.raises(ValueError):
            WindowConfig(weight_by="nonsense")

    def test_weight_by_bytes_differs_from_count(self):
        df = _make_sample_flows(with_bytes=True)
        cfg_count = WindowConfig(window_seconds=120, weight_by="count")
        cfg_bytes = WindowConfig(window_seconds=120, weight_by="bytes")
        graphs_count = build_temporal_graphs(df, cfg_count)
        graphs_bytes = build_temporal_graphs(df, cfg_bytes)

        assert len(graphs_count) == len(graphs_bytes) > 0
        # Same edges, but weights should differ: one is a flow count, the
        # other a sum of totlen_fwd_pkts, and the sample data was built so
        # these are never numerically equal.
        w_count = graphs_count[0].edge_attr.flatten().tolist()
        w_bytes = graphs_bytes[0].edge_attr.flatten().tolist()
        assert w_count != w_bytes
        assert all(w > 1.0 for w in w_bytes)  # byte volumes, not small counts

    def test_weight_by_bytes_requires_totlen_fwd_pkts_column(self):
        df = _make_sample_flows(with_bytes=False)  # no totlen_fwd_pkts column
        config = WindowConfig(window_seconds=120, weight_by="bytes")
        with pytest.raises(ValueError):
            build_temporal_graphs(df, config)
