"""
Construct temporal flow graphs from ingested network data.

Each time window produces a directed, weighted graph where:
- Nodes = unique IPs (hosts)
- Edges = flows between hosts, weighted by count or byte volume (WindowConfig.weight_by)
- Direction = src -> dst
"""

from dataclasses import dataclass

import numpy as np
import polars as pl
import torch
from torch_geometric.data import Data

VALID_WEIGHT_BY = ("count", "bytes")


@dataclass
class WindowConfig:
    """Configuration for temporal windowing."""

    window_seconds: int = 60
    stride_seconds: int | None = None  # None = non-overlapping
    weight_by: str = "count"  # "count" (number of flows) or "bytes" (totlen_fwd_pkts sum)
    classic_feature_cols: list[str] | None = None  # per-flow columns to mean-aggregate per window

    def __post_init__(self):
        if self.stride_seconds is None:
            self.stride_seconds = self.window_seconds
        if self.weight_by not in VALID_WEIGHT_BY:
            raise ValueError(f"weight_by must be one of {VALID_WEIGHT_BY}, got {self.weight_by!r}")


def _build_single_graph(
    window_df: pl.DataFrame,
    window_start: int,
    window_end: int,
    weight_by: str = "count",
    classic_feature_cols: list[str] | None = None,
) -> Data:
    """Build a PyG Data object from a single time window's flows."""
    if window_df.is_empty():
        return None

    src_ips = window_df["src_ip"].to_list()
    dst_ips = window_df["dst_ip"].to_list()

    # Build node index mapping
    all_ips = sorted(set(src_ips + dst_ips))
    ip_to_idx = {ip: i for i, ip in enumerate(all_ips)}
    num_nodes = len(all_ips)

    # Build edge index and weights
    src_indices = [ip_to_idx[ip] for ip in src_ips]
    dst_indices = [ip_to_idx[ip] for ip in dst_ips]

    # Per-row weight contribution: 1 per flow, or bytes sent in the src->dst
    # direction of that flow (totlen_fwd_pkts), depending on weight_by.
    if weight_by == "bytes":
        if "totlen_fwd_pkts" not in window_df.columns:
            raise ValueError(
                "weight_by='bytes' requires a 'totlen_fwd_pkts' column (bytes sent in "
                "the src->dst direction of each flow), which is not present in this "
                "DataFrame. Use weight_by='count' or provide that column."
            )
        row_weights = window_df["totlen_fwd_pkts"].fill_null(0.0).to_list()
    else:
        row_weights = [1.0] * len(src_indices)

    # Edge weights: aggregate by (src, dst) pair
    edge_pairs = list(zip(src_indices, dst_indices))
    pair_weights: dict[tuple[int, int], float] = {}
    for pair, w in zip(edge_pairs, row_weights):
        pair_weights[pair] = pair_weights.get(pair, 0.0) + w

    # Deduplicated edges
    unique_src, unique_dst, weights = [], [], []
    for (s, d), w in pair_weights.items():
        unique_src.append(s)
        unique_dst.append(d)
        weights.append(w)

    edge_index = torch.tensor([unique_src, unique_dst], dtype=torch.long)
    edge_weight = torch.tensor(weights, dtype=torch.float)

    # Node features: in-degree, out-degree, total bytes in/out
    in_degree = np.zeros(num_nodes, dtype=np.float32)
    out_degree = np.zeros(num_nodes, dtype=np.float32)
    for s, d, w in zip(unique_src, unique_dst, weights):
        out_degree[s] += w
        in_degree[d] += w

    node_features = torch.tensor(
        np.stack([in_degree, out_degree], axis=1), dtype=torch.float
    )

    # Aggregate labels: fraction of attack flows in this window
    attack_ratio = window_df["is_attack"].mean()
    has_attack = int(attack_ratio > 0)

    # Per-flow labels for detailed analysis
    flow_labels = torch.tensor(
        window_df["is_attack"].to_numpy(), dtype=torch.long
    )

    # Original label distribution
    label_col = window_df["label"] if "label" in window_df.columns else None
    attack_types = label_col.value_counts().to_dict() if label_col is not None else {}

    data = Data(
        x=node_features,
        edge_index=edge_index,
        edge_attr=edge_weight.unsqueeze(1),
        num_nodes=num_nodes,
    )
    data.window_start = window_start
    data.window_end = window_end
    data.attack_ratio = attack_ratio
    data.has_attack = has_attack
    data.flow_labels = flow_labels
    data.ip_map = ip_to_idx
    data.num_flows = len(window_df)
    data.attack_types = attack_types

    # Mean-aggregate requested per-flow "classic" (non-graph) feature columns
    # over this window, computed here while the window slice is already in
    # hand — avoids re-deriving window boundaries elsewhere to join them back.
    classic_features: dict[str, float] = {}
    if classic_feature_cols:
        for col in classic_feature_cols:
            if col in window_df.columns:
                mean_val = window_df[col].mean()
                classic_features[col] = float(mean_val) if mean_val is not None else 0.0
    data.classic_features = classic_features

    return data


def build_temporal_graphs(
    df: pl.DataFrame,
    config: WindowConfig | None = None,
) -> list[Data]:
    """
    Build a list of PyG graph snapshots from flow data.

    Parameters
    ----------
    df : pl.DataFrame
        Ingested flow data with columns: timestamp, src_ip, dst_ip, is_attack, label, ...
    config : WindowConfig
        Temporal windowing configuration.

    Returns
    -------
    list[Data]
        One PyG Data object per time window.
    """
    if config is None:
        config = WindowConfig()

    required = {"timestamp", "src_ip", "dst_ip", "is_attack"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Sort by timestamp
    df = df.sort("timestamp")

    # Get time range
    ts_col = df["timestamp"]
    t_min = ts_col.min()
    t_max = ts_col.max()

    if t_min is None or t_max is None:
        return []

    from datetime import timedelta

    window_delta = timedelta(seconds=config.window_seconds)
    stride_delta = timedelta(seconds=config.stride_seconds)

    graphs = []
    current_start = t_min

    while current_start <= t_max:
        current_end = current_start + window_delta

        # Filter flows in this window
        window_df = df.filter(
            (pl.col("timestamp") >= current_start) & (pl.col("timestamp") < current_end)
        )

        if not window_df.is_empty():
            has_ts = hasattr(current_start, "timestamp")
            graph = _build_single_graph(
                window_df,
                window_start=int(current_start.timestamp()) if has_ts else 0,
                window_end=int(current_end.timestamp()) if has_ts else 0,
                weight_by=config.weight_by,
                classic_feature_cols=config.classic_feature_cols,
            )
            if graph is not None:
                graphs.append(graph)

        current_start += stride_delta

    return graphs
