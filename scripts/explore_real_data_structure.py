#!/usr/bin/env python3
"""
Structural exploration of real CICIDS-2018 data: an actual interaction graph
and unsupervised clustering of flows.

scripts/analyze_real_data.py answers "what do the columns look like, one at a
time." This answers two things a table of per-column statistics cannot show:

  1. What does the traffic graph actually look like -- nodes = hosts, edges =
     flows between them -- for a real attack window vs. a real benign window?
     No figure like this existed anywhere in the repository before this
     script, despite the project's original framing being built entirely
     around graph structure.
  2. Do flows group into clusters that line up with the attack label without
     being told to (unsupervised), or is the attack scattered across the same
     clusters as benign traffic? That is the concrete link between class
     imbalance, the asymmetry signal, and how hard the problem actually looks
     to a downstream ML model.

Reuses, rather than reimplements:
  - src.graphs.builder.build_temporal_graphs for the graph construction itself
    (this script only extracts a plain edge list from its output and draws it)
  - src.viz.plots.plot_interaction_graph for the drawing
  - src.ingest.loader.load_csv / CLASSIC_FEATURES for ingestion and the
    feature set
  - the same "systematic sample, no RNG" discipline scripts/analyze_real_data.py
    already established for anything that needs a materialized matrix

Usage
-----
    python scripts/explore_real_data_structure.py \\
        data/raw/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.graphs.builder import WindowConfig, build_temporal_graphs  # noqa: E402
from src.ingest.loader import CLASSIC_FEATURES, load_csv  # noqa: E402
from src.viz.plots import plot_interaction_graph, setup_style  # noqa: E402

RESULTS_DIR = Path("results")
FIGURES_DIR = RESULTS_DIR / "figures"
METRICS_DIR = RESULTS_DIR / "metrics"

GREEN, BLUE, BOLD, NC = "\033[0;32m", "\033[0;34m", "\033[1m", "\033[0m"


def _log(msg: str) -> None:
    print(f"{BLUE}[INFO]{NC} {msg}")


def _header(msg: str) -> None:
    print(f"\n{BOLD}{msg}{NC}\n{'-' * len(msg)}")


# ------------------------------------------------------------- interaction graph
def pick_windows(flows: pl.DataFrame, window_seconds: int = 60, tau: float = 0.01):
    """Time bounds of one clearly-attack and one clearly-benign window."""
    ts = flows["timestamp"].dt.epoch("s").to_numpy()
    t0 = int(ts.min())
    bucket = (ts - t0) // window_seconds
    per_window = (
        flows.with_columns(pl.Series("w", bucket))
        .group_by("w")
        .agg(pl.col("is_attack").mean().alias("ratio"), pl.len().alias("n"))
        .filter(pl.col("n") >= 10)
        .sort("ratio", descending=True)
    )
    attack_w = int(per_window.filter(pl.col("ratio") >= tau)["w"][0])
    benign_w = int(per_window.filter(pl.col("ratio") == 0.0)["w"][-1])

    def bounds(w: int) -> tuple[int, int]:
        start = t0 + w * window_seconds
        return start, start + window_seconds

    return bounds(attack_w), bounds(benign_w)


def build_graph_edges(
    flows: pl.DataFrame, start: int, end: int, window_seconds: int
) -> tuple[list[tuple[str, str]], list[float], list[bool]]:
    """One window's edges, reusing build_temporal_graphs for the graph itself.

    That function tracks aggregate edge weight but not per-edge attack
    composition, so the attack flag per (src, dst) pair is derived here,
    directly from the same window slice, rather than added to the shared
    graph builder (kept "reused unchanged" per CLAUDE.md).
    """
    ts = flows["timestamp"].dt.epoch("s")
    window_df = flows.filter((ts >= start) & (ts < end))
    graphs = build_temporal_graphs(window_df, WindowConfig(window_seconds=window_seconds))
    if not graphs:
        return [], [], []
    g = graphs[0]
    idx_to_ip = {i: ip for ip, i in g.ip_map.items()}
    edge_index = g.edge_index.numpy()
    weights = g.edge_attr.squeeze(-1).numpy().tolist()
    edges = [
        (idx_to_ip[s], idx_to_ip[d]) for s, d in zip(edge_index[0], edge_index[1], strict=True)
    ]

    pair_attack = window_df.group_by(["src_ip", "dst_ip"]).agg(
        pl.col("is_attack").max().alias("has_attack")
    )
    attack_lookup = {
        (row["src_ip"], row["dst_ip"]): bool(row["has_attack"])
        for row in pair_attack.iter_rows(named=True)
    }
    edge_is_attack = [attack_lookup.get(e, False) for e in edges]
    return edges, weights, edge_is_attack


def make_interaction_graphs(path: Path) -> dict:
    flows = (
        load_csv(path)
        .select(["timestamp", "src_ip", "dst_ip", "is_attack"])
        .drop_nulls()
        .collect()
    )
    (attack_start, attack_end), (benign_start, benign_end) = pick_windows(flows)

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    result = {}
    for label, (start, end) in (
        ("attack", (attack_start, attack_end)),
        ("benign", (benign_start, benign_end)),
    ):
        edges, weights, edge_is_attack = build_graph_edges(flows, start, end, end - start)
        n_hosts = len({h for e in edges for h in e})
        path_out = FIGURES_DIR / f"real_data_interaction_graph_{label}.png"
        plot_interaction_graph(
            edges, edge_weights=weights, edge_is_attack=edge_is_attack,
            title=f"Ventana {label} real, DDoS-LOIC-HTTP ({end - start}s)",
            save_path=path_out,
        )
        result[label] = {
            "window_start_epoch": start, "window_end_epoch": end,
            "n_hosts": n_hosts, "n_edges": len(edges),
            "n_edges_with_attack": sum(edge_is_attack),
            "figure": str(path_out),
        }
        _log(f"{label} window: {n_hosts} hosts, {len(edges)} edges -> {path_out}")
    return result


# ------------------------------------------------------------------- clustering
def clustering_analysis(path: Path, sample_n: int = 300_000) -> dict:
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    from sklearn.metrics import silhouette_score
    from sklearn.preprocessing import StandardScaler

    lf = load_csv(path)
    total = lf.select(pl.len()).collect().item()
    stride = max(total // sample_n, 1)
    df = (
        lf.with_row_index("row_nr")
        .filter(pl.col("row_nr") % stride == 0)
        .select([*CLASSIC_FEATURES, "is_attack"])
        .drop_nulls()
        .collect()
    )

    X = df.select(CLASSIC_FEATURES).to_numpy().astype(np.float64)
    keep = X.std(axis=0) > 0
    used_cols = [c for c, k in zip(CLASSIC_FEATURES, keep, strict=True) if k]
    X = X[:, keep]
    y = df["is_attack"].to_numpy()

    # Signed log1p, then StandardScaler. CICIDS features are heavy-tailed
    # byte/time/count fields, several are extremely zero-inflated (most flag
    # counts and ratios are 0 for the overwhelming majority of flows), and a
    # few (init_fwd_win_byts/init_bwd_win_byts) use -1 as a literal "unknown"
    # sentinel -- so the transform has to be signed, not plain log1p. Two
    # earlier attempts here (StandardScaler alone; percentile-clip +
    # RobustScaler) both left the PCA projection dominated by whichever
    # column happened to have a near-zero IQR: heavy zero-inflation makes the
    # 25th/75th percentile both 0, RobustScaler's IQR=0 fallback leaves that
    # column completely unscaled, and its raw magnitude (some CICIDS time
    # fields are in microseconds) then swamps every other column in PCA.
    # Compressing the tail logarithmically first avoids that failure mode
    # instead of working around it column-by-column.
    X_log = np.sign(X) * np.log1p(np.abs(X))
    X_scaled = StandardScaler().fit_transform(X_log)

    # k via silhouette on a bounded sub-sample -- silhouette is O(n^2), the
    # full sample (hundreds of thousands of rows) would not finish in
    # reasonable time; this is a second, tighter bound within the already
    # bounded sample, not an unbounded computation.
    rng = np.random.RandomState(0)
    sub_idx = rng.choice(len(X_scaled), size=min(5000, len(X_scaled)), replace=False)
    best_k, best_score = 2, -1.0
    for k in range(2, 9):
        labels = KMeans(n_clusters=k, n_init=5, random_state=0).fit_predict(X_scaled[sub_idx])
        score = silhouette_score(X_scaled[sub_idx], labels)
        if score > best_score:
            best_k, best_score = k, score

    kmeans = KMeans(n_clusters=best_k, n_init=10, random_state=0).fit(X_scaled)
    clusters = kmeans.labels_

    pca = PCA(n_components=2, random_state=0)
    coords = pca.fit_transform(X_scaled)

    contingency = (
        pl.DataFrame({"cluster": clusters, "is_attack": y})
        .group_by(["cluster", "is_attack"])
        .agg(pl.len().alias("n"))
        .sort(["cluster", "is_attack"])
        .to_dicts()
    )

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    fig_path = _plot_cluster_scatter(coords, clusters, y)

    return {
        "n_sampled": len(X_scaled),
        "stride": stride,
        "n_features_used": len(used_cols),
        "features_used": used_cols,
        "preprocessing": "signed log1p per column, then StandardScaler",
        "best_k": best_k,
        "silhouette_at_best_k": float(best_score),
        "pca_explained_variance_ratio": pca.explained_variance_ratio_.tolist(),
        "contingency": contingency,
        "figure": fig_path,
    }


def _plot_cluster_scatter(coords: np.ndarray, clusters: np.ndarray, y: np.ndarray) -> str:
    import matplotlib.pyplot as plt

    setup_style()
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    sc0 = axes[0].scatter(coords[:, 0], coords[:, 1], c=clusters, cmap="tab10", s=3, alpha=0.5)
    axes[0].set_title("Coloreado por cluster (KMeans, no supervisado)")
    fig.colorbar(sc0, ax=axes[0], shrink=0.7, label="cluster")

    colors = np.where(y == 1, "#F44336", "#2196F3")
    axes[1].scatter(coords[:, 0], coords[:, 1], c=colors, s=3, alpha=0.5)
    axes[1].set_title("Coloreado por etiqueta real (rojo = ataque)")

    for ax in axes:
        ax.set_xlabel("PC1")
        ax.set_ylabel("PC2")

    path_out = FIGURES_DIR / "real_data_cluster_pca.png"
    fig.tight_layout()
    fig.savefig(path_out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return str(path_out)


# ------------------------------------------------------------- annotated sample
def annotated_sample_flow(path: Path) -> dict:
    """One real attack flow's raw values, for docs/comprension-datos/."""
    lf = load_csv(path)
    df = lf.filter(pl.col("is_attack") == 1).limit(1).collect()
    if df.is_empty():
        df = lf.limit(1).collect()
    row = df.row(0, named=True)
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items()}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("path", type=Path, help="CICIDS-2018 CSV file with Src IP/Dst IP")
    args = ap.parse_args()

    t0 = time.time()
    METRICS_DIR.mkdir(parents=True, exist_ok=True)

    _header(f"Interaction graph: {args.path.name}")
    graphs = make_interaction_graphs(args.path)

    _header("Clustering (systematic sample)")
    clusters = clustering_analysis(args.path)
    _log(f"k={clusters['best_k']} (silhouette={clusters['silhouette_at_best_k']:.3f})")
    for row in clusters["contingency"]:
        _log(f"  cluster {row['cluster']}, is_attack={row['is_attack']}: {row['n']} filas")

    _header("Annotated sample flow")
    sample = annotated_sample_flow(args.path)

    result = {
        "file": args.path.name,
        "interaction_graphs": graphs,
        "clustering": clusters,
        "sample_attack_flow": sample,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    out_path = METRICS_DIR / "real_data_clusters.json"
    out_path.write_text(json.dumps(result, indent=2, default=str))
    _header("Done")
    print(f"{GREEN}Written to {out_path}{NC} ({result['elapsed_seconds']}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
