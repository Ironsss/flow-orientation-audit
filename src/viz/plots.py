"""
Visualization module for IAG analysis and paper figures.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.lines import Line2D

RESULTS_DIR = Path("results/figures")
STYLE_DEFAULTS = {
    "figure.figsize": (10, 6),
    "font.size": 12,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
}


def setup_style():
    """Set consistent plot style for paper figures."""
    plt.rcParams.update(STYLE_DEFAULTS)
    sns.set_theme(style="whitegrid", palette="muted")


def plot_iag_distribution(
    iag_benign: np.ndarray,
    iag_attack: np.ndarray,
    iag_name: str = "IAG Combined",
    save_path: str | Path | None = None,
):
    """Plot overlapping distributions of IAG for benign vs attack windows."""
    setup_style()
    fig, ax = plt.subplots()

    ax.hist(iag_benign, bins=50, alpha=0.6, label="Benign", density=True, color="#2196F3")
    ax.hist(iag_attack, bins=50, alpha=0.6, label="Attack", density=True, color="#F44336")

    ax.set_xlabel(iag_name)
    ax.set_ylabel("Density")
    ax.set_title(f"Distribution of {iag_name}: Benign vs Attack")
    ax.legend()

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_iag_by_attack_type(
    iag_values: dict[str, np.ndarray],
    iag_name: str = "IAG Combined",
    save_path: str | Path | None = None,
):
    """Box plot of IAG values grouped by attack type."""
    setup_style()
    fig, ax = plt.subplots(figsize=(12, 6))

    categories = sorted(iag_values.keys())
    ax.boxplot([iag_values[k] for k in categories])
    # Set tick labels via set_xticklabels rather than boxplot(labels=...) /
    # boxplot(tick_labels=...): the kwarg was renamed between matplotlib
    # versions (labels -> tick_labels), this form works on all of them.
    ax.set_xticks(range(1, len(categories) + 1))
    ax.set_xticklabels(categories)
    ax.set_ylabel(iag_name)
    ax.set_title(f"{iag_name} by Traffic Category")
    plt.xticks(rotation=45, ha="right")

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_benchmark_comparison(
    model_names: list[str],
    classic_scores: list[float],
    iag_scores: list[float],
    metric_name: str = "PR-AUC",
    save_path: str | Path | None = None,
):
    """Bar chart comparing model performance with/without IAG."""
    setup_style()
    fig, ax = plt.subplots()

    x = np.arange(len(model_names))
    width = 0.35

    ax.bar(x - width / 2, classic_scores, width, label="Classic Features", color="#2196F3")
    ax.bar(x + width / 2, iag_scores, width, label="Classic + IAG", color="#4CAF50")

    ax.set_ylabel(metric_name)
    ax.set_title(f"Model Comparison: {metric_name}")
    ax.set_xticks(x)
    ax.set_xticklabels(model_names)
    ax.legend()

    # Add delta labels
    for i, (c, iag) in enumerate(zip(classic_scores, iag_scores)):
        delta = iag - c
        sign = "+" if delta >= 0 else ""
        ax.annotate(
            f"{sign}{delta:.3f}",
            xy=(i + width / 2, iag),
            ha="center",
            va="bottom",
            fontsize=9,
            color="#4CAF50" if delta >= 0 else "#F44336",
        )

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_asymmetry_sweep(
    levels: list[float],
    detection_scores: list[float],
    metric_name: str = "PR-AUC",
    save_path: str | Path | None = None,
):
    """Plot detection performance vs asymmetry level (ablation study)."""
    setup_style()
    fig, ax = plt.subplots()

    ax.plot(levels, detection_scores, "o-", color="#9C27B0", linewidth=2, markersize=8)
    ax.set_xlabel("Asymmetry Level")
    ax.set_ylabel(metric_name)
    ax.set_title(f"Detection {metric_name} vs Asymmetry Level (Ablation)")
    ax.set_xlim(-0.05, 1.05)
    ax.grid(True, alpha=0.3)

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_feature_importance(
    feature_names: list[str],
    importances: list[float],
    top_k: int = 20,
    save_path: str | Path | None = None,
):
    """Horizontal bar chart of top feature importances (SHAP or tree-based)."""
    setup_style()

    # Sort and take top-k
    sorted_idx = np.argsort(importances)[-top_k:]
    fig, ax = plt.subplots(figsize=(10, 8))

    colors = [
        "#4CAF50" if "iag" in feature_names[i] else "#2196F3"
        for i in sorted_idx
    ]

    ax.barh(
        [feature_names[i] for i in sorted_idx],
        [importances[i] for i in sorted_idx],
        color=colors,
    )
    ax.set_xlabel("Importance")
    ax.set_title(f"Top {top_k} Feature Importances")

    # Legend for IAG vs classic
    from matplotlib.patches import Patch

    legend_elements = [
        Patch(facecolor="#4CAF50", label="IAG Features"),
        Patch(facecolor="#2196F3", label="Classic Features"),
    ]
    ax.legend(handles=legend_elements, loc="lower right")

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_shap_summary(
    feature_names: list[str],
    mean_abs_shap: list[float],
    top_k: int = 20,
    save_path: str | Path | None = None,
):
    """
    Horizontal bar chart of top-k features by mean |SHAP value|.

    Unlike plot_feature_importance's tree-based Gini/gain importance (a
    global, structural measure of how much a feature was used to split),
    mean |SHAP value| reflects each feature's actual average contribution to
    individual predictions — see src.models.benchmark.compute_shap_values.
    """
    setup_style()

    sorted_idx = np.argsort(mean_abs_shap)[-top_k:]
    fig, ax = plt.subplots(figsize=(10, 8))

    colors = [
        "#4CAF50" if "iag" in feature_names[i] else "#2196F3"
        for i in sorted_idx
    ]

    ax.barh(
        [feature_names[i] for i in sorted_idx],
        [mean_abs_shap[i] for i in sorted_idx],
        color=colors,
    )
    ax.set_xlabel("Mean |SHAP value|")
    ax.set_title(f"Top {top_k} Features by SHAP Importance")

    from matplotlib.patches import Patch

    legend_elements = [
        Patch(facecolor="#4CAF50", label="IAG Features"),
        Patch(facecolor="#2196F3", label="Classic Features"),
    ]
    ax.legend(handles=legend_elements, loc="lower right")

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches="tight")
    return fig


def plot_interaction_graph(
    edges: list[tuple[str, str]],
    edge_weights: list[float] | None = None,
    edge_is_attack: list[bool] | None = None,
    title: str = "Host interaction graph",
    save_path: str | Path | None = None,
    max_nodes: int = 100,
):
    """Draw a directed host-interaction graph: nodes are hosts (IPs), edges
    are the flows between them, aggregated by (src, dst) pair.

    Building the graph is the caller's job (src.graphs.builder.build_temporal_graphs
    is the reusable way to do that) -- this only lays out and draws whatever
    edge list it's given, via networkx's kamada_kawai_layout (spring_layout
    left real captures as one unreadable overlapping blob: a few hub hosts
    with hundreds of low-degree neighbors is the normal shape of network
    traffic, and naive spring layouts don't separate that well).

    If the graph has more than `max_nodes` nodes, trimming keeps every host
    that touches an attack-flagged edge first, then fills the remaining
    budget with the highest-degree hosts -- a pure degree cutoff silently
    dropped every attack edge in a real DDoS window (they run between
    low-degree hosts, not the busy background servers), which would have
    rendered a graph with a "with attack traffic" legend entry and zero red
    edges in it.
    """
    import networkx as nx

    setup_style()

    graph = nx.DiGraph()
    for i, (u, v) in enumerate(edges):
        weight = edge_weights[i] if edge_weights else 1.0
        is_attack = bool(edge_is_attack[i]) if edge_is_attack else False
        if graph.has_edge(u, v):
            graph[u][v]["weight"] += weight
            graph[u][v]["is_attack"] = graph[u][v]["is_attack"] or is_attack
        else:
            graph.add_edge(u, v, weight=weight, is_attack=is_attack)

    if graph.number_of_nodes() > max_nodes:
        attack_nodes = {
            node for u, v, data in graph.edges(data=True) if data["is_attack"]
            for node in (u, v)
        }
        degrees = dict(graph.degree())
        by_degree = sorted(degrees, key=degrees.get, reverse=True)
        keep = set(attack_nodes)
        for node in by_degree:
            if len(keep) >= max_nodes:
                break
            keep.add(node)
        graph = graph.subgraph(keep).copy()

    fig, ax = plt.subplots(figsize=(10, 10))
    n_nodes = max(graph.number_of_nodes(), 1)
    # A real capture's window is rarely one connected blob -- it's usually a
    # large background component plus several small, disconnected
    # attacker/victim stars. kamada_kawai's all-pairs-shortest-path layout
    # collapses disconnected components on top of each other; spring_layout
    # with a much larger-than-default k (repulsion) and more iterations
    # separates them into legibly distinct regions instead.
    pos = nx.spring_layout(graph, seed=0, k=6.0 / n_nodes**0.5, iterations=200)

    edge_colors = [
        "#F44336" if graph[u][v]["is_attack"] else "#90A4AE" for u, v in graph.edges()
    ]
    edge_widths = [1.6 if graph[u][v]["is_attack"] else 0.6 for u, v in graph.edges()]
    node_colors = [
        "#F44336" if any(graph[u][v]["is_attack"] for v in graph.successors(u)) else "#1E3557"
        for u in graph.nodes()
    ]
    node_sizes = [40 + 25 * graph.degree(node) for node in graph.nodes()]

    nx.draw_networkx_nodes(
        graph, pos, ax=ax, node_size=node_sizes, node_color=node_colors, alpha=0.85
    )
    nx.draw_networkx_edges(
        graph, pos, ax=ax, edge_color=edge_colors, width=edge_widths, arrows=True,
        arrowsize=8, alpha=0.6, connectionstyle="arc3,rad=0.05",
    )
    ax.set_title(
        f"{title}\n({graph.number_of_nodes()} hosts, {graph.number_of_edges()} conexiones)"
    )
    ax.axis("off")

    legend_elements = [
        Line2D([0], [0], color="#90A4AE", lw=2, label="Benigno"),
        Line2D([0], [0], color="#F44336", lw=2, label="Con tráfico de ataque"),
    ]
    ax.legend(handles=legend_elements, loc="upper right")

    if save_path:
        fig.savefig(save_path, dpi=200, bbox_inches="tight")
    return fig


def plot_pr_roc_curves(
    y_true: np.ndarray,
    y_score: np.ndarray,
    model_name: str = "model",
    save_path: str | Path | None = None,
):
    """Side-by-side Precision-Recall and ROC curves for one model's real
    predictions on the test set.

    A scalar ROC-AUC can look strong under class imbalance even when the
    model is mediocre at the thing that actually matters -- catching the
    minority (attack) class without drowning in false positives. The PR
    curve's no-skill baseline is the test set's positive rate (not 0.5), so
    it makes that failure mode visible in a way the ROC curve, and a single
    AUC number, do not.
    """
    from sklearn.metrics import (
        average_precision_score,
        precision_recall_curve,
        roc_auc_score,
        roc_curve,
    )

    setup_style()
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    precision, recall, _ = precision_recall_curve(y_true, y_score)
    pr_auc = average_precision_score(y_true, y_score)
    no_skill = float(np.mean(y_true))
    axes[0].plot(recall, precision, color="#F44336", linewidth=2, label=f"AP={pr_auc:.3f}")
    axes[0].axhline(
        no_skill, color="gray", linestyle="--", linewidth=1, label=f"no-skill ({no_skill:.3f})"
    )
    axes[0].set_xlabel("Recall")
    axes[0].set_ylabel("Precision")
    axes[0].set_title(f"PR curve -- {model_name}")
    axes[0].set_ylim(-0.02, 1.02)
    axes[0].legend(loc="lower left")

    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = roc_auc_score(y_true, y_score)
    axes[1].plot(fpr, tpr, color="#2196F3", linewidth=2, label=f"AUC={roc_auc:.3f}")
    axes[1].plot([0, 1], [0, 1], color="gray", linestyle="--", linewidth=1, label="random")
    axes[1].set_xlabel("False Positive Rate")
    axes[1].set_ylabel("True Positive Rate")
    axes[1].set_title(f"ROC curve -- {model_name}")
    axes[1].legend(loc="lower right")

    if save_path:
        fig.savefig(save_path, dpi=200, bbox_inches="tight")
    return fig
