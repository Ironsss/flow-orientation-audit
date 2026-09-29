"""Tests for the visualization module (src/viz/plots.py).

Not a rendering/pixel-comparison suite — just confirms each plot function
runs without error on realistic inputs, returns a Figure, and (when given a
save_path) actually writes a file. Uses the non-interactive Agg backend so
these run headlessly in CI.
"""

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pytest

from src.viz.plots import (
    plot_asymmetry_sweep,
    plot_benchmark_comparison,
    plot_feature_importance,
    plot_iag_by_attack_type,
    plot_iag_distribution,
    plot_interaction_graph,
    plot_pr_roc_curves,
    plot_shap_summary,
)


@pytest.fixture(autouse=True)
def _close_figures_after_each_test():
    yield
    plt.close("all")


class TestPlotIagDistribution:
    def test_returns_figure(self):
        rng = np.random.default_rng(0)
        fig = plot_iag_distribution(rng.random(50), rng.random(50) + 0.5)
        assert isinstance(fig, plt.Figure)

    def test_saves_to_disk(self, tmp_path):
        rng = np.random.default_rng(0)
        out = tmp_path / "dist.png"
        plot_iag_distribution(rng.random(30), rng.random(30), save_path=out)
        assert out.exists()
        assert out.stat().st_size > 0


class TestPlotIagByAttackType:
    def test_returns_figure(self):
        rng = np.random.default_rng(0)
        values = {
            "Benign": rng.random(20),
            "DDoS": rng.random(20) + 0.5,
            "PortScan": rng.random(20) + 0.3,
        }
        fig = plot_iag_by_attack_type(values)
        assert isinstance(fig, plt.Figure)


class TestPlotBenchmarkComparison:
    def test_returns_figure(self):
        fig = plot_benchmark_comparison(
            ["RandomForest", "XGBoost"], [0.7, 0.8], [0.85, 0.9],
        )
        assert isinstance(fig, plt.Figure)

    def test_handles_negative_delta(self):
        # classic+iag doing worse than classic should not crash the annotation
        fig = plot_benchmark_comparison(["Model"], [0.9], [0.7])
        assert isinstance(fig, plt.Figure)


class TestPlotAsymmetrySweep:
    def test_returns_figure(self):
        levels = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
        scores = [0.95, 0.9, 0.8, 0.6, 0.4, 0.3]
        fig = plot_asymmetry_sweep(levels, scores)
        assert isinstance(fig, plt.Figure)


class TestPlotFeatureImportance:
    def test_returns_figure(self):
        names = [f"feature_{i}" for i in range(5)] + ["iag_combined"]
        importances = list(np.linspace(0.01, 0.3, 6))
        fig = plot_feature_importance(names, importances, top_k=6)
        assert isinstance(fig, plt.Figure)

    def test_top_k_smaller_than_feature_count(self):
        names = [f"f{i}" for i in range(30)]
        importances = list(np.random.default_rng(0).random(30))
        fig = plot_feature_importance(names, importances, top_k=10)
        ax = fig.axes[0]
        assert len(ax.get_yticklabels()) == 10


class TestPlotShapSummary:
    def test_returns_figure(self):
        names = ["iag_directional", "iag_entropic", "num_nodes", "num_edges"]
        mean_abs_shap = [0.4, 0.1, 0.05, 0.02]
        fig = plot_shap_summary(names, mean_abs_shap, top_k=4)
        assert isinstance(fig, plt.Figure)

    def test_saves_to_disk(self, tmp_path):
        out = tmp_path / "shap.png"
        plot_shap_summary(["a", "b"], [0.5, 0.2], save_path=out)
        assert out.exists()


class TestPlotInteractionGraph:
    def test_returns_figure(self):
        edges = [("10.0.0.1", "10.0.0.2"), ("10.0.0.2", "10.0.0.1"), ("10.0.0.3", "10.0.0.2")]
        fig = plot_interaction_graph(edges, edge_weights=[5, 2, 1])
        assert isinstance(fig, plt.Figure)

    def test_saves_to_disk(self, tmp_path):
        out = tmp_path / "graph.png"
        edges = [("a", "b"), ("b", "c")]
        plot_interaction_graph(edges, save_path=out)
        assert out.exists()

    def test_trimming_to_max_nodes_keeps_attack_edges(self):
        """Regression test: a pure highest-degree cutoff silently dropped every
        attack-flagged edge on a real DDoS window (they run between low-degree
        hosts, not the busy background servers) -- a plot with a "with attack
        traffic" legend entry and zero red edges in it. Attack-adjacent nodes
        must survive trimming even when far outnumbered by high-degree ones.
        """
        # A dense high-degree background clique of 20 hosts (all mutually
        # connected, so each has degree 19) plus one isolated attacker/victim
        # pair whose two nodes have degree 1 -- exactly the shape that a naive
        # top-k-by-degree cutoff discards.
        background = [f"bg{i}" for i in range(20)]
        edges = [(u, v) for u in background for v in background if u != v]
        edges.append(("attacker", "victim"))
        edge_is_attack = [False] * (len(edges) - 1) + [True]

        fig = plot_interaction_graph(
            edges, edge_is_attack=edge_is_attack, max_nodes=10
        )
        ax = fig.axes[0]
        legend_labels = [t.get_text() for t in ax.get_legend().get_texts()]
        assert "Con tráfico de ataque" in legend_labels
        # the attack edge must actually have been kept in the trimmed graph,
        # not just declared in the (static) legend -- edges are drawn as
        # FancyArrowPatch, not a LineCollection, when arrows=True
        edge_rgbs = {tuple(p.get_edgecolor())[:3] for p in ax.patches}
        red_rgb = matplotlib.colors.to_rgb("#F44336")
        assert red_rgb in edge_rgbs


class TestPlotPrRocCurves:
    def test_returns_figure_with_two_axes(self):
        rng = np.random.default_rng(0)
        y_true = (rng.random(200) < 0.1).astype(int)
        y_score = y_true * 0.7 + rng.random(200) * 0.3
        fig = plot_pr_roc_curves(y_true, y_score, model_name="test")
        assert isinstance(fig, plt.Figure)
        assert len(fig.axes) == 2

    def test_saves_to_disk(self, tmp_path):
        rng = np.random.default_rng(0)
        y_true = (rng.random(50) < 0.2).astype(int)
        y_score = rng.random(50)
        out = tmp_path / "pr_roc.png"
        plot_pr_roc_curves(y_true, y_score, save_path=out)
        assert out.exists()
