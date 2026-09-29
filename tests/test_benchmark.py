"""Tests for the classification benchmark (src/models/benchmark.py)."""

import numpy as np
import polars as pl
import pytest

from src.models.benchmark import (
    IAG_COLUMNS,
    BenchmarkResult,
    _prepare_features,
    compute_shap_values,
    run_autoencoder,
    run_benchmark,
    run_isolation_forest,
    run_one_class_svm,
    run_random_forest,
    run_xgboost,
    temporal_split,
)


def _make_feature_matrix(n: int = 120, seed: int = 0) -> pl.DataFrame:
    """Small, separable synthetic feature matrix: benign clustered near 0,
    attack clustered near 5, so every model should do meaningfully better
    than chance without needing real data."""
    rng = np.random.default_rng(seed)
    n_benign = n * 2 // 3
    n_attack = n - n_benign

    benign = rng.normal(loc=0.0, scale=1.0, size=(n_benign, 4))
    attack = rng.normal(loc=5.0, scale=1.0, size=(n_attack, 4))
    X = np.vstack([benign, attack])
    y = np.array([0] * n_benign + [1] * n_attack)

    # Shuffle deterministically but keep a "window_start" that's monotonic
    # with insertion order so temporal_split has something to sort by.
    order = rng.permutation(n)
    X, y = X[order], y[order]

    df = pl.DataFrame({
        "window_start": np.arange(n),
        "has_attack": y,
        "num_nodes": X[:, 0] + 10,
        "num_edges": X[:, 1] + 10,
        "iag_directional": X[:, 2],
        "iag_entropic": np.abs(X[:, 3]),
        "iag_combined": X[:, 2] + X[:, 3],
    })
    return df


class TestTemporalSplit:
    def test_split_respects_window_order(self):
        df = pl.DataFrame({"window_start": [3, 1, 2, 4], "value": ["c", "a", "b", "d"]})
        train, test = temporal_split(df, train_ratio=0.5)
        assert train["window_start"].to_list() == [1, 2]
        assert test["window_start"].to_list() == [3, 4]

    def test_split_ratio(self):
        df = pl.DataFrame({"window_start": list(range(100))})
        train, test = temporal_split(df, train_ratio=0.7)
        assert len(train) == 70
        assert len(test) == 30


class TestPrepareFeatures:
    def test_handles_nan_and_inf(self):
        train_df = pl.DataFrame({"a": [1.0, float("nan"), float("inf")], "has_attack": [0, 1, 0]})
        test_df = pl.DataFrame({"a": [1.0], "has_attack": [0]})
        X_train, X_test, y_train, y_test = _prepare_features(train_df, test_df, ["a"])
        assert np.isfinite(X_train).all()
        assert np.isfinite(X_test).all()

    def test_output_shapes(self):
        df = _make_feature_matrix(n=40)
        train_df, test_df = temporal_split(df)
        X_train, X_test, y_train, y_test = _prepare_features(
            train_df, test_df, ["iag_directional", "iag_entropic"]
        )
        assert X_train.shape == (len(train_df), 2)
        assert X_test.shape == (len(test_df), 2)
        assert y_train.shape == (len(train_df),)


class TestIndividualModelRunners:
    """Each model runner should return a well-formed BenchmarkResult on an
    easily-separable synthetic dataset."""

    @pytest.fixture
    def data(self):
        df = _make_feature_matrix(n=120)
        train_df, test_df = temporal_split(df)
        cols = ["num_nodes", "num_edges", "iag_directional", "iag_entropic"]
        return (*_prepare_features(train_df, test_df, cols), cols)

    def test_random_forest(self, data):
        X_train, X_test, y_train, y_test, cols = data
        result = run_random_forest(X_train, X_test, y_train, y_test, "classic+iag", cols)
        assert isinstance(result, BenchmarkResult)
        assert result.model_name == "RandomForest"
        assert result.feature_importances is not None
        assert result.pr_auc > 0.8  # data is trivially separable
        assert result.precision_attack > 0.8
        assert result.y_score is not None
        assert result.y_score.shape == y_test.shape

    def test_xgboost(self, data):
        X_train, X_test, y_train, y_test, cols = data
        result = run_xgboost(X_train, X_test, y_train, y_test, "classic+iag", cols)
        assert result.model_name == "XGBoost"
        assert result.pr_auc > 0.8
        assert result.precision_attack > 0.8

    def test_isolation_forest(self, data):
        X_train, X_test, y_train, y_test, cols = data
        result = run_isolation_forest(X_train, X_test, y_train, y_test, "classic+iag", cols)
        assert result.model_name == "IsolationForest"
        assert 0.0 <= result.fpr <= 1.0

    def test_one_class_svm(self, data):
        X_train, X_test, y_train, y_test, cols = data
        result = run_one_class_svm(X_train, X_test, y_train, y_test, "classic+iag", cols)
        assert result.model_name == "OneClassSVM"
        assert 0.0 <= result.fpr <= 1.0

    def test_autoencoder(self, data):
        X_train, X_test, y_train, y_test, cols = data
        result = run_autoencoder(
            X_train, X_test, y_train, y_test, "classic+iag", cols, epochs=10,
        )
        assert result.model_name == "Autoencoder"
        assert 0.0 <= result.fpr <= 1.0

    def test_random_forest_with_shap(self, data):
        X_train, X_test, y_train, y_test, cols = data
        result = run_random_forest(
            X_train, X_test, y_train, y_test, "classic+iag", cols, compute_shap=True,
        )
        assert result.shap_summary is not None
        assert result.shap_summary["mean_abs_shap"].shape == (len(cols),)
        assert list(result.shap_summary["feature_names"]) == cols


class TestComputeShapValues:
    def test_subsamples_large_input(self):
        from sklearn.ensemble import RandomForestClassifier

        rng = np.random.default_rng(0)
        X = rng.normal(size=(500, 3))
        y = (X[:, 0] > 0).astype(int)
        clf = RandomForestClassifier(n_estimators=20, random_state=0).fit(X, y)

        result = compute_shap_values(clf, X, ["a", "b", "c"], max_samples=50)
        assert result["shap_values"].shape[0] == 50
        assert result["mean_abs_shap"].shape == (3,)

    def test_identifies_the_informative_feature(self):
        from sklearn.ensemble import RandomForestClassifier

        rng = np.random.default_rng(1)
        X = rng.normal(size=(300, 4))
        y = (X[:, 0] > 0).astype(int)  # only column 0 matters
        clf = RandomForestClassifier(n_estimators=50, random_state=1).fit(X, y)

        result = compute_shap_values(clf, X, ["a", "b", "c", "d"])
        mean_abs = result["mean_abs_shap"]
        assert mean_abs[0] == max(mean_abs)


class TestRunBenchmark:
    def test_returns_result_per_model_per_feature_set(self):
        df = _make_feature_matrix(n=120)
        results = run_benchmark(df, ["num_nodes", "num_edges"])
        feature_sets = {r.feature_set for r in results}
        assert feature_sets == {"classic", "classic+iag"}
        # 5 model runners x 2 feature sets
        assert len(results) == 10

    def test_iag_columns_only_in_iag_feature_set(self):
        df = _make_feature_matrix(n=60)
        results = run_benchmark(df, ["num_nodes", "num_edges"])
        classic_results = [r for r in results if r.feature_set == "classic"]
        for r in classic_results:
            if r.feature_importances:
                assert not any(c in r.feature_importances for c in IAG_COLUMNS)

    def test_compute_shap_attaches_summary_only_to_tree_models(self):
        df = _make_feature_matrix(n=60)
        results = run_benchmark(df, ["num_nodes", "num_edges"], compute_shap=True)
        by_name = {(r.model_name, r.feature_set): r for r in results}
        assert by_name[("RandomForest", "classic+iag")].shap_summary is not None
        assert by_name[("XGBoost", "classic+iag")].shap_summary is not None
        assert by_name[("IsolationForest", "classic+iag")].shap_summary is None
