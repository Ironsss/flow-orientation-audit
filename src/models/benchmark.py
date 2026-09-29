"""
Classification benchmark: with IAG vs without IAG.

Models: Random Forest, XGBoost, Isolation Forest, One-Class SVM, Autoencoder.
Evaluation: PR-AUC, F1, Precision, Recall, ROC-AUC, FPR — all per class and per attack type.
"""

from dataclasses import dataclass

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    f1_score,
    precision_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

IAG_COLUMNS = ["iag_directional", "iag_entropic", "iag_combined"]


@dataclass
class BenchmarkResult:
    """Stores results for a single model run."""

    model_name: str
    feature_set: str  # "classic" or "classic+iag"
    pr_auc: float
    roc_auc: float
    f1_macro: float
    f1_per_class: dict[str, float]
    recall_attack: float
    precision_attack: float
    fpr: float
    classification_report_str: str
    feature_importances: dict[str, float] | None = None
    shap_summary: dict[str, object] | None = None
    y_score: np.ndarray | None = None
    """Per-sample anomaly/positive-class score on the test set, in the same
    order as the y_test the caller already has. Not persisted to JSON by
    itself (it's per-row) -- exists so a caller can plot a PR or ROC curve
    (sklearn.metrics.precision_recall_curve/roc_curve) instead of only ever
    seeing the single-number PR-AUC/ROC-AUC, which under class imbalance can
    look deceptively strong on their own."""


def temporal_split(
    df: pl.DataFrame,
    train_ratio: float = 0.7,
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Split data temporally (not randomly) to avoid information leakage.

    The first `train_ratio` of windows (by time) go to train, the rest to test.
    """
    if "window_start" in df.columns:
        df = df.sort("window_start")
    n = len(df)
    split_idx = int(n * train_ratio)
    return df[:split_idx], df[split_idx:]


def _prepare_features(
    train_df: pl.DataFrame,
    test_df: pl.DataFrame,
    feature_cols: list[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Extract and scale feature matrices."""
    X_train = train_df.select(feature_cols).to_numpy().astype(np.float32)
    X_test = test_df.select(feature_cols).to_numpy().astype(np.float32)
    y_train = train_df["has_attack"].to_numpy().astype(np.int32)
    y_test = test_df["has_attack"].to_numpy().astype(np.int32)

    # Replace any remaining NaN/inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test


def _compute_metrics(
    model_name: str,
    feature_set: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: np.ndarray | None,
    feature_names: list[str] | None = None,
    importances: np.ndarray | None = None,
) -> BenchmarkResult:
    """Compute all evaluation metrics."""
    # PR-AUC and ROC-AUC
    pr_auc = 0.0
    roc_auc_val = 0.0
    if y_score is not None and len(np.unique(y_true)) > 1:
        pr_auc = average_precision_score(y_true, y_score)
        roc_auc_val = roc_auc_score(y_true, y_score)

    f1_macro = f1_score(y_true, y_pred, average="macro", zero_division=0)

    report = classification_report(y_true, y_pred, zero_division=0)

    # Per-class F1
    f1_per_class = {
        "benign": f1_score(y_true, y_pred, pos_label=0, zero_division=0),
        "attack": f1_score(y_true, y_pred, pos_label=1, zero_division=0),
    }

    # Recall for attack class
    attack_mask = y_true == 1
    recall_attack = (y_pred[attack_mask] == 1).mean() if attack_mask.sum() > 0 else 0.0

    # Precision for attack class -- recall and FPR alone don't say what
    # fraction of *predicted* attacks are real; f1_macro folds in the (usually
    # much easier) benign class and can look strong even when attack-specific
    # precision/recall are mediocre, especially under class imbalance.
    precision_attack = precision_score(y_true, y_pred, pos_label=1, zero_division=0)

    # FPR
    benign_mask = y_true == 0
    fpr = (y_pred[benign_mask] == 1).mean() if benign_mask.sum() > 0 else 0.0

    # Feature importances
    feat_imp = None
    if importances is not None and feature_names is not None:
        feat_imp = dict(zip(feature_names, importances.tolist()))

    return BenchmarkResult(
        model_name=model_name,
        feature_set=feature_set,
        pr_auc=pr_auc,
        roc_auc=roc_auc_val,
        f1_macro=f1_macro,
        f1_per_class=f1_per_class,
        recall_attack=float(recall_attack),
        precision_attack=float(precision_attack),
        fpr=float(fpr),
        classification_report_str=report,
        feature_importances=feat_imp,
        y_score=y_score,
    )


def compute_shap_values(
    model,
    X: np.ndarray,
    feature_names: list[str],
    max_samples: int = 200,
) -> dict[str, object]:
    """
    Compute SHAP values for a tree-based model (RandomForest/XGBoost) via
    shap.TreeExplainer — per-prediction feature attribution, as opposed to
    the single global `feature_importances_` (Gini/gain) already reported by
    `_compute_metrics`. Substantiates rather than just asserts which features
    (and specifically, whether IAG features) actually drive individual
    predictions.

    Subsamples `X` to at most `max_samples` rows: TreeExplainer's cost scales
    with model complexity x number of samples, and datasets here can have far
    more rows than are needed for a stable mean-|SHAP| ranking.

    Returns
    -------
    dict with:
        - "shap_values": ndarray (n_samples, n_features), SHAP values for the
          positive (attack) class
        - "feature_names": the feature_names passed in
        - "mean_abs_shap": ndarray (n_features,) mean |SHAP| per feature —
          directly usable as an importance ranking, see
          src.viz.plots.plot_shap_summary
    """
    import shap

    n = X.shape[0]
    if n > max_samples:
        rng = np.random.default_rng(42)
        idx = rng.choice(n, size=max_samples, replace=False)
        X_sample = X[idx]
    else:
        X_sample = X

    explainer = shap.TreeExplainer(model)
    raw_shap = explainer.shap_values(X_sample)

    # Binary classifiers vary in SHAP output shape across sklearn/xgboost/shap
    # versions: a [class0, class1] list, a (n, features, 2) array, or already
    # a single (n, features) array for the positive class. Normalize to the
    # latter, always taking the positive (attack) class.
    if isinstance(raw_shap, list):
        shap_values = raw_shap[1]
    elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 3:
        shap_values = raw_shap[:, :, 1]
    else:
        shap_values = raw_shap

    return {
        "shap_values": shap_values,
        "feature_names": feature_names,
        "mean_abs_shap": np.abs(shap_values).mean(axis=0),
    }


def run_random_forest(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_set: str,
    feature_names: list[str],
    compute_shap: bool = False,
) -> BenchmarkResult:
    """Train and evaluate a Random Forest classifier."""
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_score = clf.predict_proba(X_test)[:, 1]

    result = _compute_metrics(
        "RandomForest", feature_set, y_test, y_pred, y_score,
        feature_names, clf.feature_importances_,
    )
    if compute_shap:
        result.shap_summary = compute_shap_values(clf, X_test, feature_names)
    return result


def run_xgboost(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_set: str,
    feature_names: list[str],
    compute_shap: bool = False,
) -> BenchmarkResult:
    """Train and evaluate an XGBoost classifier."""
    import xgboost as xgb

    scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

    clf = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        scale_pos_weight=scale_pos,
        tree_method="hist",  # Use "gpu_hist" if GPU available
        random_state=42,
        eval_metric="aucpr",
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_score = clf.predict_proba(X_test)[:, 1]

    result = _compute_metrics(
        "XGBoost", feature_set, y_test, y_pred, y_score,
        feature_names, clf.feature_importances_,
    )
    if compute_shap:
        result.shap_summary = compute_shap_values(clf, X_test, feature_names)
    return result


def run_isolation_forest(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_set: str,
    feature_names: list[str],
) -> BenchmarkResult:
    """Train and evaluate an Isolation Forest (unsupervised baseline)."""
    # Train only on benign data
    benign_mask = y_train == 0
    X_train_benign = X_train[benign_mask]

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_benign)

    # -1 = anomaly, 1 = normal -> convert to 0/1
    raw_pred = clf.predict(X_test)
    y_pred = (raw_pred == -1).astype(np.int32)
    y_score = -clf.score_samples(X_test)  # Higher = more anomalous

    return _compute_metrics(
        "IsolationForest", feature_set, y_test, y_pred, y_score,
        feature_names, None,
    )


def run_one_class_svm(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_set: str,
    feature_names: list[str],
) -> BenchmarkResult:
    """
    Train and evaluate a One-Class SVM (unsupervised baseline, trained on benign only).

    Note: kernel SVMs scale roughly O(n^2)-O(n^3) with training set size — on a
    full CICIDS-2018 window count this may be considerably slower than the
    tree-based models above. No subsampling is applied here; if this becomes a
    bottleneck, subsample X_train_benign before fitting.
    """
    benign_mask = y_train == 0
    X_train_benign = X_train[benign_mask]

    clf = OneClassSVM(kernel="rbf", nu=0.1, gamma="scale")
    clf.fit(X_train_benign)

    # -1 = anomaly, 1 = normal -> convert to 0/1
    raw_pred = clf.predict(X_test)
    y_pred = (raw_pred == -1).astype(np.int32)
    y_score = -clf.decision_function(X_test)  # Higher = more anomalous

    return _compute_metrics(
        "OneClassSVM", feature_set, y_test, y_pred, y_score,
        feature_names, None,
    )


def run_autoencoder(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_set: str,
    feature_names: list[str],
    epochs: int = 50,
    hidden_dim: int = 16,
    bottleneck_dim: int = 4,
    contamination: float = 0.1,
    seed: int = 42,
) -> BenchmarkResult:
    """
    Train and evaluate a PyTorch autoencoder (unsupervised baseline, trained on benign only).

    Reconstruction error (MSE) on the test set is the anomaly score. The
    decision threshold is the `contamination`-quantile of *training* set
    reconstruction error, mirroring IsolationForest's `contamination` parameter
    so the two unsupervised baselines are comparable at a similar operating point.
    """
    import torch
    import torch.nn as nn

    torch.manual_seed(seed)

    class _Autoencoder(nn.Module):
        def __init__(self, n_features: int, hidden_dim: int, bottleneck_dim: int):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(n_features, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, bottleneck_dim),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(bottleneck_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, n_features),
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))

    benign_mask = y_train == 0
    X_train_benign = X_train[benign_mask]
    n_features = X_train.shape[1]
    bottleneck_dim = max(1, min(bottleneck_dim, n_features - 1)) if n_features > 1 else 1

    model = _Autoencoder(n_features, hidden_dim=hidden_dim, bottleneck_dim=bottleneck_dim)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = torch.nn.MSELoss()

    X_train_t = torch.tensor(X_train_benign, dtype=torch.float32)
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        recon = model(X_train_t)
        loss = loss_fn(recon, X_train_t)
        loss.backward()
        optimizer.step()

    model.eval()
    with torch.no_grad():
        train_errors = ((model(X_train_t) - X_train_t) ** 2).mean(dim=1).numpy()
        threshold = np.quantile(train_errors, 1 - contamination)

        X_test_t = torch.tensor(X_test, dtype=torch.float32)
        test_errors = ((model(X_test_t) - X_test_t) ** 2).mean(dim=1).numpy()

    y_pred = (test_errors > threshold).astype(np.int32)
    y_score = test_errors  # Higher = more anomalous

    return _compute_metrics(
        "Autoencoder", feature_set, y_test, y_pred, y_score,
        feature_names, None,
    )


def run_benchmark(
    feature_matrix: pl.DataFrame,
    classic_feature_cols: list[str],
    compute_shap: bool = False,
) -> list[BenchmarkResult]:
    """
    Run the full benchmark: each model with and without IAG features.

    Parameters
    ----------
    feature_matrix : pl.DataFrame
        Must contain: classic features, IAG columns, has_attack, window_start.
    classic_feature_cols : list[str]
        Names of classic (non-IAG) feature columns.
    compute_shap : bool
        If True, also compute SHAP values (see compute_shap_values) for the
        tree-based models (RandomForest, XGBoost) and attach them to each
        result's `shap_summary`. Off by default since it's meaningfully
        slower than the rest of the benchmark.

    Returns
    -------
    list[BenchmarkResult]
    """
    train_df, test_df = temporal_split(feature_matrix)

    results = []
    model_runners = [
        run_random_forest,
        run_xgboost,
        run_isolation_forest,
        run_one_class_svm,
        run_autoencoder,
    ]

    for feature_set_name, feature_cols in [
        ("classic", classic_feature_cols),
        ("classic+iag", classic_feature_cols + IAG_COLUMNS),
    ]:
        # Verify all columns exist
        available = set(feature_matrix.columns)
        feature_cols = [c for c in feature_cols if c in available]

        X_train, X_test, y_train, y_test = _prepare_features(
            train_df, test_df, feature_cols,
        )

        for runner in model_runners:
            kwargs = {}
            if compute_shap and runner in (run_random_forest, run_xgboost):
                kwargs["compute_shap"] = True
            result = runner(
                X_train, X_test, y_train, y_test,
                feature_set_name, feature_cols,
                **kwargs,
            )
            results.append(result)

    return results
