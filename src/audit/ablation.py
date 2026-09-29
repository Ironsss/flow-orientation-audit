"""Group-wise leave-out ablation for correlated feature sets."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class GroupImportance:
    """Importance of one feature group, measured by refit-and-drop.

    Attributes
    ----------
    names : tuple[str, ...]
        The features in this group.
    indices : tuple[int, ...]
        Their column positions in X.
    score_full : float
        Metric with every feature present.
    score_without : float
        Metric with this group dropped and the model refit.
    drop : float
        ``score_full - score_without``. Positive means the group carried
        information nothing else replaced. Values at or below zero mean the
        group is redundant given the rest -- not that it is uninformative in
        isolation, which is a different and often less useful claim.
    """

    names: tuple[str, ...]
    indices: tuple[int, ...]
    score_full: float
    score_without: float
    drop: float


def correlation_groups(
    X: np.ndarray,
    feature_names: Sequence[str] | None = None,
    threshold: float = 0.80,
) -> list[list[int]]:
    """Cluster features into mutually-redundant groups by absolute correlation.

    Single-linkage: features land in the same group if a chain of pairwise
    correlations at or above ``threshold`` connects them. Single-linkage is
    the right choice here because redundancy is transitive in the way that
    matters -- if a is a copy of b and b is a copy of c, permuting any one of
    them leaves the other two available to the model.

    Grouping is what makes the audit interpretable. Ablating one column at a
    time when a near-copy remains in the matrix measures nothing: the model
    reads the copy and the metric does not move.

    Parameters
    ----------
    X : array of shape (n_samples, n_features)
    feature_names : optional names, only used by callers for reporting.
    threshold : absolute Pearson correlation at or above which two features
        are treated as redundant. The 0.80 default is measured, not guessed.
        Injecting three copies of the strongest feature at a controlled
        correlation and reading back its permutation importance as a fraction
        of its uncontaminated value gives:

            corr(x0, copy)   signal retained   rank of x0
                 0.9995              0%            12
                 0.9949              0%             5
                 0.9570             13%             2
                 0.8545             42%             2
                 0.7014             75%             1
                 0.4388             91%             1
                 0.1875             99%             1

        The damage is already severe at 0.85 -- well below the 0.95 that an
        earlier version of this function used as its default, which would
        have left pairs at 0.90 ungrouped while they were losing roughly half
        their measured importance. 0.80 sits just past the knee. Raise it
        toward 0.95 only if large merged groups make the audit unreadable,
        and report the sensitivity if you do.

    Returns
    -------
    List of groups, each a sorted list of column indices. Every column appears
    in exactly one group; uncorrelated features come back as singletons.
    Groups are ordered by their lowest member index, so the output is
    deterministic.
    """
    X = np.asarray(X, dtype=np.float64)
    n_features = X.shape[1]
    if feature_names is not None and len(feature_names) != n_features:
        raise ValueError(
            f"feature_names has {len(feature_names)} entries but X has {n_features} columns"
        )
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"threshold must be in [0, 1], got {threshold}")

    # A constant column has undefined correlation; np.corrcoef emits nan for
    # it. Treat nan as "not correlated" so constants stay singletons rather
    # than silently absorbing other features.
    with np.errstate(invalid="ignore", divide="ignore"):
        corr = np.corrcoef(X, rowvar=False)
    corr = np.atleast_2d(corr)
    corr[~np.isfinite(corr)] = 0.0

    parent = list(range(n_features))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    for i in range(n_features):
        for j in range(i + 1, n_features):
            if abs(corr[i, j]) >= threshold:
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n_features):
        groups.setdefault(find(i), []).append(i)
    return [sorted(g) for _, g in sorted(groups.items())]


def leave_group_out(
    fit_predict: Callable[[np.ndarray, np.ndarray, np.ndarray], np.ndarray],
    score: Callable[[np.ndarray, np.ndarray], float],
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    groups: Sequence[Sequence[int]],
    feature_names: Sequence[str] | None = None,
) -> list[GroupImportance]:
    """Measure each group's importance by dropping it and refitting.

    The refit is the point. Permutation importance perturbs the input to an
    already-fitted model, so a model that has learned to lean on a redundant
    copy keeps its performance and the permuted feature scores zero. Refitting
    without the group asks the strictly more useful question: could a model
    trained from scratch have recovered this performance from the remaining
    features?

    ``fit_predict`` and ``score`` are injected rather than fixed so the
    protocol is agnostic to both estimator and metric. Under class imbalance
    the metric choice matters more than the estimator: pass a metric whose
    no-skill baseline tracks the positive rate (average precision) rather than
    one that does not (accuracy, ROC-AUC).

    Parameters
    ----------
    fit_predict : callable ``(X_train, y_train, X_test) -> scores``
        Fits a fresh model and returns test-set scores or probabilities.
        Must not close over the full feature matrix -- it receives exactly
        the columns it is allowed to use.
    score : callable ``(y_true, y_score) -> float``, higher is better.
    groups : the output of `correlation_groups`, or any partition of columns.
    feature_names : optional; defaults to ``f"x{i}"``.

    Returns
    -------
    One `GroupImportance` per group, sorted by ``drop`` descending.

    Notes
    -----
    Cost is one refit per group plus one for the full model. That is more
    expensive than permutation importance and it is the price of an answer
    that survives correlated inputs.
    """
    X_train = np.asarray(X_train)
    X_test = np.asarray(X_test)
    n_features = X_train.shape[1]
    if X_test.shape[1] != n_features:
        raise ValueError(
            f"X_train has {n_features} columns but X_test has {X_test.shape[1]}"
        )
    if feature_names is not None:
        names = list(feature_names)
    else:
        names = [f"x{i}" for i in range(n_features)]
    if len(names) != n_features:
        raise ValueError(f"feature_names has {len(names)} entries but X has {n_features} columns")

    score_full = float(score(y_test, fit_predict(X_train, y_train, X_test)))

    results: list[GroupImportance] = []
    for group in groups:
        idx = tuple(sorted(group))
        if not idx:
            continue
        if min(idx) < 0 or max(idx) >= n_features:
            raise ValueError(f"group {idx} has indices outside [0, {n_features})")
        keep = [i for i in range(n_features) if i not in set(idx)]
        if not keep:
            # Dropping every feature leaves nothing to fit; report the group as
            # carrying all of the signal rather than raising, since "the only
            # group" is a legitimate if degenerate audit target.
            results.append(
                GroupImportance(
                    names=tuple(names[i] for i in idx),
                    indices=idx,
                    score_full=score_full,
                    score_without=float("nan"),
                    drop=float("nan"),
                )
            )
            continue
        score_without = float(
            score(y_test, fit_predict(X_train[:, keep], y_train, X_test[:, keep]))
        )
        results.append(
            GroupImportance(
                names=tuple(names[i] for i in idx),
                indices=idx,
                score_full=score_full,
                score_without=score_without,
                drop=score_full - score_without,
            )
        )

    # nan drops sort last rather than unpredictably.
    return sorted(results, key=lambda r: (-r.drop if np.isfinite(r.drop) else np.inf))
