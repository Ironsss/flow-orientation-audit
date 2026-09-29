"""
Graph Asymmetry Index (IAG) - Core definitions and computation.

Two measures of graph asymmetry:

1. Directional Asymmetry (A_dir): ratio of unidirectional to total edges.
   - Port scan -> ~1 (all unidirectional); normal traffic -> ~0.
   - O(|E|), trivially computable.

2. Entropic Asymmetry (A_ent): KL divergence between in-degree and out-degree distributions.
   - DDoS collapses entropy toward victim node.
   - O(|V|).

A third, "spectral" component (comparing eigenspectra of the adjacency
matrix against various derived matrices) was investigated and retired: three
successive formulations were each either mathematically vacuous (comparing
eigenvalues of A against A^T -- always ~0 for any matrix, by a linear
algebra identity) or, once corrected to be non-trivial, turned out to be
redundant with one of A_dir or A_ent rather than adding independent
information (verified by checking whether they distinguished a DDoS-like
star from a fully asymmetric directed cycle -- both have identical A_dir,
and a working third component should be able to tell them apart; none of
the three attempts that were mathematically sound could do this without
just re-deriving what A_dir or A_ent already computed). Rather than ship a
formula whose independent value couldn't be demonstrated, or add further
complexity (e.g. a reachability/strongly-connected-components measure that
showed promise but has its own real caveats on realistic mixed-traffic
graphs) without validating it against real data first, the IAG here is
two-component. The full investigation -- every formula tried, why each was
rejected, and the numbers behind that decision -- is preserved in
docs/matematicas/03-asimetria-espectral.md, since a documented dead end is
more useful to future work than a silently discarded one.

The final IAG is a vector [A_dir, A_ent] or a weighted combination.
"""

import numpy as np
from torch_geometric.data import Data


def directional_asymmetry(data: Data) -> float:
    """
    Compute the directional asymmetry of a graph.

    A_dir = 1 - |bidirectional edges| / |total unique edges|

    A bidirectional edge is one where both (u,v) and (v,u) exist.
    Returns a value in [0, 1] where:
    - 0 = perfectly symmetric (all edges are bidirectional)
    - 1 = perfectly asymmetric (all edges are unidirectional)
    """
    if data.edge_index.size(1) == 0:
        return 0.0

    edge_index = data.edge_index.numpy()
    src, dst = edge_index[0], edge_index[1]

    # Set of directed edges
    forward_edges = set(zip(src.tolist(), dst.tolist()))
    # Count how many have a reverse
    bidirectional = sum(1 for s, d in forward_edges if (d, s) in forward_edges)
    total = len(forward_edges)

    if total == 0:
        return 0.0

    # bidirectional counts each pair twice (both (u,v) and (v,u) are in the set)
    return 1.0 - bidirectional / total


def entropic_asymmetry(data: Data) -> float:
    """
    Compute the entropic asymmetry of a graph.

    A_ent = KL(P_in || P_out) + KL(P_out || P_in)

    where P_in and P_out are the normalized in-degree and out-degree distributions.
    Uses symmetrized KL divergence (Jensen-Shannon style) for stability.

    Returns a value >= 0 where 0 means identical degree distributions.
    """
    if data.num_nodes < 2 or data.edge_index.size(1) == 0:
        return 0.0

    n = data.num_nodes
    edge_index = data.edge_index.numpy()

    # Compute weighted degrees.
    # np.atleast_1d guards the single-edge case: .squeeze() on a (1, 1)
    # edge_attr collapses to a 0-d array, which then raises IndexError on
    # weights[i] below. Single-edge windows are common in sparse real
    # traffic (quiet hours, first/last bucket of a capture), so this is a
    # real crash path, not a synthetic edge case.
    if data.edge_attr is not None:
        weights = np.atleast_1d(data.edge_attr.squeeze().numpy())
    else:
        weights = np.ones(edge_index.shape[1])

    in_deg = np.zeros(n, dtype=np.float64)
    out_deg = np.zeros(n, dtype=np.float64)

    for i in range(edge_index.shape[1]):
        src, dst = edge_index[0, i], edge_index[1, i]
        out_deg[src] += weights[i]
        in_deg[dst] += weights[i]

    # Normalize to probability distributions (add small epsilon for stability)
    eps = 1e-10
    p_in = (in_deg + eps) / (in_deg + eps).sum()
    p_out = (out_deg + eps) / (out_deg + eps).sum()

    # Symmetrized KL divergence
    kl_in_out = np.sum(p_in * np.log(p_in / p_out))
    kl_out_in = np.sum(p_out * np.log(p_out / p_in))

    return float((kl_in_out + kl_out_in) / 2.0)


DEFAULT_IAG_WEIGHTS = (0.5, 0.5)


def compute_iag(
    data: Data,
    weights: tuple[float, float] = DEFAULT_IAG_WEIGHTS,
) -> dict[str, float]:
    """
    Compute the full IAG vector for a graph.

    Parameters
    ----------
    weights : tuple[float, float]
        (w_dir, w_ent) weights for the combined index. Default is an
        equal-weight average of the *raw* components — a provisional choice,
        not empirically tuned. Because A_dir is bounded in [0, 1] while
        A_ent is unbounded [0, inf), equal weighting on raw values lets
        A_ent dominate the combined score whenever its typical magnitude on
        a given dataset is large, independent of its actual detection
        relevance. Use `fit_iag_weights()` on labeled data to derive weights
        that account for this instead of assuming equal importance.

    Returns
    -------
    dict with keys:
        - iag_directional: directional asymmetry [0, 1]
        - iag_entropic: entropic asymmetry [0, inf)
        - iag_combined: weighted combination (primary index)
    """
    if len(weights) != 2:
        raise ValueError(
            f"weights must have exactly 2 elements (dir, ent), got {len(weights)}"
        )

    a_dir = directional_asymmetry(data)
    a_ent = entropic_asymmetry(data)

    w_dir, w_ent = weights
    iag_combined = w_dir * a_dir + w_ent * a_ent

    return {
        "iag_directional": a_dir,
        "iag_entropic": a_ent,
        "iag_combined": iag_combined,
    }


def compute_iag_batch(
    graphs: list[Data],
    weights: tuple[float, float] = DEFAULT_IAG_WEIGHTS,
) -> list[dict[str, float]]:
    """Compute IAG for a list of graph snapshots."""
    return [compute_iag(g, weights=weights) for g in graphs]


def fit_iag_weights(
    iag_records: list[dict[str, float]],
    labels: list[int] | np.ndarray,
) -> dict[str, float]:
    """
    Empirically fit combined-index weights from labeled IAG components.

    This is the "tuned empirically" step the equal-weight default in
    `compute_iag` explicitly defers. Each raw component is standardized
    (z-score) so A_dir and A_ent are on comparable scales before fitting —
    combining them unstandardized, as the equal-weight default does, is only
    a placeholder for exactly this reason. An L2-regularized logistic
    regression of the binary attack label on the two standardized components
    is then fit; its coefficients are clipped to be non-negative (a
    component negatively associated with "attack" should not actively count
    against the combined index) and L1-normalized to sum to 1.

    Parameters
    ----------
    iag_records : list[dict]
        Output of compute_iag_batch (each dict must have iag_directional,
        iag_entropic).
    labels : array-like of int
        Binary attack label (0/1) aligned with iag_records.

    Returns
    -------
    dict with keys "iag_directional", "iag_entropic" mapping to fitted,
    non-negative weights that sum to 1. Pass as
    `(w["iag_directional"], w["iag_entropic"])` to
    `compute_iag`/`compute_iag_batch`'s `weights` parameter.

    Note
    ----
    The fitted weights apply to *standardized* components. Passing them into
    `compute_iag(weights=...)`, which weights raw components, is only
    consistent if the same graphs (or a distribution with similar component
    scales) are being scored — refit if the traffic mix changes substantially.
    """
    from sklearn.linear_model import LogisticRegression

    X = np.array([
        [r["iag_directional"], r["iag_entropic"]]
        for r in iag_records
    ])
    y = np.asarray(labels)

    if len(np.unique(y)) < 2:
        raise ValueError("fit_iag_weights needs both classes (benign and attack) present in labels")

    std = X.std(axis=0)
    std[std == 0] = 1.0  # avoid div-by-zero for a constant component
    X_std = (X - X.mean(axis=0)) / std

    clf = LogisticRegression(C=1.0)  # default penalty is L2
    clf.fit(X_std, y)

    raw_weights = np.clip(clf.coef_[0], a_min=0.0, a_max=None)
    total = raw_weights.sum()
    if total == 0:
        # No component had a positive coefficient — fall back to the equal-
        # weight default rather than returning an all-zero combined index.
        normalized = np.array(DEFAULT_IAG_WEIGHTS)
    else:
        normalized = raw_weights / total

    return {
        "iag_directional": float(normalized[0]),
        "iag_entropic": float(normalized[1]),
    }
