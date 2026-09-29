"""Window feature extractors, each declaring the information tier it needs.

Two families, and the contrast between them is the experiment:

  topology_features   TUPLES      -- shape of who-talked-to-whom
  perflow_features    DIRECTIONAL -- distribution of per-flow byte asymmetry
  size_features       TUPLES      -- the control, never a treatment

`size_features` exists to be subtracted, not used. Node and edge counts
separate classes trivially whenever the attack introduces hosts, and this
project has already published an internal AUC of 1.0000 that turned out to be
`n_nodes` sitting at 51 in one class and 50 in the other with zero overlap
(docs/metodologia/). Control C1 requires reporting it as its own arm in every
comparison, so it ships as a first-class extractor rather than as something a
future experiment has to remember to build.

The topology features are deliberately scale-invariant -- ratios and
concentration measures rather than counts -- precisely so they do not smuggle
`size_features` back in through the side door. That is a design constraint the
earlier IAG did not have, and it is why `A_dir` was diluted into uselessness by
background traffic while these are not.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from src.features.tiers import InfoTier

__all__ = [
    "FEATURE_TIERS",
    "PERFLOW_FEATURES",
    "SIZE_FEATURES",
    "TOPOLOGY_FEATURES",
    "features_at_tier",
    "perflow_features",
    "size_features",
    "topology_features",
]

TOPOLOGY_FEATURES = (
    "top_maxindeg_frac",
    "top_indeg_gini",
    "top_reciprocity",
    "top_edges_per_node",
    "top_fanout_max_frac",
)
PERFLOW_FEATURES = ("fl_mean", "fl_std", "fl_p90", "fl_frac_gt1")
SIZE_FEATURES = ("sz_nodes", "sz_edges")

#: Tier required by every feature this module can produce.
FEATURE_TIERS: dict[str, InfoTier] = {
    **{name: InfoTier.TUPLES for name in TOPOLOGY_FEATURES},
    **{name: InfoTier.TUPLES for name in SIZE_FEATURES},
    **{name: InfoTier.DIRECTIONAL for name in PERFLOW_FEATURES},
}


def features_at_tier(tier: InfoTier) -> list[str]:
    """Every feature computable when the available information is `tier`.

    The filter an experiment uses to build an arm. Sorted so a feature matrix
    built from it has a deterministic column order across runs.
    """
    return sorted(name for name, need in FEATURE_TIERS.items() if need <= tier)


def _gini(values: np.ndarray) -> float:
    """Relative mean absolute difference, the standard concentration measure.

    Zero when every node receives equally, approaching one as traffic
    concentrates on a single destination -- the shape a DDoS imposes. Scale
    invariant by construction, which is the property that keeps this from
    becoming a node count in disguise.
    """
    if values.size == 0:
        return 0.0
    mean = float(values.mean())
    if mean <= 0:
        return 0.0
    return float(np.abs(np.subtract.outer(values, values)).mean() / (2.0 * mean))


def topology_features(src: Sequence, dst: Sequence) -> dict[str, float]:
    """Shape of the communication graph from `(src, dst)` pairs alone.

    Needs InfoTier.TUPLES: no byte counts, no packet counts, no timing. This is
    the information a router exports first and the reason the whole
    operational argument favours topology -- everything here is computable from
    a NetFlow record stripped to its addresses.

    Edges are deduplicated, so repeated flows between one host pair count once.
    That is the same edge-set binarization that made `A_dir` fragile, and it is
    retained deliberately here: reciprocity is a property of the pair, not of
    the traffic volume, and the volume-weighted variant belongs to a richer
    tier. Empty input returns zeros rather than raising, since sparse windows
    are ordinary in real captures.
    """
    src = list(src)
    dst = list(dst)
    if not src:
        return dict.fromkeys(TOPOLOGY_FEATURES, 0.0)

    edges = set(zip(src, dst))
    nodes = set(src) | set(dst)
    n_edges = max(len(edges), 1)

    indeg: dict[object, int] = {}
    outdeg: dict[object, int] = {}
    for a, b in edges:
        indeg[b] = indeg.get(b, 0) + 1
        outdeg[a] = outdeg.get(a, 0) + 1

    in_counts = np.fromiter(indeg.values(), dtype=np.float64, count=len(indeg))
    out_counts = np.fromiter(outdeg.values(), dtype=np.float64, count=len(outdeg))
    reciprocal = sum(1 for a, b in edges if (b, a) in edges)

    return {
        # concentration of arrivals: a many-to-one flood drives this toward 1
        "top_maxindeg_frac": float(in_counts.max() / n_edges) if in_counts.size else 0.0,
        "top_indeg_gini": _gini(in_counts),
        # fraction of host pairs that talked both ways
        "top_reciprocity": float(reciprocal / n_edges),
        # density: fan-out patterns push this up without needing counts
        "top_edges_per_node": float(len(edges) / max(len(nodes), 1)),
        # concentration of departures: a single scanner drives this toward 1
        "top_fanout_max_frac": float(out_counts.max() / n_edges) if out_counts.size else 0.0,
    }


def perflow_features(fwd_bytes: np.ndarray, bwd_bytes: np.ndarray) -> dict[str, float]:
    """Distribution of per-flow directional asymmetry within a window.

    Needs InfoTier.DIRECTIONAL: both halves of each conversation, associated.
    The log-ratio ``log(1+fwd) - log(1+bwd)`` is the scalar that reaches AUC
    0.998 on port scans and 0.946 on DDoS with no graph at all, and it is the
    baseline the operational argument has to beat under restriction rather than
    on clean data, where it wins.

    Returns zeros on empty input for the same reason as above.
    """
    fwd = np.asarray(fwd_bytes, dtype=np.float64)
    bwd = np.asarray(bwd_bytes, dtype=np.float64)
    if fwd.size == 0:
        return dict.fromkeys(PERFLOW_FEATURES, 0.0)

    ratio = np.log1p(fwd) - np.log1p(bwd)
    return {
        "fl_mean": float(ratio.mean()),
        "fl_std": float(ratio.std()),
        "fl_p90": float(np.percentile(ratio, 90)),
        # fraction of flows sending an order of magnitude more than they receive
        "fl_frac_gt1": float((ratio > 1.0).mean()),
    }


def size_features(src: Sequence, dst: Sequence) -> dict[str, float]:
    """Raw node and edge counts -- the C1 control arm.

    Never belongs in a treatment. Report it beside every comparison so that a
    lift which is really "the attack brought new hosts" is visible as such
    instead of being read as structural signal.
    """
    src = list(src)
    dst = list(dst)
    if not src:
        return dict.fromkeys(SIZE_FEATURES, 0.0)
    return {
        "sz_nodes": float(len(set(src) | set(dst))),
        "sz_edges": float(len(set(zip(src, dst)))),
    }
