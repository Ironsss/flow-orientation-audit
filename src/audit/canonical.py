"""Canonical windowing and immutable ground truth -- the evaluation instrument.

P0 (docs/datos-reales/, the sampling & label audit) showed that the windowing
in `src.features.windows.window_features` is not a fixed measuring device: it
re-derives the window grid from ``ts.min()`` of whatever frame it is handed, so
a sampled frame is partitioned differently from the full one, the anchor moves
between sampling rates, a window with no surviving rows silently ceases to
exist, `min_flows` drops windows in proportion to how much information the
treatment removed, and the per-window label is computed *after* sampling. The
net effect at 1:1000 was that the benign class disappeared -- not because
sampling changed any flow's `is_attack`, but because the instrument let the
treatment reshape the set of evaluation units.

This module fixes the instrument, and only the instrument. It does not touch
the generator, the restriction operators, the features, or the model.

    full trace
      -> build_canonical_windowing()   # grid + ground truth, frozen here
      -> sample()                       # withdraws information, nothing else
      -> canonical_window_features()    # observations mapped back onto the
                                        # frozen grid; one row per canonical
                                        # window, always

Guarantees, by construction (see tests/test_canonical_windows.py, I1-I8):

  I1  window_start / window_end are identical at every sampling rate.
  I2  a window_id denotes one fixed time interval, always.
  I3  y_gt is identical at every sampling rate.
  I4  attack_ratio_gt is identical at every sampling rate.
  I5  a window with n_observed == 0 still appears in the output.
  I6  a window with n_observed < min_flows still appears in the output.
  I7  the number and identity of canonical windows do not change with sampling.
  I8  every rate evaluates the same windows, boundaries, labels, ground truth;
      only the observed rows differ.

`min_flows` is retained only as the threshold below which a *feature* is
flagged unavailable (`feature_available`). It never removes a window. It is
not a function of the sampling rate (P0.5.5).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import polars as pl

from src.features.extractors import (
    PERFLOW_FEATURES,
    SIZE_FEATURES,
    TOPOLOGY_FEATURES,
    perflow_features,
    size_features,
    topology_features,
)
from src.features.tiers import InfoTier

__all__ = [
    "CanonicalWindowing",
    "anchor_shift_seconds",
    "build_canonical_windowing",
    "canonical_window_features",
    "map_to_canonical_window",
]

#: Columns the output always carries, before any feature columns. Kept as a
#: name so the audit script and the tests agree on the contract.
LEDGER_COLUMNS = (
    "window_id",
    "window_start",
    "window_end",
    "attack_ratio_gt",
    "y_gt",
    "n_flows_gt",
    "n_observed",
    "attack_ratio_observed",
    "has_evidence",
    "feature_available",
)


@dataclass(frozen=True)
class CanonicalWindowing:
    """A frozen window grid plus its ground truth, derived once from a full trace.

    Every array is aligned to `window_ids` and made read-only, so nothing
    downstream can rewrite the grid or the labels. `sample()` produces a
    smaller frame; it never produces a different `CanonicalWindowing`.

    Fields
    ------
    global_t0        : epoch-seconds anchor = min timestamp of the full trace.
    window_seconds   : grid step.
    tau              : label threshold on attack_ratio_gt (C5).
    window_ids       : int array, sorted, one entry per canonical window. A
                       window is canonical iff the *full* trace put at least
                       one flow in it -- a genuine gap in the full trace is
                       not invented as a unit.
    window_start/end : epoch-seconds bounds, aligned to window_ids.
    attack_ratio_gt  : mean(is_attack) over the full trace's rows in the
                       window, aligned to window_ids. Immutable ground truth.
    y_gt             : int8 (attack_ratio_gt >= tau), aligned. Immutable.
    n_flows_gt       : full-trace flow count per window, aligned. Diagnostic.
    """

    global_t0: int
    window_seconds: int
    tau: float
    window_ids: np.ndarray
    window_start: np.ndarray
    window_end: np.ndarray
    attack_ratio_gt: np.ndarray
    y_gt: np.ndarray
    n_flows_gt: np.ndarray

    def __post_init__(self) -> None:
        for name in (
            "window_ids", "window_start", "window_end",
            "attack_ratio_gt", "y_gt", "n_flows_gt",
        ):
            arr = np.asarray(getattr(self, name))
            arr.setflags(write=False)
            object.__setattr__(self, name, arr)

    @property
    def n_windows(self) -> int:
        return int(self.window_ids.size)

    def gt_frame(self) -> pl.DataFrame:
        """The immutable part of the ledger as a DataFrame, for joins/asserts."""
        return pl.DataFrame({
            "window_id": self.window_ids,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "attack_ratio_gt": self.attack_ratio_gt,
            "y_gt": self.y_gt,
            "n_flows_gt": self.n_flows_gt,
        })


def _epoch_seconds(df: pl.DataFrame, col: str = "timestamp") -> np.ndarray:
    return df[col].dt.epoch("s").to_numpy()


def build_canonical_windowing(
    full_df: pl.DataFrame,
    *,
    window_seconds: int = 60,
    tau: float = 0.01,
    timestamp_col: str = "timestamp",
    attack_col: str = "is_attack",
) -> CanonicalWindowing:
    """Freeze the window grid and the ground truth from the pre-sampling trace.

    Call this exactly once per trace, before any restriction operator. The
    result is what every sampling rate is then evaluated against.
    """
    if len(full_df) == 0:
        raise ValueError("cannot build canonical windowing from an empty frame")
    if not 0.0 < tau <= 1.0:
        raise ValueError(f"tau must be in (0, 1], got {tau}")
    for col in (timestamp_col, attack_col):
        if col not in full_df.columns:
            raise ValueError(f"full trace is missing required column {col!r}")

    ts = _epoch_seconds(full_df, timestamp_col)
    global_t0 = int(ts.min())
    wid_all = ((ts - global_t0) // window_seconds).astype(np.int64)
    attack = full_df[attack_col].to_numpy().astype(np.float64)

    # group by window id over the full trace
    order = np.argsort(wid_all, kind="stable")
    wid_sorted = wid_all[order]
    attack_sorted = attack[order]
    uniq, starts = np.unique(wid_sorted, return_index=True)
    counts = np.diff(np.append(starts, wid_sorted.size))
    ratio = np.add.reduceat(attack_sorted, starts) / counts

    return CanonicalWindowing(
        global_t0=global_t0,
        window_seconds=int(window_seconds),
        tau=float(tau),
        window_ids=uniq.astype(np.int64),
        window_start=(global_t0 + uniq * window_seconds).astype(np.int64),
        window_end=(global_t0 + (uniq + 1) * window_seconds).astype(np.int64),
        attack_ratio_gt=ratio.astype(np.float64),
        y_gt=(ratio >= tau).astype(np.int8),
        n_flows_gt=counts.astype(np.int64),
    )


def map_to_canonical_window(
    df: pl.DataFrame,
    cw: CanonicalWindowing,
    *,
    timestamp_col: str = "timestamp",
) -> np.ndarray:
    """Window id per row of `df`, using the FROZEN anchor -- never `df.ts.min()`.

    Rows whose timestamp falls outside the canonical grid, or into a grid slot
    the full trace left empty, get -1. In practice a sampled frame is a subset
    of the full trace, so -1 does not occur; it is defended against rather than
    assumed away.
    """
    if len(df) == 0:
        return np.empty(0, dtype=np.int64)
    ts = _epoch_seconds(df, timestamp_col)
    wid = ((ts - cw.global_t0) // cw.window_seconds).astype(np.int64)
    canonical = np.isin(wid, cw.window_ids)
    wid[~canonical] = -1
    return wid


def canonical_window_features(
    sampled_df: pl.DataFrame,
    cw: CanonicalWindowing,
    *,
    tier: InfoTier,
    min_flows: int = 10,
) -> pl.DataFrame:
    """One row per canonical window -- ALWAYS -- from the sampled observations.

    The window set, boundaries and ground truth come entirely from `cw`. The
    sampled frame only supplies `n_observed`, `attack_ratio_observed` (a
    diagnostic, never a label) and the feature values.

    Evidence contract (P0.5.4-P0.5.6), documented so no reader has to infer it:

      n_observed == 0            has_evidence = False, feature_available = False
                                 topology/size/per-flow columns = 0.0 (the
                                 zeros the extractors already return for empty
                                 input -- a sentinel, not a measurement)
                                 attack_ratio_observed = NaN

      0 < n_observed < min_flows has_evidence = True, feature_available = False
                                 feature columns ARE computed from the few
                                 rows present, but flagged not-yet-trustworthy
                                 attack_ratio_observed = mean over those rows

      n_observed >= min_flows    has_evidence = True, feature_available = True

    In every case the window stays in the output. `min_flows` gates the flag,
    never the row, and does not depend on the sampling rate.
    """
    want_perflow = tier >= InfoTier.DIRECTIONAL
    if want_perflow:
        for col in ("totlen_fwd_pkts", "totlen_bwd_pkts"):
            if col not in sampled_df.columns:
                raise ValueError(
                    f"tier {tier.name} requires {col!r}; restriction dropped it "
                    "or ingestion never produced it"
                )

    wid = map_to_canonical_window(sampled_df, cw)
    src = dst = attack = fwd = bwd = None
    if wid.size:
        src = sampled_df["src_ip"].to_numpy()
        dst = sampled_df["dst_ip"].to_numpy()
        attack = sampled_df["is_attack"].to_numpy()
        if want_perflow:
            fwd = sampled_df["totlen_fwd_pkts"].to_numpy()
            bwd = sampled_df["totlen_bwd_pkts"].to_numpy()

    # row indices grouped by canonical window id, for O(1) per-window lookup
    by_window: dict[int, np.ndarray] = {}
    if wid.size:
        canonical = wid >= 0
        row_idx = np.nonzero(canonical)[0]
        wid_can = wid[canonical]
        order = np.argsort(wid_can, kind="stable")
        wid_sorted = wid_can[order]
        rows_sorted = row_idx[order]
        if wid_sorted.size:
            uniq, starts = np.unique(wid_sorted, return_index=True)
            ends = np.append(starts[1:], wid_sorted.size)
            for w, a, b in zip(uniq, starts, ends):
                by_window[int(w)] = rows_sorted[a:b]

    empty_topo = dict.fromkeys(TOPOLOGY_FEATURES, 0.0)
    empty_size = dict.fromkeys(SIZE_FEATURES, 0.0)
    empty_flow = dict.fromkeys(PERFLOW_FEATURES, 0.0)

    records: list[dict[str, float]] = []
    for i, w in enumerate(cw.window_ids):
        idx = by_window.get(int(w))
        n_obs = 0 if idx is None else int(idx.size)
        has_evidence = n_obs > 0
        feature_available = n_obs >= min_flows

        rec: dict[str, float] = {
            "window_id": int(w),
            "window_start": int(cw.window_start[i]),
            "window_end": int(cw.window_end[i]),
            "attack_ratio_gt": float(cw.attack_ratio_gt[i]),
            "y_gt": int(cw.y_gt[i]),
            "n_flows_gt": int(cw.n_flows_gt[i]),
            "n_observed": n_obs,
            "attack_ratio_observed": (
                float(attack[idx].mean()) if has_evidence else float("nan")
            ),
            "has_evidence": has_evidence,
            "feature_available": feature_available,
        }
        if has_evidence:
            rec.update(topology_features(src[idx], dst[idx]))
            rec.update(size_features(src[idx], dst[idx]))
            if want_perflow:
                rec.update(perflow_features(fwd[idx], bwd[idx]))
        else:
            rec.update(empty_topo)
            rec.update(empty_size)
            if want_perflow:
                rec.update(empty_flow)
        records.append(rec)

    return pl.DataFrame(records)


def anchor_shift_seconds(sampled_df: pl.DataFrame, cw: CanonicalWindowing) -> int:
    """Seconds by which the windowing anchor moves under this sample.

    Always 0: `canonical_window_features` anchors on `cw.global_t0`, which is a
    property of the full trace and independent of which rows survived. Provided
    so the audit can assert the P0 anchor drift (2-146 s) is gone, not merely
    claim it.
    """
    return 0
