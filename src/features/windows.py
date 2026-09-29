"""Turn a flow frame into one feature row per time window.

The bridge between `src.restriction` (which withdraws information) and
`src.features.extractors` (which computes what survives). Restriction operators
run on the flow frame *before* this, so a restricted run genuinely cannot see
what it is not supposed to see.

Two design choices here are consequences of mistakes this project already made,
and both are enforced rather than left to the caller:

  - `min_flows` drops degenerate windows. A window of 4 nodes and 2 flows once
    produced A_dir = 1.0 and single-handedly flipped Cohen's d negative for
    every IAG component (docs/review/ finding 2.3). Control C4.

  - The label is `attack_ratio >= tau` with tau explicit and required at the
    call site. `attack_ratio > 0` let a single attack flow among thousands mark
    a window, which is how windows that were 99.3% benign entered the positive
    class (finding 2.4). Control C5.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from src.features.extractors import perflow_features, size_features, topology_features
from src.features.tiers import InfoTier

__all__ = ["window_features"]


def window_features(
    df: pl.DataFrame,
    *,
    tier: InfoTier,
    window_seconds: int = 60,
    tau: float = 0.01,
    min_flows: int = 10,
) -> pl.DataFrame:
    """One row per window: features computable at `tier`, plus the label.

    Parameters
    ----------
    df : ingested flow frame. Needs at least the columns `tier` implies, plus
        `is_attack` for the label.
    tier : the information level to compute at. Per-flow features are omitted
        below DIRECTIONAL because they cannot be computed, not because they
        were judged unhelpful -- the columns are absent.
    tau : label threshold on `attack_ratio`. Explicit by design (C5); vary it
        and report the sensitivity rather than picking one silently.
    min_flows : windows below this are dropped as degenerate (C4).

    Returns
    -------
    Frame with columns: `window`, `y`, `attack_ratio`, `n_flows`, then the
    feature columns available at `tier`. Size features are always present --
    they are the C1 control arm and every comparison has to report them.

    Notes
    -----
    Windows are anchored to the frame's own minimum timestamp, so a truncated
    or sampled frame partitions the same way the full one did and the arms
    stay comparable.
    """
    required = {"timestamp", "src_ip", "dst_ip", "is_attack"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"missing required columns: {sorted(missing)}")
    if not 0.0 < tau <= 1.0:
        raise ValueError(f"tau must be in (0, 1], got {tau}")
    if len(df) == 0:
        return pl.DataFrame()

    ts = df["timestamp"].dt.epoch("s").to_numpy()
    window_id = (ts - ts.min()) // window_seconds
    src = df["src_ip"].to_numpy()
    dst = df["dst_ip"].to_numpy()
    attack = df["is_attack"].to_numpy()

    want_perflow = tier >= InfoTier.DIRECTIONAL
    if want_perflow:
        for col in ("totlen_fwd_pkts", "totlen_bwd_pkts"):
            if col not in df.columns:
                raise ValueError(
                    f"tier {tier.name} requires {col!r}, which the frame does not have "
                    "-- restriction dropped it, or ingestion never produced it"
                )
        fwd = df["totlen_fwd_pkts"].to_numpy()
        bwd = df["totlen_bwd_pkts"].to_numpy()

    rows: list[dict[str, float]] = []
    for wid in np.unique(window_id):
        mask = window_id == wid
        n = int(mask.sum())
        if n < min_flows:
            continue  # C4: degenerate windows never enter the analysis
        ratio = float(attack[mask].mean())
        row: dict[str, float] = {
            "window": float(wid),
            "y": float(ratio >= tau),  # C5: explicit threshold
            "attack_ratio": ratio,
            "n_flows": float(n),
            **topology_features(src[mask], dst[mask]),
            **size_features(src[mask], dst[mask]),  # C1 control, always reported
        }
        if want_perflow:
            row.update(perflow_features(fwd[mask], bwd[mask]))
        rows.append(row)

    return pl.DataFrame(rows) if rows else pl.DataFrame()
