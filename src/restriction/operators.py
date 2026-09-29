"""Operators that withdraw information from a flow frame.

Each one models a way real telemetry is poorer than a research dataset. They
are the independent variable of hypothesis H2: under restriction, does topology
degrade less than per-flow asymmetry, and does the gap widen?

  sample()     NetFlow/IPFIX rarely records every flow. 1:1000 is ordinary on a
               backbone. Both representations lose rows, but they may not lose
               them equally: a star is still recognisably a star from a sample
               of its edges, while the mean of a byte ratio over few flows is
               just noisy.

  truncate()   Decide at t seconds into a window rather than at its end. Note
               what this does and does not model: flows in this data complete
               fast (p50 0.01s, p99 1.32s), so truncation removes flows that
               have not STARTED, not flows still running. The early-detection
               limit here is sample size, not incomplete accounting.

  enforce_tier()  Drop the columns a tier cannot see. The strict one: after
               restricting to TUPLES, per-flow features cannot be computed at
               all, because the columns are gone rather than merely ignored.

Deliberately not modelled, and worth knowing before reading any result as
operational: exporter timeouts splitting one conversation into several records,
asymmetric routing showing only one direction, NAT collapsing many hosts onto
one address, and clock skew between exporters. Each would hurt topology and
per-flow differently, and none is captured here.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from src.features.tiers import TIER_COLUMNS, InfoTier

__all__ = ["enforce_tier", "sample", "sample_mask", "truncate"]


def sample_mask(n: int, rate: int, seed: int = 0) -> np.ndarray:
    """The boolean keep-mask a Bernoulli 1:`rate` sample would apply to `n` rows.

    Factored out of `sample` so the sampling design is inspectable and testable
    on its own, and so the *nesting* property can be stated exactly: for a fixed
    `seed` and a fixed `n`, one uniform vector ``u`` is drawn and every rate
    thresholds the *same* ``u`` at ``1/rate``. Therefore

        keep(1000) ⊆ keep(100) ⊆ keep(10) ⊆ keep(1)

    row-for-row -- a coarser sample is always a subset of a finer one on the
    same frame and seed (P0.5.7). This holds only when `n` and row order are
    identical across the calls being compared, i.e. the same pre-sampling
    frame; it says nothing across two different traces.

    `seed` here is the *sampling* seed and is deliberately a separate argument
    from any simulation seed -- coupling the two is what P0 flagged.
    """
    if rate < 1:
        raise ValueError(f"rate must be >= 1, got {rate}")
    if rate == 1:
        return np.ones(n, dtype=bool)
    rng = np.random.default_rng(seed)
    return rng.random(n) < (1.0 / rate)


def sample(df: pl.DataFrame, rate: int, seed: int = 0) -> pl.DataFrame:
    """Keep roughly one flow in `rate` -- NetFlow-style packet sampling.

    Bernoulli rather than deterministic every-nth: real samplers are
    probabilistic, and deterministic selection can alias against periodic
    traffic such as botnet beaconing, manufacturing structure that is an
    artifact of the sampler rather than of the attack.

    Parameters
    ----------
    rate : 1 keeps everything; 1000 keeps about a thousandth.
    seed : the *sampling* seed -- separate from the simulation seed on purpose.
        Sampling is part of the experiment, so it is seeded and reported.

    Notes
    -----
    Sampling can empty a window entirely. That is a valid outcome of the
    treatment, not a reason to drop the window: the canonical-windowing
    instrument in `src.audit.canonical` keeps every window and records
    `n_observed = 0` rather than letting the unit disappear. The bare
    row-count reduction here is unchanged; what changed is that downstream
    windowing no longer re-anchors to the surviving `ts.min()`.
    """
    if rate == 1:
        return df
    return df.filter(pl.Series(sample_mask(len(df), rate, seed)))


def truncate(
    df: pl.DataFrame,
    window_seconds: int,
    observed_fraction: float,
    timestamp_col: str = "timestamp",
) -> pl.DataFrame:
    """Keep only flows starting in the first `observed_fraction` of each window.

    Models deciding early: at 0.1 of a 60s window you are ruling on six seconds
    of evidence. Windows are anchored to the frame's own minimum timestamp so
    the partition is reproducible and independent of absolute epoch.

    Parameters
    ----------
    observed_fraction : in (0, 1]; 1.0 returns the frame unchanged.
    """
    if not 0.0 < observed_fraction <= 1.0:
        raise ValueError(f"observed_fraction must be in (0, 1], got {observed_fraction}")
    if observed_fraction == 1.0:
        return df
    if timestamp_col not in df.columns:
        raise ValueError(f"missing timestamp column {timestamp_col!r}")

    ts = df[timestamp_col].dt.epoch("s").to_numpy()
    offset = (ts - ts.min()) % window_seconds
    return df.filter(pl.Series(offset <= window_seconds * observed_fraction))


def enforce_tier(df: pl.DataFrame, tier: InfoTier) -> pl.DataFrame:
    """Drop every column the tier cannot see.

    The strict form of restriction. `sample` and `truncate` remove rows, which
    a determined feature extractor could partly work around; this removes
    columns, so a TUPLES-restricted run genuinely cannot compute a per-flow
    byte ratio -- the data is not there.

    Label columns (`is_attack`, `label`, `attack_ratio`) are always retained.
    They are not inputs; they are how the experiment is scored, and a router's
    telemetry poverty says nothing about whether an analyst later knew the
    ground truth.
    """
    required = TIER_COLUMNS[tier]
    if not required:  # FULL keeps everything
        return df
    labels = ("is_attack", "label", "attack_ratio")
    keep = [c for c in df.columns if c in required or c in labels]
    missing = set(required) - set(df.columns)
    if missing:
        raise ValueError(f"frame lacks columns required by {tier.name}: {sorted(missing)}")
    return df.select(keep)
