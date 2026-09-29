"""Operators that withdraw information, modelling real telemetry poverty.

The independent variable of hypothesis H2 (docs/metodologia/). Applied to a
flow frame before feature extraction, so a restricted run cannot read what a
restricted deployment would not have.

    from src.restriction import sample, truncate, enforce_tier

    sample(df, rate=1000)                      # NetFlow-style 1:1000
    truncate(df, window_seconds=60, observed_fraction=0.1)   # decide at 6s
    enforce_tier(df, InfoTier.TUPLES)          # drop the columns entirely
"""

from src.restriction.operators import enforce_tier, sample, sample_mask, truncate

__all__ = ["enforce_tier", "sample", "sample_mask", "truncate"]
