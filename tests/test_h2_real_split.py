"""scripts/run_h2_real.py's temporal split helpers.

split_timestamp/temporal_row_split exist specifically to avoid a second
anchor-drift bug (distinct from the one src.audit.canonical fixes): cutting
train/test by raw row index (src.models.benchmark.temporal_split) can bisect
a single canonical window's rows across the two sets. These tests pin that
the cut is always a genuine window-grid boundary and that the resulting
splits never overlap or lose rows.
"""

from __future__ import annotations

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.audit.canonical import build_canonical_windowing  # noqa: E402
from src.simulator.agents import AttackType, SimulationConfig, run_simulation  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_h2_real import split_timestamp, temporal_row_split  # noqa: E402

WINDOW_SECONDS = 60


def _trace() -> pl.DataFrame:
    return run_simulation(SimulationConfig(
        attack_type=AttackType.DDOS, asymmetry_level=0.8,
        duration_seconds=1200, seed=1,
    ))


class TestSplitTimestamp:
    def test_is_an_exact_window_boundary(self):
        df = _trace()
        cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
        split_ts = split_timestamp(cw)
        assert split_ts in set(cw.window_start.tolist())

    def test_respects_train_fraction_ordering(self):
        df = _trace()
        cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
        split_70 = split_timestamp(cw, train_fraction=0.70)
        split_30 = split_timestamp(cw, train_fraction=0.30)
        assert split_30 <= split_70

    def test_never_returns_the_first_or_past_the_last_window(self):
        df = _trace()
        cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
        split_ts = split_timestamp(cw, train_fraction=0.01)
        assert split_ts >= int(cw.window_start[0])
        split_ts_hi = split_timestamp(cw, train_fraction=0.99)
        assert split_ts_hi <= int(cw.window_start[-1])


class TestTemporalRowSplit:
    def test_no_overlap_and_no_lost_rows(self):
        df = _trace()
        cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
        split_ts = split_timestamp(cw)
        train, test = temporal_row_split(df, split_ts)
        assert len(train) + len(test) == len(df)
        train_max = train["timestamp"].dt.epoch("s").max()
        test_min = test["timestamp"].dt.epoch("s").min()
        assert train_max < split_ts <= test_min

    def test_both_splits_non_empty_at_default_fraction(self):
        df = _trace()
        cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
        split_ts = split_timestamp(cw)
        train, test = temporal_row_split(df, split_ts)
        assert len(train) > 0
        assert len(test) > 0
