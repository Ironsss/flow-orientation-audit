"""P0.5 -- canonical windowing & immutable ground truth (src/audit/canonical.py).

Each test pins one experimental invariant the P0 audit found broken in
`src.features.windows.window_features`: the grid moved with the sampled
`ts.min()`, empty windows vanished, `min_flows` dropped windows in proportion
to the treatment, and the label was computed after sampling. The instrument
here freezes the grid and the ground truth from the full trace; sampling may
only reduce what is observed.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from src.audit.canonical import (
    build_canonical_windowing,
    canonical_window_features,
)
from src.features.tiers import InfoTier
from src.restriction import sample, sample_mask
from src.simulator.agents import AttackType, SimulationConfig, run_simulation

WINDOW_SECONDS = 60
TAU = 0.01
MIN_FLOWS = 10
RATES = (1, 10, 100, 1000)


def _trace(seed: int, duration: int = 1200) -> pl.DataFrame:
    """A full DDoS trace in the loader's schema, via the project simulator."""
    return run_simulation(SimulationConfig(
        attack_type=AttackType.DDOS,
        asymmetry_level=0.8,
        duration_seconds=duration,
        seed=seed,
    ))


def _hand_trace() -> pl.DataFrame:
    """A tiny hand-built trace with known per-window structure.

    Window 0 (t in [0,60)):   30 benign flows
    Window 1 (t in [60,120)): 30 flows, 29 of them attack   -> attack window
    Window 2 (t in [120,180)): 12 benign flows
    Anchor is t=0. Timestamps are spread so a "drop the first records" sample
    can remove all of window 0 without touching the grid.
    """
    base = np.datetime64("2024-01-01T00:00:00")
    segs = [(30, 0, 60, 0), (1, 60, 61, 0), (29, 61, 120, 1), (12, 120, 180, 0)]
    offs = np.concatenate([
        np.linspace(t0, t1 - 1, n).astype("int64") for n, t0, t1, _ in segs
    ])
    attack = np.concatenate([np.full(n, a, dtype=np.int64) for n, _, _, a in segs])
    k = np.arange(offs.size)
    # numpy datetime64 array so polars infers a Datetime column (a list of
    # np.datetime64 scalars arrives as Object) -- same trick as _flow_frame in
    # tests/test_features.py. Polars wants us resolution.
    ts = (base + offs.astype("timedelta64[s]")).astype("datetime64[us]")
    return pl.DataFrame({
        "timestamp": ts,
        "src_ip": [f"10.0.0.{i % 5}" for i in k],
        "dst_ip": [f"10.0.1.{i % 3}" for i in k],
        "totlen_fwd_pkts": (100.0 + k).astype(np.float64),
        "totlen_bwd_pkts": (50.0 + k).astype(np.float64),
        "is_attack": attack,
    }).sort("timestamp")


# --------------------------------------------------------------------------- P0.5.1
def test_canonical_boundaries_come_from_the_full_trace_not_the_sample():
    """P0.5.10 #1 -- sampling deletes the first records; boundaries do not move."""
    full = _hand_trace()
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)

    # a sample that removes the entire first window
    late = full.filter(pl.col("timestamp") >= np.datetime64("2024-01-01T00:01:00"))
    assert len(late) < len(full)

    led_full = canonical_window_features(full, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)
    led_late = canonical_window_features(late, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)

    assert led_full["window_start"].to_list() == led_late["window_start"].to_list()
    assert led_full["window_end"].to_list() == led_late["window_end"].to_list()
    assert led_full["window_id"].to_list() == led_late["window_id"].to_list()
    # window 0 is now empty but still present
    w0 = led_late.filter(pl.col("window_id") == 0)
    assert len(w0) == 1
    assert int(w0["n_observed"][0]) == 0


def test_window_start_is_pure_arithmetic_on_the_frozen_anchor():
    full = _hand_trace()
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    for wid, start, end in zip(cw.window_ids, cw.window_start, cw.window_end):
        assert start == cw.global_t0 + wid * WINDOW_SECONDS
        assert end == cw.global_t0 + (wid + 1) * WINDOW_SECONDS


# --------------------------------------------------------------------------- P0.5.4
def test_empty_window_persists_with_zero_observations():
    """P0.5.10 #2."""
    full = _hand_trace()
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    # keep only window 1
    only_w1 = full.filter(
        (pl.col("timestamp") >= np.datetime64("2024-01-01T00:01:00"))
        & (pl.col("timestamp") < np.datetime64("2024-01-01T00:02:00"))
    )
    led = canonical_window_features(only_w1, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)
    assert set(led["window_id"].to_list()) == set(cw.window_ids.tolist())
    empties = led.filter(pl.col("n_observed") == 0)
    assert set(empties["window_id"].to_list()) == {0, 2}
    assert empties["has_evidence"].to_list() == [False, False]
    assert empties["feature_available"].to_list() == [False, False]
    # ground truth still attached to the empty rows
    assert led.filter(pl.col("window_id") == 2)["y_gt"][0] == 0


# --------------------------------------------------------------------------- P0.5.5
def test_window_below_min_flows_stays_in_the_evaluation_set():
    """P0.5.10 #3 -- n_observed < min_flows flags the feature, never drops the row."""
    full = _hand_trace()
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    # window 2 has 12 flows; keep 5 of them -> 0 < n < min_flows
    w2 = full.filter(
        (pl.col("timestamp") >= np.datetime64("2024-01-01T00:02:00"))
    ).head(5)
    led = canonical_window_features(w2, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)
    row = led.filter(pl.col("window_id") == 2)
    assert len(row) == 1
    assert int(row["n_observed"][0]) == 5
    assert bool(row["has_evidence"][0]) is True
    assert bool(row["feature_available"][0]) is False
    assert len(led) == cw.n_windows  # nothing dropped


def test_min_flows_does_not_depend_on_sampling_rate():
    """The same min_flows is applied at every rate; only the flag changes."""
    full = _trace(seed=1)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    counts = []
    for r in RATES:
        led = canonical_window_features(
            sample(full, rate=r, seed=999), cw,
            tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS,
        )
        counts.append(len(led))
    assert counts == [cw.n_windows] * len(RATES)


# --------------------------------------------------------------------------- P0.5.3
def test_ground_truth_is_immutable_under_sampling():
    """P0.5.10 #4 and #5 -- attack_ratio_gt and y_gt never change with the sample."""
    full = _trace(seed=1)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    ref = canonical_window_features(full, cw, tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)
    ref = ref.sort("window_id")
    for r in RATES:
        led = canonical_window_features(
            sample(full, rate=r, seed=4242), cw,
            tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS,
        ).sort("window_id")
        assert led["y_gt"].to_list() == ref["y_gt"].to_list()
        assert led["attack_ratio_gt"].to_list() == ref["attack_ratio_gt"].to_list()


def test_attack_ratio_observed_is_a_separate_field_and_may_differ():
    full = _trace(seed=1)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    led = canonical_window_features(
        sample(full, rate=1000, seed=4242), cw,
        tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS,
    )
    # the diagnostic column exists, is distinct from gt, and is NaN where blind
    assert "attack_ratio_observed" in led.columns
    blind = led.filter(pl.col("n_observed") == 0)
    assert blind["attack_ratio_observed"].is_nan().all()
    # and gt is untouched on those same rows
    assert set(blind["y_gt"].to_list()) <= {0, 1}


# --------------------------------------------------------------------------- P0.5.2 / I7
def test_window_id_set_is_identical_across_sampling_rates():
    """P0.5.10 #6 and #7."""
    full = _trace(seed=11)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    id_sets = []
    for r in RATES:
        led = canonical_window_features(
            sample(full, rate=r, seed=7), cw,
            tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS,
        )
        id_sets.append(tuple(sorted(led["window_id"].to_list())))
    assert all(s == id_sets[0] for s in id_sets)
    assert id_sets[0] == tuple(sorted(cw.window_ids.tolist()))


def test_no_extra_window_appears_when_the_first_records_are_dropped():
    """P0.5.10 #8 -- the 20 attack -> 21 windows drift from P0 cannot recur."""
    full = _trace(seed=11)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    n_attack_gt = int((cw.y_gt == 1).sum())
    for r in RATES:
        led = canonical_window_features(
            sample(full, rate=r, seed=13), cw,
            tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS,
        )
        assert len(led) == cw.n_windows
        assert int((led["y_gt"] == 1).sum()) == n_attack_gt
        assert set(led["window_id"].to_list()) - set(cw.window_ids.tolist()) == set()


def test_window_start_end_identical_between_treatments():
    """P0.5.10 #9."""
    full = _trace(seed=11)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    ref = None
    for r in RATES:
        led = canonical_window_features(
            sample(full, rate=r, seed=1), cw,
            tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS,
        ).sort("window_id")
        block = led.select(["window_id", "window_start", "window_end"])
        if ref is None:
            ref = block
        else:
            assert block.equals(ref)


# --------------------------------------------------------------------------- P0.5.7
def test_simulation_and_sampling_seeds_are_independent():
    """P0.5.10 #10 -- different sampling seeds change the sample, not the trace
    or its ground truth; and the sampling seed is not tied to the sim seed."""
    full = _trace(seed=1)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)

    a = sample(full, rate=100, seed=1000)
    b = sample(full, rate=100, seed=2000)
    assert len(a) != len(b) or not a.equals(b)  # different sampling seed -> different sample

    kw = dict(tier=InfoTier.DIRECTIONAL, min_flows=MIN_FLOWS)
    led_a = canonical_window_features(a, cw, **kw).sort("window_id")
    led_b = canonical_window_features(b, cw, **kw).sort("window_id")
    # ground truth identical regardless of sampling seed
    assert led_a["y_gt"].to_list() == led_b["y_gt"].to_list()
    assert led_a["attack_ratio_gt"].to_list() == led_b["attack_ratio_gt"].to_list()


def test_nested_bernoulli_sampling_is_a_subset_chain():
    """P0.5.10 #11 -- S_1000 subset S_100 subset S_10 subset S_1 for one seed."""
    full = _trace(seed=1)
    n = len(full)
    m1 = sample_mask(n, 1, seed=555)
    m10 = sample_mask(n, 10, seed=555)
    m100 = sample_mask(n, 100, seed=555)
    m1000 = sample_mask(n, 1000, seed=555)
    assert np.all(m1000 <= m100)
    assert np.all(m100 <= m10)
    assert np.all(m10 <= m1)
    assert m1.all()  # rate 1 keeps everything


def test_sample_mask_matches_the_old_inline_sampler():
    """The sample() refactor is behaviour-preserving."""
    rng = np.random.default_rng(7)
    n = 5000
    expected = rng.random(n) < (1.0 / 25)
    got = sample_mask(n, 25, seed=7)
    assert np.array_equal(expected, got)


# --------------------------------------------------------------------------- misc guards
def test_build_rejects_empty_frame():
    with pytest.raises(ValueError):
        build_canonical_windowing(pl.DataFrame({"timestamp": [], "is_attack": []}))


def test_tuples_tier_omits_perflow_columns_but_keeps_the_ledger():
    full = _trace(seed=1)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    led = canonical_window_features(full, cw, tier=InfoTier.TUPLES, min_flows=MIN_FLOWS)
    assert "fl_mean" not in led.columns
    assert {"window_id", "y_gt", "attack_ratio_gt", "n_observed",
            "has_evidence", "feature_available"} <= set(led.columns)
    assert len(led) == cw.n_windows
