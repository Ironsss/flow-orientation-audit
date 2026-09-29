"""Attack-timing tests for Generator v2 (P2.3/P2.4/P2.14/P2.15).

`sample_attack_timing` and `generate_attack` are exercised directly with
small, explicit durations/pools -- fast, and independent of the frozen
3600s/80-host constants, which `run_simulation_v2` alone is responsible for
using unmodified (covered in test_simulator_v2_run.py).
"""

from __future__ import annotations

from datetime import datetime

import numpy as np
import pytest

from src.simulator.v2.attack import generate_attack, sample_attack_timing
from src.simulator.v2.config import SeverityProfile, SeverityRegime
from src.simulator.v2.population import build_host_pool

DURATION = 600.0
WINDOW = 60.0
CONTEXT = 2  # windows

_SEVERITY = SeverityProfile(
    attacker_count_range=(2, 4),
    peak_rate_per_attacker_range=(5.0, 10.0),
    ramp_seconds_range=(30.0, 90.0),
    response_probability_range=(0.1, 0.3),
)


def _pool(seed=0):
    return build_host_pool(
        np.random.default_rng(seed), size=20, role_counts=_role_counts(), n_communities=2
    )


def _role_counts():
    from src.simulator.v2.config import Role

    return {Role.CLIENT: 12, Role.SERVER: 4, Role.INFRA_HUB: 2, Role.HIGH_ACTIVITY: 2}


def _timing(seed=0, **kw):
    pool = _pool(seed)
    rngs = [np.random.default_rng(seed * 10 + i) for i in range(3)]
    defaults = dict(
        onset_fraction_range=(0.2, 0.6),
        attack_duration_range=(60.0, 200.0),
        duration_seconds=DURATION,
        window_seconds=WINDOW,
        context_pre=CONTEXT,
        context_post=CONTEXT,
    )
    defaults.update(kw)
    return pool, sample_attack_timing(
        *rngs, pool, SeverityRegime.MEDIUM, _SEVERITY, **defaults
    )


class TestTimingFeasibility:
    def test_onset_within_configured_and_context_bounds(self):
        pool, timing = _timing()
        assert CONTEXT * WINDOW <= timing.attack_start
        assert timing.attack_start + timing.attack_duration <= DURATION - CONTEXT * WINDOW

    def test_attack_duration_within_configured_range(self):
        _, timing = _timing()
        assert 60.0 <= timing.attack_duration <= 200.0

    def test_ramp_never_exceeds_attack_duration(self):
        _, timing = _timing()
        assert timing.ramp_seconds <= timing.attack_duration

    def test_attackers_and_victim_are_distinct_and_from_the_pool(self):
        pool, timing = _timing()
        assert len(set(timing.attacker_ids)) == len(timing.attacker_ids)
        assert timing.victim_id not in timing.attacker_ids
        assert set(timing.attacker_ids) <= set(pool.host_ids)
        assert timing.victim_id in pool.host_ids

    def test_reproducible_given_same_seeds(self):
        _, a = _timing(seed=3)
        _, b = _timing(seed=3)
        assert a == b

    def test_raises_on_infeasible_onset_range(self):
        with pytest.raises(ValueError, match="feasible attack onset"):
            _timing(onset_fraction_range=(0.98, 0.99))

    def test_raises_when_attacker_count_exceeds_pool(self):
        huge = SeverityProfile(
            attacker_count_range=(100, 100),
            peak_rate_per_attacker_range=(1.0, 2.0),
            ramp_seconds_range=(0.0, 0.0),
            response_probability_range=(0.0, 0.1),
        )
        pool = _pool()
        rngs = [np.random.default_rng(i) for i in range(3)]
        with pytest.raises(ValueError, match="host pool size"):
            sample_attack_timing(
                *rngs, pool, SeverityRegime.HIGH, huge,
                onset_fraction_range=(0.2, 0.6), attack_duration_range=(60.0, 100.0),
                duration_seconds=DURATION, window_seconds=WINDOW,
                context_pre=CONTEXT, context_post=CONTEXT,
            )


class TestRamp:
    def test_zero_ramp_activates_every_attacker_at_onset(self):
        pool = _pool()
        # force ramp to exactly 0 by using a severity profile with ramp=(0,0)
        zero_ramp = SeverityProfile(
            attacker_count_range=(3, 3),
            peak_rate_per_attacker_range=(5.0, 5.0),
            ramp_seconds_range=(0.0, 0.0),
            response_probability_range=(0.0, 0.0),
        )
        rngs = [np.random.default_rng(i) for i in range(3)]
        timing = sample_attack_timing(
            *rngs, pool, SeverityRegime.MEDIUM, zero_ramp,
            onset_fraction_range=(0.2, 0.6), attack_duration_range=(60.0, 100.0),
            duration_seconds=DURATION, window_seconds=WINDOW,
            context_pre=CONTEXT, context_post=CONTEXT,
        )
        assert timing.ramp_seconds == 0.0
        n = len(timing.attacker_ids)
        activations = [timing.attack_start + i * timing.ramp_seconds / n for i in range(n)]
        assert all(a == timing.attack_start for a in activations)

    def test_positive_ramp_staggers_attacker_activation(self):
        strong_ramp = SeverityProfile(
            attacker_count_range=(4, 4),
            peak_rate_per_attacker_range=(5.0, 5.0),
            ramp_seconds_range=(80.0, 80.0),
            response_probability_range=(0.0, 0.0),
        )
        pool = _pool()
        rngs = [np.random.default_rng(i) for i in range(3)]
        timing = sample_attack_timing(
            *rngs, pool, SeverityRegime.MEDIUM, strong_ramp,
            onset_fraction_range=(0.2, 0.4), attack_duration_range=(150.0, 150.0),
            duration_seconds=DURATION, window_seconds=WINDOW,
            context_pre=CONTEXT, context_post=CONTEXT,
        )
        n = len(timing.attacker_ids)
        activations = [timing.attack_start + i * timing.ramp_seconds / n for i in range(n)]
        assert activations == sorted(activations)
        assert activations[0] < activations[-1]

    def test_generate_attack_flows_fall_within_active_window_per_attacker(self):
        pool = _pool()
        rngs = [np.random.default_rng(i) for i in range(3)]
        severity = SeverityProfile(
            attacker_count_range=(3, 3),
            peak_rate_per_attacker_range=(20.0, 20.0),
            ramp_seconds_range=(60.0, 60.0),
            response_probability_range=(0.0, 0.0),
        )
        timing = sample_attack_timing(
            *rngs, pool, SeverityRegime.MEDIUM, severity,
            onset_fraction_range=(0.2, 0.3), attack_duration_range=(120.0, 120.0),
            duration_seconds=DURATION, window_seconds=WINDOW,
            context_pre=CONTEXT, context_post=CONTEXT,
        )
        flows = generate_attack(np.random.default_rng(99), timing, start_time=datetime(2024, 1, 1))
        assert len(flows) > 0
        attack_end = timing.attack_start + timing.attack_duration
        offsets = [(f["timestamp"] - datetime(2024, 1, 1)).total_seconds() for f in flows]
        assert min(offsets) >= timing.attack_start - 1e-6
        assert max(offsets) <= attack_end + 1e-6
        assert all(f["is_attack"] == 1 for f in flows)
