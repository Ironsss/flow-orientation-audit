"""Background structural tests for Generator v2 (P2.8-P2.13).

These check that the generative *mechanism* has the intended structure
(intra-community preference, hub reachability, multiple service types,
activity-state variety, and independence from attack state) with small,
fast, seed-controlled draws. They deliberately do NOT assert AC8/AC9's
numeric thresholds (background saturation, reciprocity heterogeneity) --
those are Validation-stage, run-level statistics, not unit-test material.
"""

from __future__ import annotations

import inspect
from dataclasses import replace
from datetime import datetime

import numpy as np

from src.simulator.v2.background import (
    _activity_timeline,
    _select_destination,
    _select_service,
    generate_background,
)
from src.simulator.v2.config import (
    DEFAULT_ACTIVITY,
    DEFAULT_ROLE_SERVICE_WEIGHTS,
    ActivityState,
    Role,
    SeverityRegime,
    SimulationConfigV2,
)
from src.simulator.v2.population import build_host_pool


def _small_pool(seed=0):
    role_counts = {Role.CLIENT: 8, Role.SERVER: 4, Role.INFRA_HUB: 2, Role.HIGH_ACTIVITY: 2}
    return build_host_pool(
        np.random.default_rng(seed), size=16, role_counts=role_counts, n_communities=2
    )


class TestDestinationSelection:
    def test_intra_community_preference_dominates_when_configured_to(self):
        pool = _small_pool()
        source = next(h for h in pool.host_ids if h not in pool.hub_hosts)
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        rng = np.random.default_rng(123)
        same_community = set(pool.community_peers(source))
        other_community = set(pool.other_community_hosts(source))

        draws = [_select_destination(rng, source, pool, cfg.community) for _ in range(500)]
        intra_frac = sum(1 for d in draws if d in same_community) / len(draws)
        inter_frac = sum(1 for d in draws if d in other_community) / len(draws)
        assert intra_frac > inter_frac, (
            f"intra-community fraction ({intra_frac}) should exceed inter-community "
            f"({inter_frac}) given p_intra={cfg.community.p_intra} > "
            f"p_inter={cfg.community.p_inter}"
        )

    def test_hub_is_reachable_as_a_destination_from_every_community(self):
        pool = _small_pool()
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        for community, hosts in pool.hosts_by_community.items():
            source = hosts[0]
            rng = np.random.default_rng(7)
            draws = {_select_destination(rng, source, pool, cfg.community) for _ in range(200)}
            assert draws & set(pool.hub_hosts), (
                f"community {community} never reached a hub in 200 draws"
            )

    def test_destination_is_never_the_source_itself(self):
        pool = _small_pool()
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        rng = np.random.default_rng(3)
        source = next(h for h in pool.host_ids if h not in pool.hub_hosts)
        draws = [_select_destination(rng, source, pool, cfg.community) for _ in range(200)]
        assert source not in draws


class TestServiceSelection:
    def test_multiple_service_types_appear_for_a_role(self):
        rng = np.random.default_rng(11)
        drawn = {
            _select_service(rng, Role.CLIENT, DEFAULT_ROLE_SERVICE_WEIGHTS) for _ in range(200)
        }
        assert len(drawn) > 1


class TestActivityTimeline:
    def test_long_run_visits_multiple_activity_states(self):
        rng = np.random.default_rng(5)
        mean_dwell = {
            ActivityState.IDLE: 50.0, ActivityState.NORMAL: 80.0, ActivityState.BURST: 20.0
        }
        timeline = _activity_timeline(rng, mean_dwell, duration_seconds=2000.0)
        states = {s for _, _, s in timeline}
        assert states == set(ActivityState)

    def test_timeline_covers_the_whole_duration_without_gaps(self):
        rng = np.random.default_rng(5)
        mean_dwell = {
            ActivityState.IDLE: 50.0, ActivityState.NORMAL: 80.0, ActivityState.BURST: 20.0
        }
        timeline = _activity_timeline(rng, mean_dwell, duration_seconds=500.0)
        assert timeline[0][0] == 0.0
        assert timeline[-1][1] == 500.0
        for (_, t1, _), (t0_next, _, _) in zip(timeline, timeline[1:]):
            assert t1 == t0_next


class TestBackgroundIndependentOfAttackState:
    def test_generate_background_signature_has_no_attack_parameter(self):
        """Architectural invariant (design contract SS3/SS10): the background
        generator must have no way to receive attack/label information."""
        params = set(inspect.signature(generate_background).parameters)
        attack_like = {
            p for p in params
            if "attack" in p.lower() or "label" in p.lower() or "y_gt" in p.lower()
        }
        assert not attack_like, (
            f"generate_background must not accept attack-related params: {attack_like}"
        )

    def test_generated_background_flows_are_all_labeled_benign(self):
        pool = _small_pool()
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        flows = generate_background(
            np.random.default_rng(1), np.random.default_rng(2), pool, cfg,
            duration_seconds=300.0, start_time=datetime(2024, 1, 1),
        )
        assert len(flows) > 0
        assert all(f["is_attack"] == 0 for f in flows)
        assert all(f["label"] == "Benign" for f in flows)

    def test_reproducible_given_same_rngs(self):
        pool = _small_pool()
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        a = generate_background(
            np.random.default_rng(9), np.random.default_rng(10), pool, cfg,
            duration_seconds=300.0, start_time=datetime(2024, 1, 1),
        )
        b = generate_background(
            np.random.default_rng(9), np.random.default_rng(10), pool, cfg,
            duration_seconds=300.0, start_time=datetime(2024, 1, 1),
        )
        assert a == b

    def test_all_flow_timestamps_within_duration(self):
        pool = _small_pool()
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        start = datetime(2024, 1, 1)
        flows = generate_background(
            np.random.default_rng(4), np.random.default_rng(6), pool, cfg,
            duration_seconds=300.0, start_time=start,
        )
        offsets = [(f["timestamp"] - start).total_seconds() for f in flows]
        assert min(offsets) >= 0.0
        assert max(offsets) < 300.0


def _starved_config(**overrides):
    """A config whose benign activity rates are ~0 -- so the only benign
    flows produced are the deterministic infrastructure heartbeat."""
    starved = {
        role: replace(profile, base_flows_per_min=(1e-9, 1e-9))
        for role, profile in DEFAULT_ACTIVITY.items()
    }
    kwargs = dict(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM, activity=starved)
    kwargs.update(overrides)
    return SimulationConfigV2(**kwargs)


class TestCanonicalWindowHeartbeat:
    """The deterministic per-window heartbeat is what makes
    `canonical windows/run == duration_seconds / window_seconds` a structural
    guarantee rather than a probabilistic near-certainty (design freeze SS7)."""

    def test_every_window_is_covered_when_activity_rates_are_starved(self):
        pool = _small_pool()
        start = datetime(2024, 1, 1)
        flows = generate_background(
            np.random.default_rng(0), np.random.default_rng(1), pool, _starved_config(),
            duration_seconds=600.0, window_seconds=60.0, start_time=start,
        )
        bins = {int((f["timestamp"] - start).total_seconds() // 60) for f in flows}
        assert set(range(10)) <= bins, f"missing window ids: {set(range(10)) - bins}"
        assert all(f["is_attack"] == 0 for f in flows)
        assert all(f["label"] == "Benign" for f in flows)

    def test_window_coverage_holds_for_every_flow_rng_seed(self):
        pool = _small_pool()
        start = datetime(2024, 1, 1)
        for seed in range(6):
            flows = generate_background(
                np.random.default_rng(seed), np.random.default_rng(seed + 100), pool,
                _starved_config(), duration_seconds=600.0, window_seconds=60.0, start_time=start,
            )
            bins = {int((f["timestamp"] - start).total_seconds() // 60) for f in flows}
            assert set(range(10)) <= bins, f"seed {seed} left window ids empty"

    def test_heartbeat_timestamps_sit_at_window_centres_and_never_at_a_boundary(self):
        pool = _small_pool()
        start = datetime(2024, 1, 1)
        flows = generate_background(
            np.random.default_rng(0), np.random.default_rng(1), pool, _starved_config(),
            duration_seconds=600.0, window_seconds=60.0, start_time=start,
        )
        offsets = sorted((f["timestamp"] - start).total_seconds() for f in flows)
        assert offsets == [30.0 + 60.0 * k for k in range(10)]

    def test_heartbeat_endpoints_are_real_pool_hosts_and_never_self_loops(self):
        pool = _small_pool()
        start = datetime(2024, 1, 1)
        flows = generate_background(
            np.random.default_rng(0), np.random.default_rng(1), pool, _starved_config(),
            duration_seconds=600.0, window_seconds=60.0, start_time=start,
        )
        for f in flows:
            assert f["src_ip"] in pool.host_ids
            assert f["dst_ip"] in pool.host_ids
            assert f["src_ip"] != f["dst_ip"]

    def test_heartbeat_is_a_negligible_fraction_of_a_full_background(self):
        """~60 flows/run against ~1e5 -- it cannot move AC8/AC9/volume stats."""
        pool = build_host_pool(
            np.random.default_rng(0),
            role_counts={Role.CLIENT: 8, Role.SERVER: 4, Role.INFRA_HUB: 2, Role.HIGH_ACTIVITY: 2},
            size=16,
            n_communities=2,
        )
        cfg = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
        start = datetime(2024, 1, 1)
        full = generate_background(
            np.random.default_rng(2), np.random.default_rng(3), pool, cfg,
            duration_seconds=600.0, window_seconds=60.0, start_time=start,
        )
        heartbeat = 10  # duration_seconds // window_seconds
        assert heartbeat / len(full) < 0.05
