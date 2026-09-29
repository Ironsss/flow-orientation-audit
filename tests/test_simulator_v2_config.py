"""Config-level tests for Generator v2 (frozen constants, severity/stratum
hierarchy, and the fail-fast validations in SimulationConfigV2.__post_init__).

None of these run a simulation -- they are pure config-construction checks,
fast by design.
"""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from src.simulator.v2 import (
    DEFAULT_ACTIVITY,
    DEFAULT_SERVICES,
    DEFAULT_SEVERITY,
    HOST_POOL_SIZE,
    ROLE_COUNTS,
    SEVERITY_TO_STRATUM,
    Role,
    SeverityRegime,
    SimulationConfigV2,
    Stratum,
    stratum_of,
)


def _valid_config(**overrides) -> SimulationConfigV2:
    kwargs = dict(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
    kwargs.update(overrides)
    return SimulationConfigV2(**kwargs)


class TestFrozenConstants:
    def test_role_counts_sum_to_host_pool_size(self):
        assert sum(ROLE_COUNTS.values()) == HOST_POOL_SIZE == 80

    def test_role_counts_exact(self):
        assert ROLE_COUNTS == {
            Role.CLIENT: 32,
            Role.SERVER: 12,
            Role.INFRA_HUB: 4,
            Role.HIGH_ACTIVITY: 12,
            Role.LOW_ACTIVITY: 12,
            Role.PERIODIC_M2M: 8,
        }


class TestStrataHierarchy:
    def test_mapping_is_exactly_the_frozen_one(self):
        assert SEVERITY_TO_STRATUM == {
            SeverityRegime.LOW_SIGNAL: Stratum.LOW_SIGNAL,
            SeverityRegime.LOW: Stratum.MAIN,
            SeverityRegime.MEDIUM: Stratum.MAIN,
            SeverityRegime.HIGH: Stratum.MAIN,
        }

    def test_main_is_the_union_of_low_medium_high_never_medium_high_only(self):
        main_regimes = {r for r in SeverityRegime if stratum_of(r) is Stratum.MAIN}
        assert main_regimes == {SeverityRegime.LOW, SeverityRegime.MEDIUM, SeverityRegime.HIGH}

    def test_low_signal_is_its_own_stratum(self):
        assert stratum_of(SeverityRegime.LOW_SIGNAL) is Stratum.LOW_SIGNAL
        assert stratum_of(SeverityRegime.LOW_SIGNAL) is not Stratum.MAIN


class TestDefaultSeverityContract:
    """AC11b(iii), verified as a static property of the frozen defaults --
    no simulation needed."""

    def test_low_signal_attacker_count_strictly_below_every_main_regime(self):
        main = [SeverityRegime.LOW, SeverityRegime.MEDIUM, SeverityRegime.HIGH]
        main_min = min(DEFAULT_SEVERITY[r].attacker_count_range[0] for r in main)
        assert DEFAULT_SEVERITY[SeverityRegime.LOW_SIGNAL].attacker_count_range[1] < main_min

    def test_low_signal_peak_rate_strictly_below_every_main_regime(self):
        main = [SeverityRegime.LOW, SeverityRegime.MEDIUM, SeverityRegime.HIGH]
        main_min = min(DEFAULT_SEVERITY[r].peak_rate_per_attacker_range[0] for r in main)
        low_signal_max = DEFAULT_SEVERITY[SeverityRegime.LOW_SIGNAL].peak_rate_per_attacker_range[1]
        assert low_signal_max < main_min

    def test_at_least_one_regime_allows_nonzero_ramp(self):
        assert any(sp.ramp_seconds_range[1] > 0 for sp in DEFAULT_SEVERITY.values())

    def test_at_least_two_services_below_half_reciprocity(self):
        below = [s for s, p in DEFAULT_SERVICES.items() if p.response_probability < 0.5]
        assert len(below) >= 2


class TestConfigValidation:
    def test_valid_config_constructs(self):
        _valid_config()

    def test_rejects_low_signal_not_below_main(self):
        bad_severity = dict(DEFAULT_SEVERITY)
        bad_severity[SeverityRegime.LOW_SIGNAL] = replace(
            DEFAULT_SEVERITY[SeverityRegime.LOW_SIGNAL], attacker_count_range=(50, 60)
        )
        with pytest.raises(ValueError, match="strictly below"):
            _valid_config(severity=bad_severity)

    def test_rejects_fewer_than_two_low_reciprocity_services(self):
        bad_services = {
            svc: replace(profile, response_probability=0.99)
            for svc, profile in DEFAULT_SERVICES.items()
        }
        with pytest.raises(ValueError, match="reciprocity"):
            _valid_config(services=bad_services)

    def test_rejects_p_inter_greater_than_p_intra(self):
        from src.simulator.v2 import CommunityConfig

        with pytest.raises(ValueError, match="p_inter"):
            _valid_config(community=CommunityConfig(p_intra=0.1, p_inter=0.5))

    def test_rejects_invalid_onset_fraction_range(self):
        with pytest.raises(ValueError):
            _valid_config(onset_fraction_range=(0.8, 0.2))

    def test_rejects_negative_attack_duration_range(self):
        with pytest.raises(ValueError):
            _valid_config(attack_duration_range=(-10.0, 100.0))

    def test_rejects_missing_service_profile(self):
        incomplete = dict(DEFAULT_SERVICES)
        del incomplete[next(iter(incomplete))]
        with pytest.raises(ValueError, match="missing ServiceProfile"):
            _valid_config(services=incomplete)

    def test_rejects_missing_activity_profile(self):
        incomplete = dict(DEFAULT_ACTIVITY)
        del incomplete[next(iter(incomplete))]
        with pytest.raises(ValueError, match="missing ActivityProfile"):
            _valid_config(activity=incomplete)

    def test_rejects_missing_severity_profile(self):
        incomplete = dict(DEFAULT_SEVERITY)
        del incomplete[SeverityRegime.HIGH]
        with pytest.raises(ValueError, match="missing SeverityProfile"):
            _valid_config(severity=incomplete, severity_regime=SeverityRegime.LOW)

    def test_rejects_all_regimes_zero_ramp(self):
        no_ramp = {
            regime: replace(profile, ramp_seconds_range=(0.0, 0.0))
            for regime, profile in DEFAULT_SEVERITY.items()
        }
        with pytest.raises(ValueError, match="ramp"):
            _valid_config(severity=no_ramp)

    def test_rejects_invalid_response_probability_range(self):
        bad_severity = dict(DEFAULT_SEVERITY)
        bad_severity[SeverityRegime.MEDIUM] = replace(
            DEFAULT_SEVERITY[SeverityRegime.MEDIUM], response_probability_range=(0.2, 1.5)
        )
        with pytest.raises(ValueError, match="response_probability_range"):
            _valid_config(severity=bad_severity)

    def test_rejects_infeasible_onset_given_frozen_duration_and_context(self):
        # onset forced into [0.99, 1.0] of a 3600s run leaves no room for the
        # mandatory 5-window (300s) post-attack context.
        with pytest.raises(ValueError, match="feasible onset window"):
            _valid_config(onset_fraction_range=(0.99, 0.999))

    def test_default_config_is_left_untouched_by_validation(self):
        """Constructing an invalid config must not mutate the shared DEFAULT_*
        module-level dicts other tests rely on."""
        before = copy.deepcopy(DEFAULT_SEVERITY)
        bad_severity = dict(DEFAULT_SEVERITY)
        bad_severity[SeverityRegime.LOW_SIGNAL] = replace(
            DEFAULT_SEVERITY[SeverityRegime.LOW_SIGNAL], attacker_count_range=(50, 60)
        )
        with pytest.raises(ValueError):
            _valid_config(severity=bad_severity)
        assert DEFAULT_SEVERITY == before
