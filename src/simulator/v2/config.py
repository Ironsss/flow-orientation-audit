"""Frozen configuration surface for Generator v2.

Every value the design contract marks FROZEN
(docs/methodology/P2_GENERATOR_V2_DESIGN_FREEZE.md) is a module-level
constant here, not a config field: there is no argument on
`SimulationConfigV2` that can change `host_pool.size`, the role counts,
`communities`, `duration_seconds`, or `window_seconds`. Only parameters the
contract marks "Tunable in Development" (SS13 of the contract) are exposed as
config fields, and every one of them is validated fail-fast in
`SimulationConfigV2.__post_init__` rather than allowed to produce a silently
degenerate trace.

Tunable defaults below are a *starting configuration*, explicitly not a
validated one -- Development may adjust them to satisfy the frozen
structural contract (AC1-AC12), never to move a detector AUC.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

__all__ = [
    "ActivityProfile",
    "ActivityState",
    "CommunityConfig",
    "CONTEXT_MIN_WINDOWS_POST",
    "CONTEXT_MIN_WINDOWS_PRE",
    "DEFAULT_ACTIVITY",
    "DEFAULT_ROLE_SERVICE_WEIGHTS",
    "DEFAULT_SERVICES",
    "DEFAULT_SEVERITY",
    "DURATION_SECONDS",
    "HOST_POOL_SIZE",
    "N_COMMUNITIES",
    "ROLE_COUNTS",
    "Role",
    "SEVERITY_TO_STRATUM",
    "ServiceProfile",
    "ServiceType",
    "SeverityProfile",
    "SeverityRegime",
    "SimulationConfigV2",
    "Stratum",
    "WINDOW_SECONDS",
    "stratum_of",
]


# --------------------------------------------------------------- frozen constants
HOST_POOL_SIZE = 80
N_COMMUNITIES = 4
DURATION_SECONDS = 3600
WINDOW_SECONDS = 60
CONTEXT_MIN_WINDOWS_PRE = 5
CONTEXT_MIN_WINDOWS_POST = 5


class Role(Enum):
    CLIENT = "client"
    SERVER = "server"
    INFRA_HUB = "infra_shared_hub"
    HIGH_ACTIVITY = "high_activity"
    LOW_ACTIVITY = "low_activity"
    PERIODIC_M2M = "periodic_m2m"


#: Frozen role counts. Sum must equal HOST_POOL_SIZE -- asserted once below,
#: not per-config, since this dict is not user-settable.
ROLE_COUNTS: Mapping[Role, int] = {
    Role.CLIENT: 32,
    Role.SERVER: 12,
    Role.INFRA_HUB: 4,
    Role.HIGH_ACTIVITY: 12,
    Role.LOW_ACTIVITY: 12,
    Role.PERIODIC_M2M: 8,
}
assert sum(ROLE_COUNTS.values()) == HOST_POOL_SIZE, (
    f"ROLE_COUNTS sums to {sum(ROLE_COUNTS.values())}, contract freezes "
    f"host_pool.size={HOST_POOL_SIZE}"
)


class ServiceType(Enum):
    WEB_INTERACTIVE = "web_interactive"
    DNS_LIKE = "dns_like"
    SSH_ADMIN_LIKE = "ssh_admin_like"
    BULK_TRANSFER = "bulk_transfer"
    PERIODIC_SERVICE = "periodic_service"
    BACKGROUND_M2M = "background_m2m"


class ActivityState(Enum):
    IDLE = "idle"
    NORMAL = "normal"
    BURST = "burst"


class SeverityRegime(Enum):
    LOW_SIGNAL = "low_signal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Stratum(Enum):
    MAIN = "Main"
    LOW_SIGNAL = "Low-signal"


#: The only valid mapping (contract SS6). `Main = {low, medium, high}`,
#: `Low-signal = {low_signal}` -- never `Main = {medium, high}`.
SEVERITY_TO_STRATUM: Mapping[SeverityRegime, Stratum] = {
    SeverityRegime.LOW_SIGNAL: Stratum.LOW_SIGNAL,
    SeverityRegime.LOW: Stratum.MAIN,
    SeverityRegime.MEDIUM: Stratum.MAIN,
    SeverityRegime.HIGH: Stratum.MAIN,
}


def stratum_of(regime: SeverityRegime) -> Stratum:
    """The frozen severity_regime -> stratum mapping, as a function."""
    return SEVERITY_TO_STRATUM[regime]


# --------------------------------------------------------------- tunable profiles
@dataclass(frozen=True)
class ServiceProfile:
    """Generative parameters for one benign activity/service type.

    `response_probability` is the reciprocity knob (P2.12/P2.13): the
    probability that a forward flow gets a reverse-direction flow emitted.
    The contract requires >=2 service types configured below 0.5 -- checked
    in `SimulationConfigV2.__post_init__`, not assumed.
    """

    preferred_dst_roles: tuple[Role, ...]
    response_probability: float
    bytes_range: tuple[float, float]
    packets_range: tuple[int, int]
    duration_range: tuple[float, float]  # microseconds, matching v1's flow_duration units


DEFAULT_SERVICES: Mapping[ServiceType, ServiceProfile] = {
    ServiceType.WEB_INTERACTIVE: ServiceProfile(
        preferred_dst_roles=(Role.SERVER, Role.CLIENT),
        response_probability=0.98,
        bytes_range=(200.0, 8000.0),
        packets_range=(2, 30),
        duration_range=(5_000.0, 800_000.0),
    ),
    ServiceType.DNS_LIKE: ServiceProfile(
        preferred_dst_roles=(Role.INFRA_HUB,),
        response_probability=0.95,
        bytes_range=(60.0, 300.0),
        packets_range=(1, 3),
        duration_range=(500.0, 5_000.0),
    ),
    ServiceType.SSH_ADMIN_LIKE: ServiceProfile(
        preferred_dst_roles=(Role.SERVER, Role.INFRA_HUB),
        response_probability=0.92,
        bytes_range=(100.0, 2_000.0),
        packets_range=(3, 20),
        duration_range=(50_000.0, 3_000_000.0),
    ),
    ServiceType.BULK_TRANSFER: ServiceProfile(
        preferred_dst_roles=(Role.SERVER, Role.CLIENT),
        response_probability=0.05,
        bytes_range=(5_000.0, 200_000.0),
        packets_range=(20, 500),
        duration_range=(200_000.0, 4_000_000.0),
    ),
    ServiceType.PERIODIC_SERVICE: ServiceProfile(
        preferred_dst_roles=(Role.INFRA_HUB,),
        response_probability=0.02,
        bytes_range=(50.0, 400.0),
        packets_range=(1, 4),
        duration_range=(1_000.0, 10_000.0),
    ),
    ServiceType.BACKGROUND_M2M: ServiceProfile(
        preferred_dst_roles=(Role.SERVER, Role.INFRA_HUB, Role.CLIENT),
        response_probability=0.15,
        bytes_range=(80.0, 1_000.0),
        packets_range=(1, 8),
        duration_range=(500.0, 50_000.0),
    ),
}

#: Which services a source of a given role tends to generate, as relative
#: weights (not required to sum to 1 -- normalized at draw time).
DEFAULT_ROLE_SERVICE_WEIGHTS: Mapping[Role, Mapping[ServiceType, float]] = {
    Role.CLIENT: {
        ServiceType.WEB_INTERACTIVE: 0.55,
        ServiceType.SSH_ADMIN_LIKE: 0.15,
        ServiceType.DNS_LIKE: 0.20,
        ServiceType.BACKGROUND_M2M: 0.10,
    },
    Role.SERVER: {
        ServiceType.WEB_INTERACTIVE: 0.40,
        ServiceType.BULK_TRANSFER: 0.30,
        ServiceType.BACKGROUND_M2M: 0.30,
    },
    Role.INFRA_HUB: {
        ServiceType.DNS_LIKE: 0.40,
        ServiceType.PERIODIC_SERVICE: 0.40,
        ServiceType.BACKGROUND_M2M: 0.20,
    },
    Role.HIGH_ACTIVITY: {
        ServiceType.BULK_TRANSFER: 0.45,
        ServiceType.WEB_INTERACTIVE: 0.35,
        ServiceType.BACKGROUND_M2M: 0.20,
    },
    Role.LOW_ACTIVITY: {
        ServiceType.WEB_INTERACTIVE: 0.50,
        ServiceType.SSH_ADMIN_LIKE: 0.30,
        ServiceType.DNS_LIKE: 0.20,
    },
    Role.PERIODIC_M2M: {
        ServiceType.PERIODIC_SERVICE: 0.70,
        ServiceType.BACKGROUND_M2M: 0.30,
    },
}


@dataclass(frozen=True)
class ActivityProfile:
    """Per-role temporal activity model (P2.10).

    A host's rate over the run is a semi-Markov process over
    {idle, normal, burst}: dwell time in each state is exponential with the
    given mean, and the instantaneous rate is `base_flows_per_min * multiplier
    [state]`. `base_flows_per_min` is a per-host range -- each host draws its
    own base rate once, per run, from it.
    """

    base_flows_per_min: tuple[float, float]
    state_multiplier: Mapping[ActivityState, float]
    mean_dwell_seconds: Mapping[ActivityState, float]


#: P2 Development finding (2026-09-19, `results/metrics/p2_generator_v2_development.json`):
#: the original (8-60 flows/min, idle multiplier 0.3) rates produced ~1.3e5
#: background flows/run, which drove AC8 (pair_coverage_run median 0.838,
#: target <0.50) and AC9 (std_recip_run median 0.011, target >0.05) to fail
#: clearly -- at that volume, per-window service-mix composition converges to
#: the same average every window (law of large numbers) and enough rare-pair
#: draws accumulate over an hour that nearly every possible host pair gets
#: touched at least once. Cutting the rate 20x and dropping IDLE's multiplier
#: (0.3 -> 0.08, so idle windows are close to silent) reintroduces per-window
#: sampling noise in both quantities without threatening the P0.5 heartbeat
#: contract (`tests/test_simulator_v2_background.py::test_heartbeat_is_a_negligible_fraction...`,
#: verified to stay under half its 5% budget across seeds at this rate).
_DEFAULT_STATE_MULTIPLIER = {
    ActivityState.IDLE: 0.08,
    ActivityState.NORMAL: 1.0,
    ActivityState.BURST: 3.0,
}
_DEFAULT_DWELL = {
    ActivityState.IDLE: 300.0,
    ActivityState.NORMAL: 600.0,
    ActivityState.BURST: 120.0,
}

DEFAULT_ACTIVITY: Mapping[Role, ActivityProfile] = {
    Role.CLIENT: ActivityProfile((0.40, 1.00), _DEFAULT_STATE_MULTIPLIER, _DEFAULT_DWELL),
    Role.SERVER: ActivityProfile((0.50, 1.25), _DEFAULT_STATE_MULTIPLIER, _DEFAULT_DWELL),
    Role.INFRA_HUB: ActivityProfile((0.75, 2.00), _DEFAULT_STATE_MULTIPLIER, _DEFAULT_DWELL),
    Role.HIGH_ACTIVITY: ActivityProfile((1.25, 3.00), _DEFAULT_STATE_MULTIPLIER, _DEFAULT_DWELL),
    Role.LOW_ACTIVITY: ActivityProfile((0.05, 0.20), _DEFAULT_STATE_MULTIPLIER, _DEFAULT_DWELL),
    Role.PERIODIC_M2M: ActivityProfile((0.10, 0.30), _DEFAULT_STATE_MULTIPLIER, _DEFAULT_DWELL),
}


@dataclass(frozen=True)
class SeverityProfile:
    """Generative intensity ranges for one severity_regime (P2.14/P2.16)."""

    attacker_count_range: tuple[int, int]
    peak_rate_per_attacker_range: tuple[float, float]  # requests/second
    ramp_seconds_range: tuple[float, float]
    response_probability_range: tuple[float, float]


#: P2 Development finding (2026-09-19): cutting background volume 20x to fix
#: AC8/AC9 (see DEFAULT_ACTIVITY above) left LOW/LOW_SIGNAL's unchanged attack
#: rates completely dominating the now-much-smaller background, so a single
#: threshold on raw `n_flows` separated benign from attack almost perfectly
#: (AC2b: 100% of eligible runs at sep_run>=0.95, target <=20%) and AC7's
#: near-tau windows nearly vanished (an attack burst this large relative to
#: background jumps `attack_ratio_gt` straight past the near-tau band). Only
#: `peak_rate_per_attacker_range` is scaled here (not `attacker_count_range`,
#: which is frozen count-shaped semantics, not a rate); LOW is scaled more
#: than LOW_SIGNAL only insofar as needed to keep satisfying the contract's
#: `low_signal < every Main regime's minimum` ordering (SS10/__post_init__).
DEFAULT_SEVERITY: Mapping[SeverityRegime, SeverityProfile] = {
    SeverityRegime.LOW_SIGNAL: SeverityProfile(
        attacker_count_range=(1, 1),
        peak_rate_per_attacker_range=(0.025, 0.05),
        ramp_seconds_range=(300.0, 900.0),
        response_probability_range=(0.10, 0.30),
    ),
    SeverityRegime.LOW: SeverityProfile(
        attacker_count_range=(2, 3),
        peak_rate_per_attacker_range=(0.0833, 0.25),
        ramp_seconds_range=(0.0, 900.0),
        response_probability_range=(0.0, 0.30),
    ),
    SeverityRegime.MEDIUM: SeverityProfile(
        attacker_count_range=(3, 6),
        peak_rate_per_attacker_range=(20.0, 50.0),
        ramp_seconds_range=(0.0, 600.0),
        response_probability_range=(0.0, 0.25),
    ),
    SeverityRegime.HIGH: SeverityProfile(
        attacker_count_range=(8, 15),
        peak_rate_per_attacker_range=(30.0, 80.0),
        ramp_seconds_range=(0.0, 300.0),
        response_probability_range=(0.0, 0.20),
    ),
}


@dataclass(frozen=True)
class CommunityConfig:
    """Stochastic-block-model-like destination weighting (P2.8/P2.9).

    Not a full pairwise probability matrix: a flow's destination is drawn
    from one of three buckets -- same community, other community, or a hub
    (cross-community by construction) -- weighted by `p_intra`, `p_inter` and
    `hub_preference` respectively (normalized at draw time).
    """

    p_intra: float = 0.30
    #: P2 Development finding (2026-09-19): at the original 0.03, hub hosts'
    #: inter-community bucket (their only non-hub route, since a hub has no
    #: community) fanned out over all 76 non-hub hosts at high volume, and
    #: regular hosts' own inter bucket did the same at smaller scale -- between
    #: them this was the dominant driver of AC8's pair_coverage_run failure
    #: (median 0.838, target <0.50). Set to 0 (still satisfies the contract's
    #: `0 <= p_inter < p_intra`): background traffic stays within a host's own
    #: community plus the shared hubs, never crossing to another community.
    p_inter: float = 0.0
    hub_preference: float = 0.05


# ------------------------------------------------------------------ top config
@dataclass
class SimulationConfigV2:
    """Generator v2 configuration.

    The only exposed seed is `simulation_seed`; every internal random stream
    (population, background timing, background flows, attacker selection,
    attack timing, attack intensity) is derived from it deterministically via
    `numpy.random.SeedSequence(simulation_seed).spawn(...)` in
    `src.simulator.v2.run`. There is no field for `host_pool.size`,
    `duration_seconds`, `window_seconds`, role counts, or `communities` --
    those are frozen module constants above, not configurable here.
    """

    simulation_seed: int
    severity_regime: SeverityRegime
    onset_fraction_range: tuple[float, float] = (0.15, 0.70)
    #: P2 Validation finding (2026-09-19, first Validation attempt, seeds
    #: 30001-30045, burned per SS14): AC4 requires Acc_time_validation<=0.75,
    #: but at the original (300.0, ...) lower bound only ~24% of windows were
    #: attack, so majority-class accuracy alone (0.7533) already exceeded the
    #: 0.75 target -- AC4 was structurally close to unpassable regardless of
    #: any real temporal shortcut. Raising the floor to 600s lifts the
    #: attack-window share to ~28% (majority_acc~0.72, checked against the 20
    #: Development seeds before spending new Validation seeds on it) while
    #: leaving AC2b/AC7 unchanged (onset span is unaffected: onset_hi was
    #: already bounded by onset_fraction_range's 0.70 fraction, not by this
    #: floor, both before and after).
    attack_duration_range: tuple[float, float] = (600.0, 1800.0)
    community: CommunityConfig = field(default_factory=CommunityConfig)
    services: Mapping[ServiceType, ServiceProfile] = field(
        default_factory=lambda: dict(DEFAULT_SERVICES)
    )
    role_service_weights: Mapping[Role, Mapping[ServiceType, float]] = field(
        default_factory=lambda: dict(DEFAULT_ROLE_SERVICE_WEIGHTS)
    )
    activity: Mapping[Role, ActivityProfile] = field(
        default_factory=lambda: dict(DEFAULT_ACTIVITY)
    )
    severity: Mapping[SeverityRegime, SeverityProfile] = field(
        default_factory=lambda: dict(DEFAULT_SEVERITY)
    )

    def __post_init__(self) -> None:
        _validate_fraction_range(
            "onset_fraction_range", self.onset_fraction_range, lo_bound=0.0, hi_bound=1.0
        )
        _validate_positive_range("attack_duration_range", self.attack_duration_range)

        if not (0.0 <= self.community.p_inter < self.community.p_intra <= 1.0):
            raise ValueError(
                "community config must satisfy 0 <= p_inter < p_intra <= 1, got "
                f"p_intra={self.community.p_intra}, p_inter={self.community.p_inter}"
            )
        if not (0.0 <= self.community.hub_preference < 1.0):
            raise ValueError(
                f"community.hub_preference must be in [0,1), got {self.community.hub_preference}"
            )

        missing_services = set(ServiceType) - set(self.services)
        if missing_services:
            raise ValueError(
                f"missing ServiceProfile for: {sorted(s.value for s in missing_services)}"
            )
        for svc, profile in self.services.items():
            if not (0.0 <= profile.response_probability <= 1.0):
                raise ValueError(f"service {svc.value}: response_probability out of [0,1]")
            _validate_positive_range(f"service {svc.value}.bytes_range", profile.bytes_range)
            _validate_positive_range(f"service {svc.value}.packets_range", profile.packets_range)
            _validate_positive_range(f"service {svc.value}.duration_range", profile.duration_range)
        low_reciprocity = [s for s, p in self.services.items() if p.response_probability < 0.5]
        if len(low_reciprocity) < 2:
            raise ValueError(
                "contract requires >=2 service types configured with reciprocity < 0.5, "
                f"found {len(low_reciprocity)}: {[s.value for s in low_reciprocity]}"
            )

        missing_roles = set(Role) - set(self.activity)
        if missing_roles:
            raise ValueError(
                f"missing ActivityProfile for: {sorted(r.value for r in missing_roles)}"
            )
        for role, profile in self.activity.items():
            _validate_positive_range(
                f"activity[{role.value}].base_flows_per_min", profile.base_flows_per_min
            )
            for state in ActivityState:
                if state not in profile.state_multiplier or profile.state_multiplier[state] < 0:
                    raise ValueError(
                        f"activity[{role.value}] missing/negative multiplier for {state.value}"
                    )
                dwell = profile.mean_dwell_seconds
                if state not in dwell or dwell[state] <= 0:
                    raise ValueError(
                        f"activity[{role.value}] missing/non-positive dwell for {state.value}"
                    )

        missing_regimes = set(SeverityRegime) - set(self.severity)
        if missing_regimes:
            raise ValueError(
                f"missing SeverityProfile for: {sorted(r.value for r in missing_regimes)}"
            )
        for regime, sp in self.severity.items():
            _validate_positive_range(
                f"severity[{regime.value}].attacker_count_range", sp.attacker_count_range
            )
            _validate_positive_range(
                f"severity[{regime.value}].peak_rate_per_attacker_range",
                sp.peak_rate_per_attacker_range,
            )
            if sp.ramp_seconds_range[0] < 0 or sp.ramp_seconds_range[1] < sp.ramp_seconds_range[0]:
                raise ValueError(
                    f"severity[{regime.value}].ramp_seconds_range invalid: {sp.ramp_seconds_range}"
                )
            rp_lo, rp_hi = sp.response_probability_range
            if not (0.0 <= rp_lo <= rp_hi <= 1.0):
                raise ValueError(
                    f"severity[{regime.value}].response_probability_range out of [0,1]: "
                    f"{sp.response_probability_range}"
                )
        if self.severity_regime not in self.severity:
            raise ValueError(f"unknown severity_regime {self.severity_regime!r}")

        main_regimes = [r for r in SeverityRegime if stratum_of(r) is Stratum.MAIN]
        main_min_attackers = min(self.severity[r].attacker_count_range[0] for r in main_regimes)
        main_min_rate = min(self.severity[r].peak_rate_per_attacker_range[0] for r in main_regimes)
        low_signal = self.severity[SeverityRegime.LOW_SIGNAL]
        if not (low_signal.attacker_count_range[1] < main_min_attackers):
            raise ValueError(
                "low_signal.attacker_count_range must be strictly below every Main regime's "
                f"minimum ({main_min_attackers}); got {low_signal.attacker_count_range}"
            )
        if not (low_signal.peak_rate_per_attacker_range[1] < main_min_rate):
            raise ValueError(
                "low_signal.peak_rate_per_attacker_range must be strictly below every Main "
                f"regime's minimum ({main_min_rate}); got {low_signal.peak_rate_per_attacker_range}"
            )

        if all(sp.ramp_seconds_range[1] == 0.0 for sp in self.severity.values()):
            raise ValueError(
                "every severity_regime has ramp_seconds_range=(0,0) -- AC6 (gradual transitions) "
                "would be structurally impossible to satisfy; at least one regime must allow ramp>0"
            )

        _check_timing_feasibility(self.onset_fraction_range, self.attack_duration_range)


def _validate_fraction_range(
    name: str, rng: tuple[float, float], *, lo_bound: float, hi_bound: float
) -> None:
    lo, hi = rng
    if not (lo_bound <= lo < hi <= hi_bound):
        raise ValueError(f"{name} must satisfy {lo_bound} <= lo < hi <= {hi_bound}, got {rng}")


def _validate_positive_range(name: str, rng: tuple[float, float]) -> None:
    lo, hi = rng
    if not (0 < lo <= hi):
        raise ValueError(f"{name} must satisfy 0 < lo <= hi, got {rng}")


def _check_timing_feasibility(
    onset_fraction_range: tuple[float, float], attack_duration_range: tuple[float, float]
) -> None:
    """Static feasibility check against the FROZEN duration/window/context
    constants -- catches a structurally impossible config before any run.

    Mirrors the derivation `src.simulator.v2.attack.sample_attack_timing`
    performs per-run, so a contradiction is reported at config-construction
    time rather than surfacing later as an unbounded resampling loop.
    """
    min_onset = CONTEXT_MIN_WINDOWS_PRE * WINDOW_SECONDS
    max_onset_by_context = (
        DURATION_SECONDS - CONTEXT_MIN_WINDOWS_POST * WINDOW_SECONDS - attack_duration_range[0]
    )
    lo = max(onset_fraction_range[0] * DURATION_SECONDS, min_onset)
    hi = min(onset_fraction_range[1] * DURATION_SECONDS, max_onset_by_context)
    if lo >= hi:
        raise ValueError(
            "onset_fraction_range and attack_duration_range leave no feasible onset window "
            f"given the frozen duration_seconds={DURATION_SECONDS}, "
            f"window_seconds={WINDOW_SECONDS}, "
            f"context_min_windows_pre={CONTEXT_MIN_WINDOWS_PRE}, "
            f"context_min_windows_post={CONTEXT_MIN_WINDOWS_POST}: "
            f"effective onset range would be [{lo}, {hi})"
        )
