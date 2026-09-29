"""DDoS v2 attack generation (P2.14-P2.16).

Attackers and the victim are drawn from the SAME `HostPool` used for
background traffic (P2.7) -- there is no attacker-only address range, which
is the direct fix for P1's node-count shortcut. Onset, duration and ramp are
derived mathematically from the frozen duration/window/context constants
rather than by unbounded rejection sampling (P2.14/design contract SS7), so a
config that leaves no feasible timing raises immediately instead of looping.

`attack_ratio_gt` is never written here or anywhere in this module -- it is
computed later by `src.audit.canonical.build_canonical_windowing` from the
per-flow `is_attack` column this module sets. Ramp only staggers how many
attackers are active; the resulting label is entirely a consequence of how
many flows land in each canonical window.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np

from src.simulator.v2.config import (
    CONTEXT_MIN_WINDOWS_POST,
    CONTEXT_MIN_WINDOWS_PRE,
    DURATION_SECONDS,
    WINDOW_SECONDS,
    SeverityProfile,
    SeverityRegime,
)
from src.simulator.v2.population import HostPool

__all__ = ["AttackTiming", "generate_attack", "sample_attack_timing"]


@dataclass(frozen=True)
class AttackTiming:
    """One run's realized attack parameters -- all sampled, none hand-set."""

    attack_start: float  # seconds from run start
    attack_duration: float
    ramp_seconds: float
    attacker_ids: tuple[str, ...]
    victim_id: str
    peak_rate_per_attacker: float  # requests/second, per attacker, once fully ramped
    response_probability: float


def _feasible_onset_range(
    onset_fraction_range: tuple[float, float],
    attack_duration_range: tuple[float, float],
    *,
    duration_seconds: float,
    window_seconds: float,
    context_pre: int,
    context_post: int,
) -> tuple[float, float]:
    min_onset = context_pre * window_seconds
    max_onset_by_context = (
        duration_seconds - context_post * window_seconds - attack_duration_range[0]
    )
    lo = max(onset_fraction_range[0] * duration_seconds, min_onset)
    hi = min(onset_fraction_range[1] * duration_seconds, max_onset_by_context)
    if lo >= hi:
        raise ValueError(
            "no feasible attack onset: configured onset_fraction_range="
            f"{onset_fraction_range}, attack_duration_range={attack_duration_range}, "
            f"duration_seconds={duration_seconds}, context_pre={context_pre} windows, "
            f"context_post={context_post} windows -> effective range [{lo}, {hi})"
        )
    return lo, hi


def sample_attack_timing(
    rng_selection: np.random.Generator,
    rng_timing: np.random.Generator,
    rng_intensity: np.random.Generator,
    host_pool: HostPool,
    severity_regime: SeverityRegime,
    severity_profile: SeverityProfile,
    *,
    onset_fraction_range: tuple[float, float],
    attack_duration_range: tuple[float, float],
    duration_seconds: float = DURATION_SECONDS,
    window_seconds: float = WINDOW_SECONDS,
    context_pre: int = CONTEXT_MIN_WINDOWS_PRE,
    context_post: int = CONTEXT_MIN_WINDOWS_POST,
) -> AttackTiming:
    """Derive one run's attack timing/population/intensity.

    Three separate RNGs, matching the substream list in the design contract:
    `rng_selection` picks attackers/victim, `rng_timing` draws onset/duration/
    ramp, `rng_intensity` draws attacker_count/peak_rate/response_probability.
    `duration_seconds`/`window_seconds`/`context_*` default to the frozen
    constants; they remain parameters purely so this function is unit-testable
    at other scales without spinning a full run.
    """
    lo, hi = _feasible_onset_range(
        onset_fraction_range,
        attack_duration_range,
        duration_seconds=duration_seconds,
        window_seconds=window_seconds,
        context_pre=context_pre,
        context_post=context_post,
    )
    attack_start = float(rng_timing.uniform(lo, hi))

    max_duration = duration_seconds - attack_start - context_post * window_seconds
    duration_hi = min(attack_duration_range[1], max_duration)
    if attack_duration_range[0] > duration_hi:
        raise ValueError(
            f"attack_start={attack_start} leaves no room for attack_duration_range="
            f"{attack_duration_range} within duration_seconds={duration_seconds}"
        )
    attack_duration = float(rng_timing.uniform(attack_duration_range[0], duration_hi))

    ramp_seconds = float(rng_timing.uniform(*severity_profile.ramp_seconds_range))
    ramp_seconds = min(ramp_seconds, attack_duration)  # cannot ramp longer than the attack itself

    attacker_count = int(
        rng_intensity.integers(
            severity_profile.attacker_count_range[0], severity_profile.attacker_count_range[1] + 1
        )
    )
    if attacker_count >= len(host_pool.host_ids):
        raise ValueError(
            f"attacker_count={attacker_count} >= host pool size {len(host_pool.host_ids)}"
        )
    chosen = rng_selection.choice(len(host_pool.host_ids), size=attacker_count + 1, replace=False)
    attacker_ids = tuple(host_pool.host_ids[i] for i in chosen[:attacker_count])
    victim_id = host_pool.host_ids[chosen[attacker_count]]

    peak_rate = float(rng_intensity.uniform(*severity_profile.peak_rate_per_attacker_range))
    response_probability = float(
        rng_intensity.uniform(*severity_profile.response_probability_range)
    )

    return AttackTiming(
        attack_start=attack_start,
        attack_duration=attack_duration,
        ramp_seconds=ramp_seconds,
        attacker_ids=attacker_ids,
        victim_id=victim_id,
        peak_rate_per_attacker=peak_rate,
        response_probability=response_probability,
    )


def generate_attack(
    rng: np.random.Generator,
    timing: AttackTiming,
    *,
    start_time: datetime,
) -> list[dict]:
    """Flood flows for one run's realized `AttackTiming`.

    Attacker *i* activates at `attack_start + i*ramp_seconds/n_attackers`
    (P2.15) -- when `ramp_seconds=0` every attacker activates at
    `attack_start`, the formula degenerates to the abrupt case without a
    special branch. Each attacker then sends at `peak_rate_per_attacker`
    requests/second (Poisson arrivals) until the attack ends.
    """
    flows: list[dict] = []
    n = len(timing.attacker_ids)
    attack_end = timing.attack_start + timing.attack_duration
    for i, attacker in enumerate(timing.attacker_ids):
        activation = timing.attack_start + i * timing.ramp_seconds / n
        active_seconds = max(attack_end - activation, 0.0)
        if active_seconds <= 0:
            continue
        expected = timing.peak_rate_per_attacker * active_seconds
        count = int(rng.poisson(expected)) if expected > 0 else 0
        if count == 0:
            continue
        timestamps = rng.uniform(activation, attack_end, size=count)
        for t_seconds in timestamps:
            flows.append(
                _attack_flow(rng, start_time, float(t_seconds), attacker, timing.victim_id)
            )
            if rng.random() < timing.response_probability:
                flows.append(
                    _attack_flow(
                        rng,
                        start_time,
                        float(t_seconds) + float(rng.uniform(0.001, 0.05)),
                        timing.victim_id,
                        attacker,
                    )
                )
    return flows


def _attack_flow(
    rng: np.random.Generator, start_time: datetime, t_seconds: float, src: str, dst: str
) -> dict:
    return {
        "timestamp": start_time + timedelta(seconds=t_seconds),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": int(rng.integers(1024, 65535)),
        "dst_port": 80,
        "protocol": 6,
        "flow_duration": float(rng.exponential(10_000.0)),
        "tot_fwd_pkts": int(rng.integers(1, 5)),
        "tot_bwd_pkts": int(rng.integers(0, 2)),
        "totlen_fwd_pkts": float(rng.integers(40, 1500)),
        "totlen_bwd_pkts": float(rng.integers(0, 100)),
        "label": "DDoS",
        "is_attack": 1,
    }
