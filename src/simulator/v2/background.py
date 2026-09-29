"""Benign traffic generation for Generator v2 (P2.9-P2.13).

Replaces v1's single uniform-random-choice background (P1 measured it as a
saturated clique: 2450/2450 ordered pairs present, reciprocity≈1.0 in every
run) with role- and community-structured traffic: destination selection
prefers same-community peers and shared hubs over the rest of the pool
(P2.8/P2.9), each host's instantaneous rate follows an idle/normal/burst
timeline (P2.10), and each flow's service type drives its byte/packet/
duration distribution and reciprocity probability (P2.11-P2.13).

This module never looks at attack state. It has no parameter that could carry
attack information, by construction -- the attack is added independently and
additively in `src.simulator.v2.attack`, matching the frozen architecture
(SS3 of the design contract): background does not know whether the run it is
part of is being scored `benign` or `attack` for any window.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np

from src.simulator.v2.config import (
    WINDOW_SECONDS,
    ActivityState,
    Role,
    ServiceType,
    SimulationConfigV2,
)
from src.simulator.v2.population import HostPool

__all__ = ["generate_background"]

_PORT_BY_SERVICE = {
    ServiceType.WEB_INTERACTIVE: (80, 443, 8080),
    ServiceType.DNS_LIKE: (53,),
    ServiceType.SSH_ADMIN_LIKE: (22,),
    ServiceType.BULK_TRANSFER: (80, 443, 21),
    ServiceType.PERIODIC_SERVICE: (123, 161),
    ServiceType.BACKGROUND_M2M: tuple(range(5000, 5010)),
}


def _activity_timeline(
    rng: np.random.Generator, mean_dwell: dict[ActivityState, float], duration_seconds: float
) -> list[tuple[float, float, ActivityState]]:
    """A reproducible idle/normal/burst timeline covering [0, duration_seconds).

    A lightweight semi-Markov process: dwell time in each state is
    exponential with the state's configured mean; the next state is chosen
    uniformly among the other two. Starting state is drawn uniformly.
    """
    states = list(ActivityState)
    segments: list[tuple[float, float, ActivityState]] = []
    t = 0.0
    state = states[rng.integers(0, len(states))]
    while t < duration_seconds:
        dwell = rng.exponential(mean_dwell[state])
        t_end = min(t + dwell, duration_seconds)
        segments.append((t, t_end, state))
        t = t_end
        others = [s for s in states if s is not state]
        state = others[rng.integers(0, len(others))]
    return segments


def _select_destination(
    rng: np.random.Generator, source: str, host_pool: HostPool, community_cfg
) -> str:
    """SBM-like destination pick: same-community, other-community, or hub,
    weighted by `p_intra` / `p_inter` / `hub_preference` (normalized here)."""
    intra = host_pool.community_peers(source)
    inter = host_pool.other_community_hosts(source)
    hubs = tuple(h for h in host_pool.hub_hosts if h != source)

    buckets = [
        (intra, community_cfg.p_intra),
        (inter, community_cfg.p_inter),
        (hubs, community_cfg.hub_preference),
    ]
    buckets = [(pool, w) for pool, w in buckets if pool]
    if not buckets:
        raise ValueError(f"host {source} has no eligible destination")
    weights = np.array([w for _, w in buckets], dtype=np.float64)
    weights /= weights.sum()
    bucket = buckets[rng.choice(len(buckets), p=weights)][0]
    return bucket[rng.integers(0, len(bucket))]


def _select_service(rng: np.random.Generator, role: Role, role_service_weights) -> ServiceType:
    weights_map = role_service_weights[role]
    services = list(weights_map)
    weights = np.array([weights_map[s] for s in services], dtype=np.float64)
    weights /= weights.sum()
    return services[rng.choice(len(services), p=weights)]


def _emit_flow(
    rng: np.random.Generator,
    start_time: datetime,
    t_seconds: float,
    src: str,
    dst: str,
    service: ServiceType,
    profile,
) -> dict:
    ports = _PORT_BY_SERVICE[service]
    dst_port = int(ports[rng.integers(0, len(ports))])
    fwd_bytes = float(rng.uniform(*profile.bytes_range))
    bwd_bytes = float(rng.uniform(*profile.bytes_range) * 0.3)  # ack-sized reverse direction
    fwd_pkts = int(rng.integers(profile.packets_range[0], profile.packets_range[1] + 1))
    bwd_pkts = max(1, fwd_pkts // 3)
    duration = float(rng.uniform(*profile.duration_range))
    return {
        "timestamp": start_time + timedelta(seconds=t_seconds),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": int(rng.integers(1024, 65535)),
        "dst_port": dst_port,
        "protocol": 6,
        "flow_duration": duration,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "totlen_fwd_pkts": fwd_bytes,
        "totlen_bwd_pkts": bwd_bytes,
        "label": "Benign",
        "is_attack": 0,
    }


def _infrastructure_heartbeat(
    rng_flows: np.random.Generator,
    host_pool: HostPool,
    services,
    *,
    duration_seconds: float,
    window_seconds: float,
    start_time: datetime,
) -> list[dict]:
    """One deterministic benign flow at the centre of every canonical window.

    `src.audit.canonical.build_canonical_windowing` only emits a window that
    the full trace put at least one flow in; the frozen temporal protocol
    (design freeze SS7) fixes `canonical windows/run = duration_seconds /
    window_seconds`. Poisson background alone makes full coverage only
    *overwhelmingly likely*, and it depends on tunable benign rates -- it is
    not a structural guarantee. This adds a fixed-cadence infrastructure
    poll (one flow per 60 s interval, ~60 flows/run against ~1.3e5 benign)
    so every window is non-empty by construction, for any `simulation_seed`,
    any `severity_regime`, and any Development rate tuning.

    The flow carries no class information: it is present, identical, in
    benign and attack windows alike, and never touches `is_attack` /
    ground truth. Timestamp and endpoints are fully deterministic; only the
    cosmetic per-flow fields in `_emit_flow` consume `rng_flows`.
    """
    n_windows = int(duration_seconds // window_seconds)
    ids = host_pool.host_ids
    hub_ids = host_pool.hub_hosts or ids
    profile = services[ServiceType.PERIODIC_SERVICE]
    flows: list[dict] = []
    for k in range(n_windows):
        src = hub_ids[k % len(hub_ids)]
        dst = ids[k % len(ids)]
        if dst == src:
            dst = ids[(k + 1) % len(ids)]
        t_centre = (k + 0.5) * window_seconds
        flows.append(
            _emit_flow(
                rng_flows, start_time, t_centre, src, dst,
                ServiceType.PERIODIC_SERVICE, profile,
            )
        )
    return flows


def generate_background(
    rng_timing: np.random.Generator,
    rng_flows: np.random.Generator,
    host_pool: HostPool,
    config: SimulationConfigV2,
    *,
    duration_seconds: float,
    start_time: datetime,
    window_seconds: float = WINDOW_SECONDS,
) -> list[dict]:
    """Every benign flow for one run, across the whole `host_pool`.

    Two independent RNGs, matching the substream separation in
    `src.simulator.v2.run`: `rng_timing` drives each host's activity-state
    timeline, `rng_flows` drives destination/service/bytes/packets/duration/
    response draws for every individual flow.

    `window_seconds` is used only by the deterministic infrastructure
    heartbeat (`_infrastructure_heartbeat`), which guarantees full canonical
    window coverage; it defaults to the frozen constant and `run_simulation_v2`
    never overrides it.
    """
    flows: list[dict] = []
    for host in host_pool.host_ids:
        role = host_pool.role_of[host]
        profile = config.activity[role]
        base_rate = rng_timing.uniform(*profile.base_flows_per_min)
        timeline = _activity_timeline(
            rng_timing, dict(profile.mean_dwell_seconds), duration_seconds
        )

        for t0, t1, state in timeline:
            rate = base_rate * profile.state_multiplier[state]  # flows/min
            expected = rate * (t1 - t0) / 60.0
            n = int(rng_flows.poisson(expected)) if expected > 0 else 0
            if n == 0:
                continue
            timestamps = rng_flows.uniform(t0, t1, size=n)
            for t_seconds in timestamps:
                dst = _select_destination(rng_flows, host, host_pool, config.community)
                service = _select_service(rng_flows, role, config.role_service_weights)
                service_profile = config.services[service]
                flows.append(
                    _emit_flow(
                        rng_flows, start_time, float(t_seconds), host, dst, service, service_profile
                    )
                )
                if rng_flows.random() < service_profile.response_probability:
                    response_t = min(
                        float(t_seconds) + float(rng_flows.uniform(0.001, 0.5)),
                        duration_seconds - 1e-6,
                    )
                    flows.append(
                        _emit_flow(
                            rng_flows, start_time, response_t, dst, host, service, service_profile
                        )
                    )

    flows.extend(
        _infrastructure_heartbeat(
            rng_flows,
            host_pool,
            config.services,
            duration_seconds=duration_seconds,
            window_seconds=window_seconds,
            start_time=start_time,
        )
    )
    return flows
