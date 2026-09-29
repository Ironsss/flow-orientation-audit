"""Generator v2 orchestration: the only public entry point.

`run_simulation_v2` is the single place that uses the frozen constants
(`HOST_POOL_SIZE`, `DURATION_SECONDS`, `WINDOW_SECONDS`, `N_COMMUNITIES`) with
no way to override them -- background/population/attack helper functions
accept these as ordinary keyword defaults (useful for fast, small-scale unit
tests of the underlying math), but this function never passes anything else.

Reproducibility: `simulation_seed` is the only seed a caller supplies. Every
internal stream is a deterministic sub-stream of
`numpy.random.SeedSequence(simulation_seed)`, spawned once, in a fixed order,
so the same seed always produces the same trace and no internal reordering of
components can change one component's random draws by way of another's.
"""

from __future__ import annotations

from datetime import datetime

import numpy as np
import polars as pl

from src.simulator.v2.attack import generate_attack, sample_attack_timing
from src.simulator.v2.background import generate_background
from src.simulator.v2.config import (
    DURATION_SECONDS,
    HOST_POOL_SIZE,
    N_COMMUNITIES,
    WINDOW_SECONDS,
    SimulationConfigV2,
)
from src.simulator.v2.population import build_host_pool

__all__ = ["run_simulation_v2"]

#: Fixed, arbitrary epoch -- reproducibility only requires it be constant,
#: not that it mean anything (same convention as Generator v1).
_START_TIME = datetime(2024, 1, 1)

#: Names and order of the substreams spawned from `simulation_seed`. Order is
#: part of the reproducibility contract: never reorder this list, only append.
_SUBSTREAMS = (
    "population",        # host roles + community assignment
    "background_timing",  # per-host idle/normal/burst timelines
    "background_flows",   # destination/service/bytes/packets/duration/response draws
    "attack_selection",    # attacker set + victim
    "attack_timing",        # onset/duration/ramp
    "attack_intensity",      # attacker_count/peak_rate/response_probability + per-flow draws
)


def run_simulation_v2(config: SimulationConfigV2) -> pl.DataFrame:
    """Run one Generator v2 simulation and return a flow frame.

    Schema matches Generator v1 / the ingest module exactly: `timestamp,
    src_ip, dst_ip, src_port, dst_port, protocol, flow_duration,
    tot_fwd_pkts, tot_bwd_pkts, totlen_fwd_pkts, totlen_bwd_pkts, label,
    is_attack` -- so `src.audit.canonical.build_canonical_windowing` and
    `canonical_window_features` consume it unchanged. No window label or
    ground truth is computed here; `is_attack` is the only class information
    this module ever writes, per flow, and canonical windowing derives
    `attack_ratio_gt`/`y_gt` from it afterward.
    """
    seed_seq = np.random.SeedSequence(config.simulation_seed)
    streams = {
        name: np.random.default_rng(child)
        for name, child in zip(_SUBSTREAMS, seed_seq.spawn(len(_SUBSTREAMS)))
    }

    host_pool = build_host_pool(
        streams["population"], size=HOST_POOL_SIZE, n_communities=N_COMMUNITIES
    )

    background_flows = generate_background(
        streams["background_timing"],
        streams["background_flows"],
        host_pool,
        config,
        duration_seconds=DURATION_SECONDS,
        window_seconds=WINDOW_SECONDS,
        start_time=_START_TIME,
    )

    timing = sample_attack_timing(
        streams["attack_selection"],
        streams["attack_timing"],
        streams["attack_intensity"],
        host_pool,
        config.severity_regime,
        config.severity[config.severity_regime],
        onset_fraction_range=config.onset_fraction_range,
        attack_duration_range=config.attack_duration_range,
        duration_seconds=DURATION_SECONDS,
        window_seconds=WINDOW_SECONDS,
    )
    attack_flows = generate_attack(streams["attack_intensity"], timing, start_time=_START_TIME)

    all_flows = background_flows + attack_flows
    if not all_flows:
        raise RuntimeError("Generator v2 produced zero flows -- check activity/severity config")

    df = pl.DataFrame(all_flows)
    return df.sort("timestamp")
