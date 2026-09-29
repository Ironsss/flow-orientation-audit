"""Generator v2 -- the P2 experimental substrate.

Implements docs/methodology/P2_GENERATOR_V2_DESIGN_FREEZE.md. Coexists
additively with Generator v1 (`src.simulator.agents`), which is unchanged and
remains the only way to reproduce P0/P0.5/P0.6/P1 results.

    from src.simulator.v2 import SimulationConfigV2, SeverityRegime, run_simulation_v2

    config = SimulationConfigV2(simulation_seed=1, severity_regime=SeverityRegime.MEDIUM)
    trace = run_simulation_v2(config)

`trace` is a flow frame in the same schema Generator v1 and the ingest module
produce, ready for `src.audit.canonical.build_canonical_windowing` unchanged.

This module implements the generator only -- it does not compute, evaluate,
or embed any acceptance criterion (AC1-AC12). That belongs to Development/
Validation audit tooling, built separately, against this generator's output.
"""

from src.simulator.v2.config import (
    CONTEXT_MIN_WINDOWS_POST,
    CONTEXT_MIN_WINDOWS_PRE,
    DEFAULT_ACTIVITY,
    DEFAULT_ROLE_SERVICE_WEIGHTS,
    DEFAULT_SERVICES,
    DEFAULT_SEVERITY,
    DURATION_SECONDS,
    HOST_POOL_SIZE,
    N_COMMUNITIES,
    ROLE_COUNTS,
    SEVERITY_TO_STRATUM,
    WINDOW_SECONDS,
    ActivityProfile,
    ActivityState,
    CommunityConfig,
    Role,
    ServiceProfile,
    ServiceType,
    SeverityProfile,
    SeverityRegime,
    SimulationConfigV2,
    Stratum,
    stratum_of,
)
from src.simulator.v2.population import HostPool, build_host_pool
from src.simulator.v2.run import run_simulation_v2

__all__ = [
    "ActivityProfile",
    "ActivityState",
    "CONTEXT_MIN_WINDOWS_POST",
    "CONTEXT_MIN_WINDOWS_PRE",
    "CommunityConfig",
    "DEFAULT_ACTIVITY",
    "DEFAULT_ROLE_SERVICE_WEIGHTS",
    "DEFAULT_SERVICES",
    "DEFAULT_SEVERITY",
    "DURATION_SECONDS",
    "HOST_POOL_SIZE",
    "HostPool",
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
    "build_host_pool",
    "run_simulation_v2",
    "stratum_of",
]
