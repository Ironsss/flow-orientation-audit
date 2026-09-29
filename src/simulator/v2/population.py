"""Host population for Generator v2 (P2.7/P2.8).

One shared pool of hosts. Attackers and the victim are drawn FROM this pool
elsewhere (`src.simulator.v2.attack`) -- there is no separate address range
for attackers anywhere in this module, which is the direct fix for the
node-count shortcut P1 measured in Generator v1 (n_nodes: benign ~50 exact,
attack ~55 exact, std=0).

`infra_shared_hub` hosts are deliberately NOT assigned to a single community:
they are the shared-service hubs (P2.9) reachable from every community, so
`community_of[hub] is None` and `hosts_by_community` only ever contains
non-hub hosts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import numpy as np

from src.simulator.v2.config import HOST_POOL_SIZE, N_COMMUNITIES, ROLE_COUNTS, Role

__all__ = ["HostPool", "build_host_pool"]


@dataclass(frozen=True)
class HostPool:
    """A frozen host population: identity, role, and community assignment.

    `community_of[h] is None` for hub hosts (cross-community by design);
    every non-hub host belongs to exactly one of `range(n_communities)`.
    """

    host_ids: tuple[str, ...]
    role_of: Mapping[str, Role]
    community_of: Mapping[str, int | None]
    hosts_by_role: Mapping[Role, tuple[str, ...]]
    hosts_by_community: Mapping[int, tuple[str, ...]]
    hub_hosts: tuple[str, ...]
    n_communities: int

    def community_peers(self, host: str) -> tuple[str, ...]:
        """Non-hub hosts sharing `host`'s community, excluding `host` itself."""
        c = self.community_of[host]
        if c is None:
            return ()
        return tuple(h for h in self.hosts_by_community[c] if h != host)

    def other_community_hosts(self, host: str) -> tuple[str, ...]:
        """Non-hub hosts in a community other than `host`'s (or all non-hub
        hosts, if `host` is itself a hub)."""
        c = self.community_of[host]
        return tuple(
            h for comm, hosts in self.hosts_by_community.items() if comm != c for h in hosts
        )


def build_host_pool(
    rng: np.random.Generator,
    *,
    size: int = HOST_POOL_SIZE,
    role_counts: Mapping[Role, int] = ROLE_COUNTS,
    n_communities: int = N_COMMUNITIES,
) -> HostPool:
    """Assign roles and communities to `size` hosts, reproducibly from `rng`.

    `size`/`role_counts`/`n_communities` default to the frozen contract
    constants; they remain parameters here (not hardcoded) purely so
    population-assignment logic can be unit-tested at small scale without
    spinning the full 80-host pool -- `run_simulation_v2` never overrides
    them.
    """
    if sum(role_counts.values()) != size:
        raise ValueError(
            f"role_counts sums to {sum(role_counts.values())}, expected size={size}"
        )

    host_ids = tuple(f"10.0.0.{i + 1}" for i in range(size))

    role_sequence: list[Role] = []
    for role, count in role_counts.items():
        role_sequence.extend([role] * count)
    role_order = rng.permutation(len(role_sequence))
    role_of = {host_ids[pos]: role_sequence[i] for i, pos in enumerate(role_order)}

    hosts_by_role: dict[Role, tuple[str, ...]] = {
        role: tuple(h for h in host_ids if role_of[h] is role) for role in role_counts
    }
    hub_hosts = hosts_by_role.get(Role.INFRA_HUB, ())

    non_hub_hosts = tuple(h for h in host_ids if h not in hub_hosts)
    if n_communities <= 0 or len(non_hub_hosts) < n_communities:
        raise ValueError(
            f"cannot split {len(non_hub_hosts)} non-hub hosts into {n_communities} communities"
        )
    community_order = rng.permutation(len(non_hub_hosts))
    hosts_by_community: dict[int, list[str]] = {c: [] for c in range(n_communities)}
    community_of: dict[str, int | None] = {h: None for h in hub_hosts}
    for i, pos in enumerate(community_order):
        community = i % n_communities
        host = non_hub_hosts[pos]
        hosts_by_community[community].append(host)
        community_of[host] = community

    return HostPool(
        host_ids=host_ids,
        role_of=role_of,
        community_of=community_of,
        hosts_by_role=hosts_by_role,
        hosts_by_community={c: tuple(hs) for c, hs in hosts_by_community.items()},
        hub_hosts=hub_hosts,
        n_communities=n_communities,
    )
