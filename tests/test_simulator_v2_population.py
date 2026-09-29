"""Population tests for Generator v2 (P2.7/P2.8): host pool, roles,
communities, and the no-attacker-subnet property.

Uses the frozen contract sizes (80 hosts) since population assignment is
cheap (pure numpy permutations, no flow generation) -- no need to shrink it
for test speed.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.simulator.v2 import HOST_POOL_SIZE, N_COMMUNITIES, ROLE_COUNTS, Role, build_host_pool


def _pool(seed: int = 0):
    return build_host_pool(np.random.default_rng(seed))


class TestHostPool:
    def test_exactly_80_hosts(self):
        pool = _pool()
        assert len(pool.host_ids) == HOST_POOL_SIZE == 80
        assert len(set(pool.host_ids)) == 80  # no duplicate addresses

    def test_role_counts_exact(self):
        pool = _pool()
        counts = {role: len(hosts) for role, hosts in pool.hosts_by_role.items()}
        assert counts == dict(ROLE_COUNTS)

    def test_every_host_has_exactly_one_role(self):
        pool = _pool()
        assert set(pool.role_of) == set(pool.host_ids)
        assert all(isinstance(r, Role) for r in pool.role_of.values())

    def test_exactly_4_communities(self):
        pool = _pool()
        assert pool.n_communities == N_COMMUNITIES == 4
        assert set(pool.hosts_by_community) == {0, 1, 2, 3}

    def test_communities_partition_the_non_hub_hosts(self):
        pool = _pool()
        non_hub = set(pool.host_ids) - set(pool.hub_hosts)
        union = set()
        for hosts in pool.hosts_by_community.values():
            union |= set(hosts)
        assert union == non_hub

    def test_hub_hosts_have_no_single_community(self):
        pool = _pool()
        assert len(pool.hub_hosts) == ROLE_COUNTS[Role.INFRA_HUB] == 4
        for h in pool.hub_hosts:
            assert pool.community_of[h] is None

    def test_no_attacker_subnet_exists_in_the_address_scheme(self):
        """There is nothing in a host's address that encodes its role -- the
        only source of an attacker population is a run-time SUBSET of
        `host_ids`, drawn in src.simulator.v2.attack, never a reserved range."""
        pool = _pool()
        prefixes = {h.rsplit(".", 1)[0] for h in pool.host_ids}
        assert len(prefixes) == 1, "all hosts should share one address prefix, no reserved range"

    def test_reproducible_given_same_rng_seed(self):
        a = build_host_pool(np.random.default_rng(42))
        b = build_host_pool(np.random.default_rng(42))
        assert a.host_ids == b.host_ids
        assert a.role_of == b.role_of
        assert a.community_of == b.community_of

    def test_different_seed_gives_a_different_assignment(self):
        a = build_host_pool(np.random.default_rng(1))
        b = build_host_pool(np.random.default_rng(2))
        assert a.role_of != b.role_of or a.community_of != b.community_of

    def test_community_peers_excludes_self_and_hubs(self):
        pool = _pool()
        non_hub = next(h for h in pool.host_ids if h not in pool.hub_hosts)
        peers = pool.community_peers(non_hub)
        assert non_hub not in peers
        assert set(peers) <= set(pool.hosts_by_community[pool.community_of[non_hub]])

    def test_hub_has_no_community_peers(self):
        pool = _pool()
        assert pool.community_peers(pool.hub_hosts[0]) == ()

    def test_small_scale_pool_for_fast_unit_tests(self):
        """Population assignment is parametrized (size/role_counts/
        n_communities) precisely so it can be exercised at a scale smaller
        than the frozen 80, without ever touching that constant."""
        small_roles = {Role.CLIENT: 6, Role.SERVER: 2, Role.INFRA_HUB: 2}
        pool = build_host_pool(
            np.random.default_rng(0), size=10, role_counts=small_roles, n_communities=2
        )
        assert len(pool.host_ids) == 10
        assert len(pool.hub_hosts) == 2

    def test_rejects_role_counts_not_summing_to_size(self):
        with pytest.raises(ValueError):
            build_host_pool(np.random.default_rng(0), size=10, role_counts={Role.CLIENT: 5})
