"""Integration tests for Generator v2's public entry point.

Full `run_simulation_v2` calls are kept to the minimum needed to prove
reproducibility and canonical-windowing compatibility -- each uses a
low-intensity severity regime to keep the suite fast; the frozen
80-host/3600s/60s constants are used unmodified throughout, since
`run_simulation_v2` has no parameter to override them.
"""

from __future__ import annotations

import polars as pl

from src.audit.canonical import build_canonical_windowing, canonical_window_features
from src.features import InfoTier
from src.simulator.v2 import (
    DURATION_SECONDS,
    HOST_POOL_SIZE,
    WINDOW_SECONDS,
    SeverityRegime,
    SimulationConfigV2,
    Stratum,
    run_simulation_v2,
    stratum_of,
)

_V1_SCHEMA = {
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts",
    "totlen_bwd_pkts", "label", "is_attack",
}


class TestReproducibility:
    def test_same_seed_same_config_gives_an_identical_trace(self):
        cfg = SimulationConfigV2(simulation_seed=101, severity_regime=SeverityRegime.LOW_SIGNAL)
        a = run_simulation_v2(cfg)
        b = run_simulation_v2(cfg)
        assert a.equals(b)

    def test_different_seed_gives_a_different_trace(self):
        cfg_a = SimulationConfigV2(simulation_seed=101, severity_regime=SeverityRegime.LOW_SIGNAL)
        cfg_b = SimulationConfigV2(simulation_seed=102, severity_regime=SeverityRegime.LOW_SIGNAL)
        assert not run_simulation_v2(cfg_a).equals(run_simulation_v2(cfg_b))

    def test_schema_matches_generator_v1(self):
        cfg = SimulationConfigV2(simulation_seed=101, severity_regime=SeverityRegime.LOW_SIGNAL)
        df = run_simulation_v2(cfg)
        assert _V1_SCHEMA <= set(df.columns)
        assert df["timestamp"].dtype == pl.Datetime or "Datetime" in str(df["timestamp"].dtype)

    def test_output_is_sorted_by_timestamp(self):
        cfg = SimulationConfigV2(simulation_seed=101, severity_regime=SeverityRegime.LOW_SIGNAL)
        df = run_simulation_v2(cfg)
        ts = df["timestamp"].to_list()
        assert ts == sorted(ts)

    def test_both_classes_present_from_the_same_trace(self):
        """C2/AC12: positives and negatives must come from the same run."""
        cfg = SimulationConfigV2(simulation_seed=101, severity_regime=SeverityRegime.LOW_SIGNAL)
        df = run_simulation_v2(cfg)
        assert (df["is_attack"] == 0).sum() > 0
        assert (df["is_attack"] == 1).sum() > 0

    def test_attackers_are_not_a_separate_address_range_from_benign_traffic(self):
        """P2.7: the set of hosts appearing in attack flows must be a SUBSET
        of the hosts appearing in benign flows' address space, not a disjoint
        range (the direct fix for the v1 n_nodes shortcut)."""
        cfg = SimulationConfigV2(simulation_seed=101, severity_regime=SeverityRegime.MEDIUM)
        df = run_simulation_v2(cfg)
        benign_hosts = set(df.filter(pl.col("is_attack") == 0)["src_ip"]) | set(
            df.filter(pl.col("is_attack") == 0)["dst_ip"]
        )
        attack_hosts = set(df.filter(pl.col("is_attack") == 1)["src_ip"]) | set(
            df.filter(pl.col("is_attack") == 1)["dst_ip"]
        )
        assert attack_hosts <= benign_hosts, (
            "every attacking/victim host must also appear in benign traffic "
            "(same shared pool) -- an address seen only in attack flows would "
            "reintroduce the v1 node-count shortcut"
        )


class TestCanonicalCompatibility:
    def test_canonical_windowing_runs_unmodified_against_a_v2_trace(self):
        cfg = SimulationConfigV2(simulation_seed=55, severity_regime=SeverityRegime.MEDIUM)
        df = run_simulation_v2(cfg)

        cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
        assert cw.n_windows == DURATION_SECONDS // WINDOW_SECONDS == 60

        feat = canonical_window_features(df, cw, tier=InfoTier.DIRECTIONAL, min_flows=10)
        assert len(feat) == cw.n_windows
        assert (feat["y_gt"] == 0).sum() > 0
        assert (feat["y_gt"] == 1).sum() > 0
        # y_gt/attack_ratio_gt are derived by canonical windowing from
        # is_attack -- Generator v2 must never have written them itself.
        assert "y_gt" not in df.columns
        assert "attack_ratio_gt" not in df.columns

    def test_stratum_helper_matches_severity_regime_used(self):
        cfg = SimulationConfigV2(simulation_seed=55, severity_regime=SeverityRegime.LOW_SIGNAL)
        assert stratum_of(cfg.severity_regime) is Stratum.LOW_SIGNAL
        cfg2 = SimulationConfigV2(simulation_seed=55, severity_regime=SeverityRegime.HIGH)
        assert stratum_of(cfg2.severity_regime) is Stratum.MAIN

    def test_host_pool_size_is_the_frozen_constant_regardless_of_severity(self):
        cfg = SimulationConfigV2(simulation_seed=55, severity_regime=SeverityRegime.LOW_SIGNAL)
        df = run_simulation_v2(cfg)
        all_hosts = set(df["src_ip"]) | set(df["dst_ip"])
        assert len(all_hosts) <= HOST_POOL_SIZE


class TestCanonicalWindowCoverage:
    """Design freeze SS7: `canonical windows/run = 60`, for Development,
    Validation and Final Test alike. The deterministic infrastructure
    heartbeat in `generate_background` makes this hold for every severity
    regime and every seed -- not just the ones the other tests happen to
    use -- so `build_canonical_windowing` never drops or invents a window."""

    def test_exactly_60_windows_for_every_regime_and_several_seeds(self):
        expected = DURATION_SECONDS // WINDOW_SECONDS
        assert expected == 60
        for regime in SeverityRegime:
            for seed in (7, 23):
                cfg = SimulationConfigV2(simulation_seed=seed, severity_regime=regime)
                df = run_simulation_v2(cfg)
                cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=0.01)
                assert cw.n_windows == expected, (
                    f"{regime.value} seed={seed}: got {cw.n_windows} canonical windows"
                )
                # the grid must be the contiguous 0..59, no gaps, no id >= 60
                assert list(cw.window_ids) == list(range(expected))
