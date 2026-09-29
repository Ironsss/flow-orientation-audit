"""Tests for the agent-based simulator."""

import polars as pl
import pytest

from src.simulator import agents as agents_module
from src.simulator.agents import AttackType, SimulationConfig, run_simulation, sweep_asymmetry


class TestSimulation:
    def test_benign_only(self):
        cfg = SimulationConfig(
            attack_type=AttackType.BENIGN,
            num_benign_hosts=10,
            duration_seconds=60,
            flows_per_second_benign=5.0,
            seed=42,
        )
        df = run_simulation(cfg)
        assert len(df) > 0
        assert (df["is_attack"] == 0).all()

    def test_ddos_produces_attacks(self):
        cfg = SimulationConfig(
            attack_type=AttackType.DDOS,
            num_benign_hosts=10,
            num_attackers=3,
            duration_seconds=60,
            seed=42,
        )
        df = run_simulation(cfg)
        assert (df["is_attack"] == 1).sum() > 0
        assert (df["is_attack"] == 0).sum() > 0

    def test_schema(self):
        cfg = SimulationConfig(
            attack_type=AttackType.DDOS,
            duration_seconds=60,
            seed=42,
        )
        df = run_simulation(cfg)
        required = {"timestamp", "src_ip", "dst_ip", "is_attack", "label"}
        assert required.issubset(set(df.columns))

    def test_asymmetry_level_affects_output(self):
        """Higher asymmetry should produce fewer response flows."""
        cfg_low = SimulationConfig(
            attack_type=AttackType.DDOS,
            asymmetry_level=0.0,  # Symmetric: all attacks get responses
            duration_seconds=60,
            seed=42,
        )
        cfg_high = SimulationConfig(
            attack_type=AttackType.DDOS,
            asymmetry_level=1.0,  # Fully asymmetric: no responses
            duration_seconds=60,
            seed=42,
        )
        df_low = run_simulation(cfg_low)
        df_high = run_simulation(cfg_high)

        # Low asymmetry should produce more total flows (more responses)
        attack_flows_low = len(df_low.filter(pl.col("is_attack") == 1))
        attack_flows_high = len(df_high.filter(pl.col("is_attack") == 1))
        assert attack_flows_low > attack_flows_high

    def test_botnet_produces_attacks(self):
        cfg = SimulationConfig(
            attack_type=AttackType.BOTNET,
            num_benign_hosts=10,
            num_attackers=4,
            duration_seconds=600,
            seed=42,
        )
        df = run_simulation(cfg)
        assert (df["is_attack"] == 1).sum() > 0
        assert (df.filter(pl.col("is_attack") == 1)["label"] == "Botnet").all()

    def test_botnet_beacons_spread_across_full_duration(self):
        """Unlike burst attacks, botnet beaconing should not be confined to the
        middle 50% window — it should appear across (close to) the full duration."""
        cfg = SimulationConfig(
            attack_type=AttackType.BOTNET,
            num_benign_hosts=5,
            num_attackers=3,
            duration_seconds=1800,
            asymmetry_level=1.0,
            seed=7,
        )
        df = run_simulation(cfg)
        attack_df = df.filter(pl.col("is_attack") == 1)
        offsets = (
            attack_df["timestamp"] - cfg.start_time
        ).dt.total_seconds()
        # At least one beacon in both the first and the last quarter of the run.
        assert (offsets < cfg.duration_seconds * 0.25).any()
        assert (offsets > cfg.duration_seconds * 0.75).any()

    def test_missing_generator_raises_instead_of_silently_producing_benign(self, monkeypatch):
        """A guard should stop AttackType additions from silently falling back
        to benign-only traffic when nobody has written a generator for them yet."""
        monkeypatch.setattr(agents_module, "_ATTACK_GENERATORS", {})
        cfg = SimulationConfig(attack_type=AttackType.DDOS, duration_seconds=60, seed=42)
        with pytest.raises(NotImplementedError):
            run_simulation(cfg)


class TestSweep:
    def test_sweep_returns_multiple_levels(self):
        results = sweep_asymmetry(
            levels=[0.0, 0.5, 1.0],
            attack_type=AttackType.DDOS,
            duration_seconds=30,
            num_benign_hosts=5,
        )
        assert len(results) == 3
        assert all(isinstance(df, pl.DataFrame) for df in results.values())
