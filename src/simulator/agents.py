"""
Agent-based network traffic simulator with controllable asymmetry.

Generates synthetic flow data where the asymmetry level is a configurable
parameter, enabling ablation studies impossible with real data.

Outputs the same schema as the ingest module for pipeline reuse.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

import numpy as np
import polars as pl


class AttackType(Enum):
    BENIGN = "Benign"
    DDOS = "DDoS"
    PORT_SCAN = "PortScan"
    BRUTE_FORCE = "BruteForce"
    INFILTRATION = "Infiltration"
    BOTNET = "Botnet"


@dataclass
class AgentConfig:
    """Configuration for a single agent in the simulation."""

    ip: str
    is_attacker: bool = False
    attack_type: AttackType = AttackType.BENIGN


@dataclass
class SimulationConfig:
    """Configuration for a full simulation run."""

    num_benign_hosts: int = 50
    num_attackers: int = 5
    attack_type: AttackType = AttackType.DDOS
    duration_seconds: int = 3600
    flows_per_second_benign: float = 10.0
    flows_per_second_attack: float = 100.0
    asymmetry_level: float = 0.8  # 0.0 = symmetric attack, 1.0 = fully asymmetric
    seed: int = 42
    start_time: datetime = field(default_factory=lambda: datetime(2024, 1, 1))


def _generate_benign_flows(
    config: SimulationConfig,
    hosts: list[str],
    rng: np.random.Generator,
) -> list[dict]:
    """Generate symmetric benign traffic between hosts."""
    flows = []
    total_flows = int(config.flows_per_second_benign * config.duration_seconds)

    for i in range(total_flows):
        src = rng.choice(hosts)
        dst = rng.choice([h for h in hosts if h != src])
        ts = config.start_time + timedelta(
            seconds=rng.uniform(0, config.duration_seconds)
        )

        # Benign: request flow
        flows.append({
            "timestamp": ts,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": int(rng.choice([80, 443, 8080, 22, 53])),
            "protocol": 6,  # TCP
            "flow_duration": float(rng.exponential(500000)),
            "tot_fwd_pkts": int(rng.integers(1, 50)),
            "tot_bwd_pkts": int(rng.integers(1, 50)),
            "totlen_fwd_pkts": float(rng.integers(100, 10000)),
            "totlen_bwd_pkts": float(rng.integers(100, 10000)),
            "label": "Benign",
            "is_attack": 0,
        })

        # Benign: response flow (symmetric)
        flows.append({
            "timestamp": ts + timedelta(milliseconds=float(rng.uniform(1, 100))),
            "src_ip": dst,
            "dst_ip": src,
            "src_port": int(rng.choice([80, 443, 8080, 22, 53])),
            "dst_port": int(rng.integers(1024, 65535)),
            "protocol": 6,
            "flow_duration": float(rng.exponential(500000)),
            "tot_fwd_pkts": int(rng.integers(1, 50)),
            "tot_bwd_pkts": int(rng.integers(1, 50)),
            "totlen_fwd_pkts": float(rng.integers(100, 10000)),
            "totlen_bwd_pkts": float(rng.integers(100, 10000)),
            "label": "Benign",
            "is_attack": 0,
        })

    return flows


def _generate_ddos_flows(
    config: SimulationConfig,
    attackers: list[str],
    victim: str,
    rng: np.random.Generator,
) -> list[dict]:
    """Generate DDoS attack flows with controllable asymmetry."""
    flows = []
    total_flows = int(config.flows_per_second_attack * config.duration_seconds)

    # Attack window: middle 50% of simulation
    attack_start = config.duration_seconds * 0.25
    attack_end = config.duration_seconds * 0.75

    for i in range(total_flows):
        attacker = rng.choice(attackers)
        ts = config.start_time + timedelta(
            seconds=rng.uniform(attack_start, attack_end)
        )

        # Attack flow: attacker -> victim
        flows.append({
            "timestamp": ts,
            "src_ip": attacker,
            "dst_ip": victim,
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": 80,
            "protocol": 6,
            "flow_duration": float(rng.exponential(10000)),
            "tot_fwd_pkts": int(rng.integers(1, 100)),
            "tot_bwd_pkts": int(rng.integers(0, 3)),  # Very few backward packets
            "totlen_fwd_pkts": float(rng.integers(40, 1500)),
            "totlen_bwd_pkts": float(rng.integers(0, 100)),
            "label": "DDoS",
            "is_attack": 1,
        })

        # With probability (1 - asymmetry_level), add a response (less asymmetric)
        if rng.random() > config.asymmetry_level:
            flows.append({
                "timestamp": ts + timedelta(milliseconds=float(rng.uniform(1, 50))),
                "src_ip": victim,
                "dst_ip": attacker,
                "src_port": 80,
                "dst_port": int(rng.integers(1024, 65535)),
                "protocol": 6,
                "flow_duration": float(rng.exponential(5000)),
                "tot_fwd_pkts": int(rng.integers(1, 10)),
                "tot_bwd_pkts": int(rng.integers(0, 2)),
                "totlen_fwd_pkts": float(rng.integers(40, 500)),
                "totlen_bwd_pkts": float(rng.integers(0, 50)),
                "label": "DDoS",
                "is_attack": 1,
            })

    return flows


def _generate_port_scan_flows(
    config: SimulationConfig,
    attackers: list[str],
    targets: list[str],
    rng: np.random.Generator,
) -> list[dict]:
    """Generate port scan flows with controllable asymmetry."""
    flows = []
    total_flows = int(config.flows_per_second_attack * config.duration_seconds)

    attack_start = config.duration_seconds * 0.25
    attack_end = config.duration_seconds * 0.75

    for i in range(total_flows):
        attacker = rng.choice(attackers)
        target = rng.choice(targets)
        ts = config.start_time + timedelta(
            seconds=rng.uniform(attack_start, attack_end)
        )

        # Scan flow: SYN to random port
        flows.append({
            "timestamp": ts,
            "src_ip": attacker,
            "dst_ip": target,
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": int(rng.integers(1, 65535)),
            "protocol": 6,
            "flow_duration": float(rng.exponential(1000)),
            "tot_fwd_pkts": 1,
            "tot_bwd_pkts": 0,
            "totlen_fwd_pkts": 44.0,  # SYN packet
            "totlen_bwd_pkts": 0.0,
            "label": "PortScan",
            "is_attack": 1,
        })

        # With probability (1 - asymmetry_level), add RST/SYN-ACK response
        if rng.random() > config.asymmetry_level:
            flows.append({
                "timestamp": ts + timedelta(milliseconds=float(rng.uniform(1, 10))),
                "src_ip": target,
                "dst_ip": attacker,
                "src_port": int(rng.integers(1, 65535)),
                "dst_port": int(rng.integers(1024, 65535)),
                "protocol": 6,
                "flow_duration": float(rng.exponential(100)),
                "tot_fwd_pkts": 1,
                "tot_bwd_pkts": 0,
                "totlen_fwd_pkts": 44.0,
                "totlen_bwd_pkts": 0.0,
                "label": "PortScan",
                "is_attack": 1,
            })

    return flows


def _generate_brute_force_flows(
    config: SimulationConfig,
    attackers: list[str],
    target: str,
    rng: np.random.Generator,
) -> list[dict]:
    """Generate brute force attack flows."""
    flows = []
    total_flows = int(config.flows_per_second_attack * config.duration_seconds)

    attack_start = config.duration_seconds * 0.25
    attack_end = config.duration_seconds * 0.75

    for i in range(total_flows):
        attacker = rng.choice(attackers)
        ts = config.start_time + timedelta(
            seconds=rng.uniform(attack_start, attack_end)
        )

        # Login attempt
        flows.append({
            "timestamp": ts,
            "src_ip": attacker,
            "dst_ip": target,
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": int(rng.choice([22, 3389, 21])),  # SSH, RDP, FTP
            "protocol": 6,
            "flow_duration": float(rng.exponential(100000)),
            "tot_fwd_pkts": int(rng.integers(3, 15)),
            "tot_bwd_pkts": int(rng.integers(2, 10)),
            "totlen_fwd_pkts": float(rng.integers(200, 2000)),
            "totlen_bwd_pkts": float(rng.integers(100, 500)),
            "label": "BruteForce",
            "is_attack": 1,
        })

        # Response (brute force is somewhat symmetric at flow level)
        if rng.random() > config.asymmetry_level:
            flows.append({
                "timestamp": ts + timedelta(milliseconds=float(rng.uniform(10, 500))),
                "src_ip": target,
                "dst_ip": attacker,
                "src_port": int(rng.choice([22, 3389, 21])),
                "dst_port": int(rng.integers(1024, 65535)),
                "protocol": 6,
                "flow_duration": float(rng.exponential(50000)),
                "tot_fwd_pkts": int(rng.integers(2, 8)),
                "tot_bwd_pkts": int(rng.integers(1, 5)),
                "totlen_fwd_pkts": float(rng.integers(100, 500)),
                "totlen_bwd_pkts": float(rng.integers(50, 300)),
                "label": "BruteForce",
                "is_attack": 1,
            })

    return flows


def _generate_infiltration_flows(
    config: SimulationConfig,
    attacker: str,
    targets: list[str],
    rng: np.random.Generator,
) -> list[dict]:
    """Generate slow infiltration flows (APT-like, stealthy)."""
    flows = []
    # Infiltration: low volume, spread over entire duration
    total_flows = int(config.flows_per_second_attack * config.duration_seconds * 0.01)

    for i in range(max(total_flows, 10)):
        target = rng.choice(targets)
        ts = config.start_time + timedelta(
            seconds=rng.uniform(0, config.duration_seconds)
        )

        flows.append({
            "timestamp": ts,
            "src_ip": attacker,
            "dst_ip": target,
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": int(rng.choice([80, 443, 8443, 8080])),
            "protocol": 6,
            "flow_duration": float(rng.exponential(1000000)),
            "tot_fwd_pkts": int(rng.integers(5, 30)),
            "tot_bwd_pkts": int(rng.integers(3, 25)),
            "totlen_fwd_pkts": float(rng.integers(500, 5000)),
            "totlen_bwd_pkts": float(rng.integers(300, 4000)),
            "label": "Infiltration",
            "is_attack": 1,
        })

        # Infiltration mimics normal traffic, so responses are common
        if rng.random() > config.asymmetry_level:
            flows.append({
                "timestamp": ts + timedelta(milliseconds=float(rng.uniform(5, 200))),
                "src_ip": target,
                "dst_ip": attacker,
                "src_port": int(rng.choice([80, 443, 8443, 8080])),
                "dst_port": int(rng.integers(1024, 65535)),
                "protocol": 6,
                "flow_duration": float(rng.exponential(800000)),
                "tot_fwd_pkts": int(rng.integers(3, 20)),
                "tot_bwd_pkts": int(rng.integers(2, 15)),
                "totlen_fwd_pkts": float(rng.integers(300, 4000)),
                "totlen_bwd_pkts": float(rng.integers(200, 3000)),
                "label": "Infiltration",
                "is_attack": 1,
            })

    return flows


def _generate_botnet_flows(
    config: SimulationConfig,
    bots: list[str],
    c2_server: str,
    rng: np.random.Generator,
) -> list[dict]:
    """
    Generate botnet C2 beaconing flows.

    Unlike DDoS/scan/brute-force (concentrated in a burst window), beaconing is
    periodic and low-volume, spread across the *entire* simulation duration:
    each bot independently checks in with the C2 server on a jittered interval.
    """
    flows = []
    beacon_interval = 60.0  # seconds, typical C2 check-in period

    for bot in bots:
        jitter = rng.uniform(0.1, 0.4)
        t = rng.uniform(0, beacon_interval)

        while t < config.duration_seconds:
            ts = config.start_time + timedelta(seconds=t)

            # Beacon: small, low-volume check-in
            flows.append({
                "timestamp": ts,
                "src_ip": bot,
                "dst_ip": c2_server,
                "src_port": int(rng.integers(1024, 65535)),
                "dst_port": int(rng.choice([443, 8080, 53])),
                "protocol": 6,
                "flow_duration": float(rng.exponential(2000)),
                "tot_fwd_pkts": int(rng.integers(1, 5)),
                "tot_bwd_pkts": int(rng.integers(0, 2)),
                "totlen_fwd_pkts": float(rng.integers(40, 300)),
                "totlen_bwd_pkts": float(rng.integers(0, 100)),
                "label": "Botnet",
                "is_attack": 1,
            })

            # C2 command delivery, with probability (1 - asymmetry_level)
            if rng.random() > config.asymmetry_level:
                flows.append({
                    "timestamp": ts + timedelta(milliseconds=float(rng.uniform(5, 300))),
                    "src_ip": c2_server,
                    "dst_ip": bot,
                    "src_port": int(rng.choice([443, 8080, 53])),
                    "dst_port": int(rng.integers(1024, 65535)),
                    "protocol": 6,
                    "flow_duration": float(rng.exponential(1000)),
                    "tot_fwd_pkts": int(rng.integers(1, 3)),
                    "tot_bwd_pkts": 0,
                    "totlen_fwd_pkts": float(rng.integers(40, 500)),
                    "totlen_bwd_pkts": 0.0,
                    "label": "Botnet",
                    "is_attack": 1,
                })

            # Next beacon, jittered so bots don't stay in lockstep
            t += beacon_interval * (1 + rng.uniform(-jitter, jitter))

    return flows


_ATTACK_GENERATORS = {
    AttackType.DDOS:
        lambda cfg, atk, hosts, rng: _generate_ddos_flows(cfg, atk, hosts[0], rng),
    AttackType.PORT_SCAN:
        lambda cfg, atk, hosts, rng: _generate_port_scan_flows(cfg, atk, hosts, rng),
    AttackType.BRUTE_FORCE:
        lambda cfg, atk, hosts, rng: _generate_brute_force_flows(cfg, atk, hosts[0], rng),
    AttackType.INFILTRATION:
        lambda cfg, atk, hosts, rng: _generate_infiltration_flows(cfg, atk[0], hosts, rng),
    AttackType.BOTNET:
        lambda cfg, atk, hosts, rng: _generate_botnet_flows(cfg, atk, hosts[0], rng),
}


def run_simulation(config: SimulationConfig) -> pl.DataFrame:
    """
    Run a full simulation and return a DataFrame matching the ingest schema.

    Parameters
    ----------
    config : SimulationConfig
        Simulation parameters including asymmetry_level.

    Returns
    -------
    pl.DataFrame
        Flow data with same schema as ingest output.
    """
    rng = np.random.default_rng(config.seed)

    # Generate IP addresses
    benign_hosts = [f"10.0.0.{i}" for i in range(1, config.num_benign_hosts + 1)]
    attackers = [f"192.168.1.{i}" for i in range(1, config.num_attackers + 1)]

    # Generate benign traffic
    all_flows = _generate_benign_flows(config, benign_hosts, rng)

    # Generate attack traffic
    if config.attack_type != AttackType.BENIGN:
        generator = _ATTACK_GENERATORS.get(config.attack_type)
        if generator is None:
            implemented = sorted(t.name for t in _ATTACK_GENERATORS)
            raise NotImplementedError(
                f"No traffic generator implemented for AttackType.{config.attack_type.name}. "
                f"Implemented: {implemented}. Add a generator to _ATTACK_GENERATORS instead of "
                "silently falling back to benign-only traffic."
            )
        attack_flows = generator(config, attackers, benign_hosts, rng)
        all_flows.extend(attack_flows)

    # Convert to DataFrame
    df = pl.DataFrame(all_flows)
    df = df.sort("timestamp")

    return df


def sweep_asymmetry(
    levels: list[float] | None = None,
    attack_type: AttackType = AttackType.DDOS,
    **kwargs,
) -> dict[float, pl.DataFrame]:
    """
    Run simulations across a range of asymmetry levels.

    Useful for ablation studies (H3): finding the detection threshold.

    Parameters
    ----------
    levels : list[float]
        Asymmetry levels to sweep. Default: [0.0, 0.2, 0.4, 0.6, 0.8, 1.0].
    attack_type : AttackType
        Type of attack to simulate.

    Returns
    -------
    dict mapping asymmetry_level -> DataFrame
    """
    if levels is None:
        levels = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]

    results = {}
    for level in levels:
        cfg = SimulationConfig(
            asymmetry_level=level,
            attack_type=attack_type,
            **kwargs,
        )
        results[level] = run_simulation(cfg)

    return results
