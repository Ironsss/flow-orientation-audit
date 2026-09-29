"""P1 -- tests for the generator-audit primitives (src/audit/generator_audit.py).

These pin that the AUDITOR measures correctly, not that the generator
produces any particular number -- P1's brief is diagnostic, not corrective,
and these tests must never be tuned to make the simulator look a particular
way (see CLAUDE.md and docs/metodologia/).
"""

from __future__ import annotations

import numpy as np
import polars as pl

from src.audit.canonical import build_canonical_windowing
from src.audit.generator_audit import (
    attack_phase_labels,
    background_flow_stats,
    window_generative_stats,
)

WINDOW_SECONDS = 60
TAU = 0.01


def _trace(rows: list[dict]) -> pl.DataFrame:
    """Build a flow frame in the loader/simulator schema from plain dicts,
    with a numpy datetime64 timestamp column (list-of-scalars would infer
    Object and fail to sort -- same fix as tests/test_canonical_windows.py)."""
    base = np.datetime64("2024-01-01T00:00:00")
    ts = np.array(
        [base + np.timedelta64(int(r["t"]), "s") for r in rows], dtype="datetime64[us]"
    )
    return pl.DataFrame({
        "timestamp": ts,
        "src_ip": [r["src"] for r in rows],
        "dst_ip": [r["dst"] for r in rows],
        "is_attack": [r["attack"] for r in rows],
        "totlen_fwd_pkts": [float(r.get("fwd_b", 100.0)) for r in rows],
        "totlen_bwd_pkts": [float(r.get("bwd_b", 50.0)) for r in rows],
        "tot_fwd_pkts": [int(r.get("fwd_p", 1)) for r in rows],
        "tot_bwd_pkts": [int(r.get("bwd_p", 1)) for r in rows],
        "flow_duration": [float(r.get("dur", 1000.0)) for r in rows],
    }).sort("timestamp")


def _star_window(t0: int, n: int, center: str, leaves: list[str], attack: int) -> list[dict]:
    """`n` flows leaf -> center, one per leaf cycling, all inside [t0, t0+60)."""
    out = []
    for i in range(n):
        out.append({
            "t": t0 + (i % 55), "src": leaves[i % len(leaves)], "dst": center,
            "attack": attack, "fwd_b": 100.0 + i, "bwd_b": 10.0,
        })
    return out


def test_window_generative_stats_matches_hand_counted_structure():
    """A 15-flow star into one center, all in window 0: n_nodes, n_edges,
    fan_in, reciprocity should match hand-counted values exactly."""
    leaves = [f"h{i}" for i in range(5)]
    rows = _star_window(0, 15, "victim", leaves, attack=1)
    full = _trace(rows)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    stats = window_generative_stats(full, cw)

    assert len(stats) == 1
    row = stats.row(0, named=True)
    assert row["n_flows"] == 15
    assert row["n_nodes"] == 6         # 5 leaves + 1 center
    assert row["n_src_nodes"] == 5
    assert row["n_dst_nodes"] == 1
    assert row["n_edges"] == 5         # 5 distinct (leaf, victim) pairs
    assert row["fan_in_max"] == 5      # victim receives from all 5 leaves
    assert row["fan_out_max"] == 1     # every leaf only ever sends to victim
    assert row["reciprocity"] == 0.0   # no leaf receives back from victim
    assert row["flows_per_edge"] == 3.0  # 15 flows / 5 edges
    assert row["y_gt"] == 1
    assert row["attack_ratio_gt"] == 1.0


def test_reciprocal_pairs_give_full_reciprocity():
    rows = (
        _star_window(0, 10, "a", ["b"], attack=0)  # b -> a, 10 flows
        + [{"t": 5 + i, "src": "a", "dst": "b", "attack": 0} for i in range(10)]  # a -> b
    )
    full = _trace(rows)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    stats = window_generative_stats(full, cw)
    row = stats.row(0, named=True)
    assert row["n_edges"] == 2          # (a,b) and (b,a)
    assert row["reciprocity"] == 1.0


def test_window_generative_stats_covers_every_canonical_window_including_gaps():
    """Window 1 (t in [60,120)) has zero rows in this trace; the canonical
    grid must still include only windows the FULL trace populated (0 and 2),
    and every row in the output must have n_flows == n_flows_gt at rate 1:1."""
    rows = (
        _star_window(0, 12, "v", ["a", "b"], attack=0)
        + _star_window(120, 12, "v", ["a", "b"], attack=0)
    )
    full = _trace(rows)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    stats = window_generative_stats(full, cw)
    assert set(stats["window_id"].to_list()) == {0, 2}
    assert stats["n_flows"].to_list() == stats["n_flows_gt"].to_list()


def test_attack_phase_labels_pre_attack_post():
    stats = pl.DataFrame({
        "window_id": [0, 1, 2, 3, 4],
        "y_gt": [0, 0, 1, 1, 0],
    })
    labeled = attack_phase_labels(stats)
    assert labeled["phase"].to_list() == [
        "pre-attack", "pre-attack", "attack", "attack", "post-attack",
    ]


def test_attack_phase_labels_all_benign_is_all_pre_attack():
    stats = pl.DataFrame({"window_id": [0, 1, 2], "y_gt": [0, 0, 0]})
    labeled = attack_phase_labels(stats)
    assert labeled["phase"].to_list() == ["pre-attack"] * 3


def test_background_flow_stats_measures_full_saturation_and_uniformity():
    """4 hosts, every ordered pair present exactly once, uniform byte size."""
    hosts = ["h0", "h1", "h2", "h3"]
    rows = []
    t = 0
    for a in hosts:
        for b in hosts:
            if a == b:
                continue
            rows.append({"t": t, "src": a, "dst": b, "attack": 0, "fwd_b": 500.0, "bwd_b": 500.0})
            t += 1
    full = _trace(rows)
    stats = background_flow_stats(full)
    assert stats["n_benign_flows"] == 12          # 4*3 ordered pairs
    assert stats["n_hosts_seen"] == 4
    assert stats["n_unique_pairs"] == 12
    assert stats["n_possible_ordered_pairs"] == 12
    assert stats["pair_repeat_count"]["fraction_pairs_seen_once"] == 1.0
    assert stats["byte_size_distribution"]["mean"] == 500.0
    assert stats["byte_size_distribution"]["std"] == 0.0


def test_background_flow_stats_ignores_attack_flows():
    rows = _star_window(0, 5, "v", ["a"], attack=0) + _star_window(0, 5, "v", ["x"], attack=1)
    full = _trace(rows)
    stats = background_flow_stats(full)
    assert stats["n_benign_flows"] == 5
    assert stats["n_hosts_seen"] == 2  # a, v -- not the attacker x


def test_window_generative_stats_is_read_only_and_deterministic():
    """Calling twice on the same inputs gives identical output -- no hidden
    state, no mutation of the canonical grid (P0.5 already freezes it)."""
    leaves = [f"h{i}" for i in range(5)]
    rows = _star_window(0, 15, "v", leaves, attack=0)
    full = _trace(rows)
    cw = build_canonical_windowing(full, window_seconds=WINDOW_SECONDS, tau=TAU)
    a = window_generative_stats(full, cw)
    b = window_generative_stats(full, cw)
    assert a.equals(b)
    # the frozen ground-truth arrays are unaffected by having been read
    assert cw.window_ids.flags.writeable is False
