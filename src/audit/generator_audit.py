"""P1 -- generator audit primitives (read-only, diagnostic only).

Answers one question: does the current simulator (`src.simulator.agents`)
contain signals that separate benign from attack traffic *independent of the
asymmetry representation the project studies* -- raw volume, graph size,
degree structure, or the position of a window in time? None of what lives
here is a detector feature. It exists to be looked at, not to be fed to a
model; `window_generative_stats` deliberately does not reuse
`src.features.extractors` (which exists to be fed to a model) even though
some quantities overlap, so the two purposes never blur.

Everything is computed on the canonical window grid (`src.audit.canonical`),
never on the pre-P0.5 `window_features` grid, so a window here is the same
unit of analysis P0.5 froze: `window_id` -> `(window_start, window_end,
attack_ratio_gt, y_gt)` fixed from the full trace before any restriction.

Nothing here mutates the simulator, the restriction operators, or the
detector features. It only reads a flow frame and a `CanonicalWindowing` and
reports.
"""

from __future__ import annotations

import numpy as np
import polars as pl

from src.audit.canonical import CanonicalWindowing, map_to_canonical_window

__all__ = [
    "GENERATIVE_COLUMNS",
    "attack_phase_labels",
    "background_flow_stats",
    "window_generative_stats",
]

#: Columns this module adds beyond the canonical ledger (window_id,
#: window_start, window_end, attack_ratio_gt, y_gt, n_flows_gt, n_observed).
#: Kept as a name so the audit script and its tests agree on the contract.
GENERATIVE_COLUMNS = (
    "n_flows", "total_bytes", "fwd_bytes", "bwd_bytes",
    "total_pkts", "fwd_pkts", "bwd_pkts",
    "n_nodes", "n_edges", "n_src_nodes", "n_dst_nodes", "unique_peers",
    "mean_peers_per_src", "mean_peers_per_dst",
    "fan_out_max", "fan_in_max", "reciprocity", "flows_per_edge",
)


def _degree_stats(src: np.ndarray, dst: np.ndarray) -> dict[str, float]:
    """Raw (non-scale-invariant) graph-structure quantities for one window.

    Deliberately raw counts, not the ratios `src.features.extractors` computes
    -- P1 is auditing whether raw size/degree already separates the classes,
    so normalizing it away here would hide the thing being measured.
    """
    if src.size == 0:
        return {
            "n_nodes": 0, "n_edges": 0, "n_src_nodes": 0, "n_dst_nodes": 0,
            "unique_peers": 0, "mean_peers_per_src": 0.0, "mean_peers_per_dst": 0.0,
            "fan_out_max": 0, "fan_in_max": 0, "reciprocity": 0.0, "flows_per_edge": 0.0,
        }
    edges = set(zip(src.tolist(), dst.tolist()))
    src_set, dst_set = set(src.tolist()), set(dst.tolist())
    nodes = src_set | dst_set

    out_peers: dict[object, set] = {}
    in_peers: dict[object, set] = {}
    for a, b in edges:
        out_peers.setdefault(a, set()).add(b)
        in_peers.setdefault(b, set()).add(a)

    fan_out_max = max((len(v) for v in out_peers.values()), default=0)
    fan_in_max = max((len(v) for v in in_peers.values()), default=0)
    reciprocal = sum(1 for a, b in edges if (b, a) in edges)
    n_edges = len(edges)

    return {
        "n_nodes": len(nodes),
        "n_edges": n_edges,
        "n_src_nodes": len(src_set),
        "n_dst_nodes": len(dst_set),
        "unique_peers": len(nodes),
        "mean_peers_per_src": float(np.mean([len(v) for v in out_peers.values()])),
        "mean_peers_per_dst": float(np.mean([len(v) for v in in_peers.values()])),
        "fan_out_max": fan_out_max,
        "fan_in_max": fan_in_max,
        "reciprocity": reciprocal / n_edges if n_edges else 0.0,
        "flows_per_edge": src.size / n_edges if n_edges else 0.0,
    }


def window_generative_stats(
    sampled_df: pl.DataFrame,
    cw: CanonicalWindowing,
) -> pl.DataFrame:
    """One row per canonical window: raw volume + structure + ground truth.

    Same anchoring contract as `canonical_window_features` (frozen
    `cw.global_t0`, every canonical window emitted, sampling only changes what
    is observed) but exposes the raw generative quantities P1 audits instead
    of the scale-invariant features the detector uses. At `rate=1` (P1's
    primary analysis) every canonical window has `n_flows_gt` observations, so
    no window is empty here -- P0.5's no-evidence handling is not exercised by
    this function and is out of scope for P1 (see P1.16).
    """
    required = {"timestamp", "src_ip", "dst_ip", "is_attack",
                "totlen_fwd_pkts", "totlen_bwd_pkts"}
    missing = required - set(sampled_df.columns)
    if missing:
        raise ValueError(f"frame is missing required columns: {sorted(missing)}")
    has_pkts = {"tot_fwd_pkts", "tot_bwd_pkts"} <= set(sampled_df.columns)

    wid = map_to_canonical_window(sampled_df, cw)
    src = sampled_df["src_ip"].to_numpy()
    dst = sampled_df["dst_ip"].to_numpy()
    fwd_b = sampled_df["totlen_fwd_pkts"].to_numpy()
    bwd_b = sampled_df["totlen_bwd_pkts"].to_numpy()
    if has_pkts:
        fwd_p = sampled_df["tot_fwd_pkts"].to_numpy()
        bwd_p = sampled_df["tot_bwd_pkts"].to_numpy()

    by_window: dict[int, np.ndarray] = {}
    if wid.size:
        canonical = wid >= 0
        row_idx = np.nonzero(canonical)[0]
        wid_can = wid[canonical]
        order = np.argsort(wid_can, kind="stable")
        wid_sorted = wid_can[order]
        rows_sorted = row_idx[order]
        if wid_sorted.size:
            uniq, starts = np.unique(wid_sorted, return_index=True)
            ends = np.append(starts[1:], wid_sorted.size)
            for w, a, b in zip(uniq, starts, ends):
                by_window[int(w)] = rows_sorted[a:b]

    records = []
    for i, w in enumerate(cw.window_ids):
        idx = by_window.get(int(w))
        n = 0 if idx is None else int(idx.size)
        rec: dict[str, float] = {
            "window_id": int(w),
            "window_start": int(cw.window_start[i]),
            "window_end": int(cw.window_end[i]),
            "attack_ratio_gt": float(cw.attack_ratio_gt[i]),
            "y_gt": int(cw.y_gt[i]),
            "n_flows_gt": int(cw.n_flows_gt[i]),
            "n_flows": n,
            "has_evidence": n > 0,
        }
        if n == 0:
            rec.update(total_bytes=0.0, fwd_bytes=0.0, bwd_bytes=0.0,
                       total_pkts=0.0, fwd_pkts=0.0, bwd_pkts=0.0)
            rec.update(_degree_stats(np.array([]), np.array([])))
        else:
            fb, bb = fwd_b[idx], bwd_b[idx]
            rec.update(
                total_bytes=float(fb.sum() + bb.sum()),
                fwd_bytes=float(fb.sum()), bwd_bytes=float(bb.sum()),
            )
            if has_pkts:
                fp, bp = fwd_p[idx], bwd_p[idx]
                rec.update(total_pkts=float(fp.sum() + bp.sum()),
                           fwd_pkts=float(fp.sum()), bwd_pkts=float(bp.sum()))
            else:
                rec.update(total_pkts=float("nan"), fwd_pkts=float("nan"),
                           bwd_pkts=float("nan"))
            rec.update(_degree_stats(src[idx], dst[idx]))
        records.append(rec)

    return pl.DataFrame(records)


def attack_phase_labels(stats: pl.DataFrame) -> pl.DataFrame:
    """Label each canonical window pre-attack / attack / post-attack.

    Measured from the emitted `y_gt` sequence, not from simulator config: the
    "attack" phase is every window with `y_gt == 1`; "pre-attack" is every
    window before the first such window; "post-attack" every window after the
    last one. If `y_gt == 1` windows are non-contiguous, `attack` still covers
    every one of them and the function does not assume a single block --
    contiguity is checked separately (see `audit_generator_p1.py`).
    """
    stats = stats.sort("window_id")
    attack_ids = stats.filter(pl.col("y_gt") == 1)["window_id"]
    if len(attack_ids) == 0:
        phase = ["pre-attack"] * len(stats)
        return stats.with_columns(pl.Series("phase", phase))
    lo, hi = int(attack_ids.min()), int(attack_ids.max())
    phase = [
        "attack" if y == 1 else ("pre-attack" if wid < lo else
                                  "post-attack" if wid > hi else "gap-within-attack")
        for wid, y in zip(stats["window_id"], stats["y_gt"])
    ]
    return stats.with_columns(pl.Series("phase", phase))


def background_flow_stats(full_df: pl.DataFrame) -> dict:
    """Descriptive statistics of BENIGN flows only, over the whole trace.

    Flow-level, not windowed -- P1.12 asks what the generator's background
    traffic looks like structurally, which is a property of the whole run,
    not of any one 60s slice. Everything here is measured from the frame that
    `run_simulation` actually returned, never assumed from `SimulationConfig`.
    """
    b = full_df.filter(pl.col("is_attack") == 0)
    if len(b) == 0:
        return {"n_benign_flows": 0}

    src = b["src_ip"].to_numpy()
    dst = b["dst_ip"].to_numpy()
    hosts, host_counts = np.unique(np.concatenate([src, dst]), return_counts=True)
    src_counts = dict(zip(*np.unique(src, return_counts=True)))
    peers_per_host = {}
    for h in hosts:
        as_src = set(dst[src == h].tolist())
        as_dst = set(src[dst == h].tolist())
        peers_per_host[h] = len(as_src | as_dst)
    peer_counts = np.array(list(peers_per_host.values()))

    pairs = list(zip(src.tolist(), dst.tolist()))
    pair_counts = np.array(list(_count(pairs).values()))
    edges = set(pairs)
    reciprocal = sum(1 for a, b_ in edges if (b_, a) in edges)

    fwd = b["totlen_fwd_pkts"].to_numpy()
    bwd = b["totlen_bwd_pkts"].to_numpy()
    all_bytes = np.concatenate([fwd, bwd])
    dur = b["flow_duration"].to_numpy() if "flow_duration" in b.columns else None
    ts = b["timestamp"].dt.epoch("s").to_numpy()
    t0, t1 = int(ts.min()), int(ts.max())
    n_bins = max(int((t1 - t0) / 60), 1)
    per_min_counts = np.bincount(((ts - t0) // 60).astype(int), minlength=n_bins)

    dports = b["dst_port"].to_numpy() if "dst_port" in b.columns else None

    def _q(a, *ps):
        return {f"p{p}": float(np.percentile(a, p)) for p in ps}

    out = {
        "n_benign_flows": int(len(b)),
        "n_hosts_seen": int(len(hosts)),
        "host_flow_count": {
            "mean": float(host_counts.mean()), "std": float(host_counts.std()),
            "min": int(host_counts.min()), "max": int(host_counts.max()),
            "cv": float(host_counts.std() / host_counts.mean()) if host_counts.mean() else 0.0,
        },
        "src_host_selection_uniform_check": {
            "n_hosts_as_src": len(src_counts),
            "min": int(min(src_counts.values())), "max": int(max(src_counts.values())),
        },
        "peers_per_host": {
            "mean": float(peer_counts.mean()), "std": float(peer_counts.std()),
            "min": int(peer_counts.min()), "max": int(peer_counts.max()),
            **_q(peer_counts, 10, 50, 90),
        },
        "n_unique_pairs": int(len(edges)),
        "n_possible_ordered_pairs": int(len(hosts) * (len(hosts) - 1)),
        "pair_repeat_count": {
            "mean": float(pair_counts.mean()), "max": int(pair_counts.max()),
            "fraction_pairs_seen_once": float((pair_counts == 1).mean()),
        },
        "reciprocity_fraction_of_pairs": reciprocal / len(edges) if edges else 0.0,
        "byte_size_distribution": {
            "mean": float(all_bytes.mean()), "std": float(all_bytes.std()),
            "min": float(all_bytes.min()), "max": float(all_bytes.max()),
            **_q(all_bytes, 10, 50, 90, 99),
            "max_over_mean": float(all_bytes.max() / all_bytes.mean()),
            "top1pct_share_of_total_bytes": float(
                np.sort(all_bytes)[-max(int(0.01 * all_bytes.size), 1):].sum()
                / all_bytes.sum()
            ),
        },
        "fwd_bwd_byte_ratio": {
            "mean_fwd_over_bwd": float((fwd.sum()) / (bwd.sum())) if bwd.sum() else float("nan"),
        },
        "flows_per_60s_bin": {
            "mean": float(per_min_counts.mean()), "std": float(per_min_counts.std()),
            "cv": float(per_min_counts.std() / per_min_counts.mean())
            if per_min_counts.mean() else 0.0,
            "min": int(per_min_counts.min()), "max": int(per_min_counts.max()),
        },
        "distinct_dst_ports": int(len(set(dports.tolist()))) if dports is not None else None,
    }
    if dur is not None:
        out["flow_duration_us"] = {
            "mean": float(dur.mean()), "std": float(dur.std()),
            **_q(dur, 50, 90, 99),
            "max_over_mean": float(dur.max() / dur.mean()) if dur.mean() else float("nan"),
        }
    return out


def _count(items: list) -> dict:
    out: dict = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return out
