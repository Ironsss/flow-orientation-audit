#!/usr/bin/env python3
"""P0.6 -- regression audit of the canonical-windowing instrument (P0.5).

Read-only. Observes and reports; changes no data and no results. It re-runs the
P0 sampling diagnostic through `src.audit.canonical` and checks the P0.5
invariants I1-I8, the paired-identity / immutable-ground-truth / anchor-shift /
conservation / nested-sampling gates, and the evidence-distribution contract.

It is the reproducible successor to the throwaway ``p0_audit.py`` used in P0:
same measurements, no session-local paths, seeds and configuration are CLI
arguments, and it depends only on committed project code.

Usage
-----
    python scripts/audit_canonical_windows.py
    python scripts/audit_canonical_windows.py --sampling-seed 11 --json out.json
    python scripts/audit_canonical_windows.py --rates 1 10 100 1000 --min-flows 10

The simulator path mirrors experiments/04_restriction.py: DDoS, asymmetry 0.8,
duration 2400 s, TRAIN = simulation seeds (1, 2), TEST = simulation seed 11.
The sampling seed is separate from every simulation seed (P0.5.7); pass
``--sampling-seed`` to change it, including to a simulation seed to reproduce
P0's original coupled draw.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.audit.canonical import (  # noqa: E402
    build_canonical_windowing,
    canonical_window_features,
)
from src.features import InfoTier  # noqa: E402
from src.restriction import sample, sample_mask  # noqa: E402
from src.simulator.agents import (  # noqa: E402
    AttackType,
    SimulationConfig,
    run_simulation,
)

DEFAULT_RATES = (1, 10, 100, 1000)


def simulate(sim_seed: int, duration: int) -> pl.DataFrame:
    return run_simulation(SimulationConfig(
        attack_type=AttackType.DDOS,
        asymmetry_level=0.8,
        duration_seconds=duration,
        seed=sim_seed,
    ))


def ledger_for_split(
    sim_seeds: list[int],
    *,
    duration: int,
    window_seconds: int,
    tau: float,
    min_flows: int,
    sampling_seed: int,
    rates: tuple[int, ...],
) -> dict:
    """Per-rate canonical ledgers for one split (one or more simulation seeds).

    Returns
    -------
    dict with:
      per_rate[rate] : pl.DataFrame, the concatenated canonical ledger across
                       the split's simulation seeds (a `sim_seed` column tags
                       provenance). Exactly len(sim_seeds) * n_windows rows.
      per_seed[seed] : dict(cw=CanonicalWindowing, per_rate={rate: ledger},
                       nested=bool)  -- kept for the invariant checks.
    """
    per_seed: dict[int, dict] = {}
    for s in sim_seeds:
        full = simulate(s, duration)
        cw = build_canonical_windowing(full, window_seconds=window_seconds, tau=tau)
        n = len(full)
        masks = {r: sample_mask(n, r, sampling_seed) for r in rates}
        nested = all(
            bool(np.all(masks[a] <= masks[b]))
            for a, b in zip(sorted(rates, reverse=True), sorted(rates, reverse=True)[1:])
        )
        pr, raw_offset = {}, {}
        full_min = int(full["timestamp"].dt.epoch("s").min())
        for r in rates:
            sdf = sample(full, rate=r, seed=sampling_seed)
            led = canonical_window_features(
                sdf, cw, tier=InfoTier.DIRECTIONAL, min_flows=min_flows
            )
            pr[r] = led
            raw_offset[r] = (
                int(sdf["timestamp"].dt.epoch("s").min()) - full_min if len(sdf) else 0
            )
        per_seed[s] = {
            "cw": cw, "per_rate": pr, "nested": nested, "n_flows": n,
            "raw_offset": raw_offset,
        }

    per_rate = {
        r: pl.concat([
            per_seed[s]["per_rate"][r].with_columns(pl.lit(s).alias("sim_seed"))
            for s in sim_seeds
        ])
        for r in rates
    }
    return {"per_rate": per_rate, "per_seed": per_seed, "sim_seeds": sim_seeds}


# ----------------------------------------------------------------- P0.6 tables
def p06_table(split: dict, rates: tuple[int, ...], min_flows: int) -> list[dict]:
    rows = []
    for r in rates:
        led = split["per_rate"][r]
        b = led.filter(pl.col("y_gt") == 0)
        a = led.filter(pl.col("y_gt") == 1)
        rows.append({
            "sampling": f"1:{r}",
            "canonical_benign": len(b),
            "canonical_attack": len(a),
            "empty_benign": int((b["n_observed"] == 0).sum()),
            "empty_attack": int((a["n_observed"] == 0).sum()),
            "under_benign": int(((b["n_observed"] > 0) & (b["n_observed"] < min_flows)).sum()),
            "under_attack": int(((a["n_observed"] > 0) & (a["n_observed"] < min_flows)).sum()),
            "output_benign": len(b),
            "output_attack": len(a),
        })
    return rows


def evidence_distribution(split: dict, rates: tuple[int, ...], min_flows: int) -> list[dict]:
    rows = []
    for r in rates:
        led = split["per_rate"][r]
        for cls, y in (("benign", 0), ("attack", 1)):
            sub = led.filter(pl.col("y_gt") == y)["n_observed"]
            rows.append({
                "sampling": f"1:{r}", "class": cls,
                "n_eq_0": int((sub == 0).sum()),
                "n_1_to_9": int(((sub > 0) & (sub < min_flows)).sum()),
                "n_ge_min": int((sub >= min_flows).sum()),
            })
    return rows


# ------------------------------------------------------------------- invariants
def check_invariants(split: dict, rates: tuple[int, ...], min_flows: int) -> dict:
    res: dict[str, dict] = {}
    ref_rate = rates[0]

    # per simulation seed, compare every rate's ledger against the 1:1 ledger
    i1 = i2 = i3 = i4 = i7 = i8 = True
    i5_has_empty = i6_has_under = False
    extra_total = missing_total = 0
    ev = []
    for s, d in split["per_seed"].items():
        cw = d["cw"]
        ref = d["per_rate"][ref_rate].sort("window_id")
        canonical_ids = set(cw.window_ids.tolist())
        for r in rates:
            led = d["per_rate"][r].sort("window_id")
            ids = set(led["window_id"].to_list())
            missing = canonical_ids - ids
            extra = ids - canonical_ids
            missing_total += len(missing)
            extra_total += len(extra)
            if missing or extra:
                i7 = False
            # I1 boundaries identical to 1:1
            if (led["window_start"].to_list() != ref["window_start"].to_list()
                    or led["window_end"].to_list() != ref["window_end"].to_list()):
                i1 = False
            # I2 identity == arithmetic on the frozen anchor, same at every rate
            expect_start = [cw.global_t0 + w * cw.window_seconds for w in led["window_id"]]
            if led["window_start"].to_list() != expect_start:
                i2 = False
            # I3 / I4 ground truth identical to 1:1
            if led["y_gt"].to_list() != ref["y_gt"].to_list():
                i3 = False
            if led["attack_ratio_gt"].to_list() != ref["attack_ratio_gt"].to_list():
                i4 = False
            # I8 the whole GT block is row-identical to 1:1
            gt_cols = ["window_id", "window_start", "window_end", "y_gt", "attack_ratio_gt"]
            if not led.select(gt_cols).equals(ref.select(gt_cols)):
                i8 = False
            if int((led["n_observed"] == 0).sum()) > 0:
                i5_has_empty = True
            if int(((led["n_observed"] > 0) & (led["n_observed"] < min_flows)).sum()) > 0:
                i6_has_under = True
            ev.append(f"seed {s} 1:{r}: {len(led)} rows, "
                      f"missing={len(missing)} extra={len(extra)}")

    # I5 / I6: windows persist despite zero / sub-min evidence. Verified by the
    # fact that every rate still has the full canonical row count (i7) AND that
    # some rate actually exercises the zero / sub-min case.
    i5 = i7 and i5_has_empty
    i6 = i7 and i6_has_under

    res["I1"] = {"pass": i1, "evidence": "window_start/end identical to 1:1 at every rate"}
    res["I2"] = {"pass": i2,
                 "evidence": "window_start == global_t0 + id*window_seconds at every rate"}
    res["I3"] = {"pass": i3, "evidence": "y_gt row-identical to 1:1 at every rate"}
    res["I4"] = {"pass": i4, "evidence": "attack_ratio_gt row-identical to 1:1 at every rate"}
    res["I5"] = {"pass": i5,
                 "evidence": f"empty windows present and still rows (exercised={i5_has_empty})"}
    res["I6"] = {"pass": i6,
                 "evidence": f"sub-min_flows windows still rows (exercised={i6_has_under})"}
    res["I7"] = {"pass": i7,
                 "evidence": f"missing IDs={missing_total}, extra IDs={extra_total} "
                             "over all rates/seeds"}
    res["I8"] = {"pass": i8,
                 "evidence": "per-rate GT block (id,start,end,y_gt,ratio_gt) equals 1:1"}
    res["_detail"] = ev
    return res


def paired_ids(split: dict, rates: tuple[int, ...]) -> bool:
    for d in split["per_seed"].values():
        sets = [set(d["per_rate"][r]["window_id"].to_list()) for r in rates]
        if any(x != sets[0] for x in sets):
            return False
    return True


def gt_mismatches(split: dict, rates: tuple[int, ...]) -> tuple[int, int]:
    label_mm = ratio_mm = 0
    for d in split["per_seed"].values():
        ref = d["per_rate"][rates[0]].sort("window_id")
        for r in rates[1:]:
            led = d["per_rate"][r].sort("window_id")
            label_mm += int((led["y_gt"] != ref["y_gt"]).sum())
            ratio_mm += int((led["attack_ratio_gt"] != ref["attack_ratio_gt"]).sum())
    return label_mm, ratio_mm


def anchor_shift_table(split: dict, rates: tuple[int, ...]) -> list[dict]:
    # By construction the instrument anchors on cw.global_t0, so the shift the
    # windowing sees is exactly 0 at every rate. We also report the raw offset
    # of the first surviving flow, to show that drift still exists in the data
    # but no longer touches the grid.
    rows = []
    for r in rates:
        raw = [d["raw_offset"][r] for d in split["per_seed"].values()]
        rows.append({
            "sampling": f"1:{r}",
            "anchor_shift_min": 0,
            "anchor_shift_max": 0,
            "raw_first_obs_offset_min_s": min(raw),
            "raw_first_obs_offset_max_s": max(raw),
        })
    return rows


def conservation_table(split: dict, rates: tuple[int, ...]) -> list[dict]:
    rows = []
    for r in rates:
        for s, d in split["per_seed"].items():
            cw = d["cw"]
            led = d["per_rate"][r]
            ids = set(led["window_id"].to_list())
            canonical_ids = set(cw.window_ids.tolist())
            rows.append({
                "sampling": f"1:{r}", "sim_seed": s,
                "total_windows": len(led),
                "attack_windows": int((led["y_gt"] == 1).sum()),
                "benign_windows": int((led["y_gt"] == 0).sum()),
                "missing_ids": len(canonical_ids - ids),
                "extra_ids": len(ids - canonical_ids),
            })
    return rows


def nested_sampling(split: dict) -> bool:
    return all(d["nested"] for d in split["per_seed"].values())


def representation_contract() -> list[dict]:
    return [
        {"state": "n_observed == 0",
         "topology": "0.0 sentinel (extractor's empty return)",
         "flow": "0.0 sentinel",
         "size": "0.0 sentinel (sz_nodes=sz_edges=0)",
         "window_preserved": "yes",
         "flags": "has_evidence=False, feature_available=False, attack_ratio_observed=NaN"},
        {"state": "0 < n_observed < min_flows",
         "topology": "computed from the rows present",
         "flow": "computed from the rows present",
         "size": "computed from the rows present",
         "window_preserved": "yes",
         "flags": "has_evidence=True, feature_available=False, attack_ratio_observed=mean(obs)"},
    ]


# ------------------------------------------------------------------------ print
def _print_table(title: str, rows: list[dict], cols: list[str]) -> None:
    print(f"\n{title}")
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print(" | ".join(c.rjust(widths[c]) for c in cols))
    print("-+-".join("-" * widths[c] for c in cols))
    for r in rows:
        print(" | ".join(str(r[c]).rjust(widths[c]) for c in cols))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--window-seconds", type=int, default=60)
    ap.add_argument("--tau", type=float, default=0.01)
    ap.add_argument("--min-flows", type=int, default=10)
    ap.add_argument("--duration", type=int, default=2400)
    ap.add_argument("--train-sim-seeds", type=int, nargs="+", default=[1, 2])
    ap.add_argument("--test-sim-seed", type=int, default=11)
    ap.add_argument("--sampling-seed", type=int, default=20260901,
                    help="separate from every simulation seed (P0.5.7)")
    ap.add_argument("--rates", type=int, nargs="+", default=list(DEFAULT_RATES))
    ap.add_argument("--json", type=Path,
                    default=REPO_ROOT / "results/metrics/p0_6_regression_audit.json")
    args = ap.parse_args()
    rates = tuple(args.rates)
    mf = args.min_flows

    cfg = dict(
        duration=args.duration, window_seconds=args.window_seconds, tau=args.tau,
        min_flows=mf, sampling_seed=args.sampling_seed, rates=list(rates),
    )
    splits = {
        "TRAIN": ledger_for_split(args.train_sim_seeds, **cfg),
        "TEST": ledger_for_split([args.test_sim_seed], **cfg),
    }

    print("=" * 88)
    print("P0.6 REGRESSION AUDIT -- canonical windowing instrument")
    print("=" * 88)
    print(f"window_seconds={args.window_seconds}  tau={args.tau}  min_flows={mf}  "
          f"duration={args.duration}")
    print(f"TRAIN simulation seeds={args.train_sim_seeds}  "
          f"TEST simulation seed={args.test_sim_seed}")
    print(f"sampling_seed={args.sampling_seed}  (independent of every simulation seed)")

    out: dict = {"config": cfg, "splits": {}}

    for name, split in splits.items():
        tbl = p06_table(split, rates, mf)
        _print_table(
            f"[{name}] P0.6 main table  (classes counted by y_gt)",
            tbl,
            ["sampling", "canonical_benign", "canonical_attack", "empty_benign",
             "empty_attack", "under_benign", "under_attack", "output_benign", "output_attack"],
        )
        ev = evidence_distribution(split, rates, mf)
        _print_table(f"[{name}] evidence distribution  (n_observed buckets)", ev,
                     ["sampling", "class", "n_eq_0", "n_1_to_9", "n_ge_min"])
        cons = conservation_table(split, rates)
        _print_table(f"[{name}] conservation", cons,
                     ["sampling", "sim_seed", "total_windows", "attack_windows",
                      "benign_windows", "missing_ids", "extra_ids"])
        anch = anchor_shift_table(split, rates)
        _print_table(f"[{name}] anchor shift", anch,
                     ["sampling", "anchor_shift_min", "anchor_shift_max",
                      "raw_first_obs_offset_min_s", "raw_first_obs_offset_max_s"])

        inv = check_invariants(split, rates, mf)
        label_mm, ratio_mm = gt_mismatches(split, rates)
        paired = paired_ids(split, rates)
        nested = nested_sampling(split)
        print(f"\n[{name}] paired window IDs across rates : {'PASS' if paired else 'FAIL'}")
        print(f"[{name}] immutable ground truth        : "
              f"label mismatches={label_mm}  attack_ratio_gt mismatches={ratio_mm}")
        print(f"[{name}] nested sampling S1000<=S100<=S10<=S1 : {'PASS' if nested else 'FAIL'}")
        _print_table(f"[{name}] invariants I1-I8",
                     [{"invariant": k, "result": "PASS" if v["pass"] else "FAIL",
                       "evidence": v["evidence"]}
                      for k, v in inv.items() if k.startswith("I")],
                     ["invariant", "result", "evidence"])

        out["splits"][name] = {
            "p06_table": tbl, "evidence_distribution": ev, "conservation": cons,
            "anchor_shift": anch,
            "invariants": {k: v for k, v in inv.items() if k.startswith("I")},
            "paired_window_ids": paired,
            "label_mismatches": label_mm, "attack_ratio_gt_mismatches": ratio_mm,
            "nested_sampling": nested,
        }

    _print_table("representation contract (M)", representation_contract(),
                 ["state", "topology", "flow", "size", "window_preserved", "flags"])

    all_inv_pass = all(
        v["pass"]
        for sp in out["splits"].values()
        for v in sp["invariants"].values()
    )
    gates_pass = all_inv_pass and all(
        sp["paired_window_ids"] and sp["label_mismatches"] == 0
        and sp["attack_ratio_gt_mismatches"] == 0 and sp["nested_sampling"]
        for sp in out["splits"].values()
    )
    out["gate"] = "PASS" if gates_pass else "FAIL"

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nJSON written to {args.json.relative_to(REPO_ROOT)}")
    print("\n" + "=" * 88)
    if gates_pass:
        print("P0.5/P0.6 GATE: PASS -- I1-I8 satisfied. Ready for review before P1.")
    else:
        print("P0.5/P0.6 GATE: FAIL -- do not proceed to P1.")
    print("=" * 88)
    return 0 if gates_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
