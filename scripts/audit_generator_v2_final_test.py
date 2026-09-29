#!/usr/bin/env python3
"""Final Test -- AC10 (sample size, no escape clause), per
docs/methodology/P2_FINAL_FREEZE.md.

Builds the frozen N_final runs (21 Main = 7 low + 7 medium + 7 high, 28
Low-signal; seeds 50001-50058, disjoint from Development/Validation) and
checks, per stratum, at full information (rate=1): >=250 benign windows AND
>=250 attack windows. "No 'or maximum achievable' clause" (SS10) -- if this
fails, it is reported as a finding, not patched by adding more runs to this
same frozen set (SS11).

Usage
-----
    .venv/Scripts/python.exe scripts/audit_generator_v2_final_test.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.audit.canonical import build_canonical_windowing  # noqa: E402
from src.simulator.v2 import (  # noqa: E402
    WINDOW_SECONDS,
    SeverityRegime,
    SimulationConfigV2,
    Stratum,
    run_simulation_v2,
    stratum_of,
)

TAU = 0.01
MIN_WINDOWS_PER_CLASS_FINAL = 250  # AC10

#: Final Test seed lists, frozen in P2_FINAL_FREEZE.md. Disjoint from
#: Development (20001-20040), burned Validation v1 (30001-30045), and
#: passing Validation v2 (40001-40045).
FINAL_SEEDS: dict[SeverityRegime, tuple[int, ...]] = {
    SeverityRegime.LOW: tuple(range(50001, 50008)),
    SeverityRegime.MEDIUM: tuple(range(50011, 50018)),
    SeverityRegime.HIGH: tuple(range(50021, 50028)),
    SeverityRegime.LOW_SIGNAL: tuple(range(50031, 50059)),
}
assert len(FINAL_SEEDS[SeverityRegime.LOW]) == 7
assert len(FINAL_SEEDS[SeverityRegime.MEDIUM]) == 7
assert len(FINAL_SEEDS[SeverityRegime.HIGH]) == 7
assert len(FINAL_SEEDS[SeverityRegime.LOW_SIGNAL]) == 28
_ALL_PRIOR_SEEDS = set(range(20001, 20041)) | set(range(30001, 30046)) | set(range(40001, 40046))
assert not set().union(*FINAL_SEEDS.values()) & _ALL_PRIOR_SEEDS, (
    "Final Test seeds must be disjoint from every prior seed block (SS12)"
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--json", type=Path, default=REPO_ROOT / "results/metrics/p2_final_test_ac10.json",
    )
    args = ap.parse_args()

    print("=" * 90)
    print("FINAL TEST -- AC10 sample-size check (N_final runs, full information)")
    print("=" * 90)

    by_stratum: dict[Stratum, dict[str, int]] = {
        Stratum.MAIN: {"benign": 0, "attack": 0, "n_runs": 0},
        Stratum.LOW_SIGNAL: {"benign": 0, "attack": 0, "n_runs": 0},
    }
    rows = []
    for regime, seeds in FINAL_SEEDS.items():
        stratum = stratum_of(regime)
        for seed in seeds:
            print(f"simulating regime={regime.value} seed={seed} ...")
            df = run_simulation_v2(SimulationConfigV2(simulation_seed=seed, severity_regime=regime))
            cw = build_canonical_windowing(df, window_seconds=WINDOW_SECONDS, tau=TAU)
            nb, na = int((cw.y_gt == 0).sum()), int((cw.y_gt == 1).sum())
            by_stratum[stratum]["benign"] += nb
            by_stratum[stratum]["attack"] += na
            by_stratum[stratum]["n_runs"] += 1
            rows.append({
                "seed": seed, "regime": regime.value, "stratum": stratum.value,
                "benign_windows": nb, "attack_windows": na,
            })

    print(f"\n{'stratum':>12}{'n_runs':>8}{'benign':>10}{'attack':>10}{'verdict':>10}")
    print("-" * 50)
    verdicts = {}
    for stratum, d in by_stratum.items():
        ok = (
            d["benign"] >= MIN_WINDOWS_PER_CLASS_FINAL
            and d["attack"] >= MIN_WINDOWS_PER_CLASS_FINAL
        )
        verdicts[stratum.value] = "PASS" if ok else "FAIL"
        print(f"{stratum.value:>12}{d['n_runs']:>8}{d['benign']:>10}{d['attack']:>10}"
              f"{verdicts[stratum.value]:>10}")

    overall = "PASS" if all(v == "PASS" for v in verdicts.values()) else "FAIL"
    print(f"\nAC10 overall: {overall}")

    out = {
        "rows": rows,
        "by_stratum": {s.value: d for s, d in by_stratum.items()},
        "min_windows_per_class": MIN_WINDOWS_PER_CLASS_FINAL,
        "verdicts": verdicts, "overall": overall,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nJSON written to {args.json}")
    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
