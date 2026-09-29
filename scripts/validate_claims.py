#!/usr/bin/env python3
"""
Re-derive the repository's headline numbers on this machine.

Every claim below was produced by running code in a remote session. This script
re-runs the same computations locally and compares against the recorded values,
so a fresh clone can establish that the documented findings reproduce on
different hardware before anyone builds on them.

Claims checked, with where each is asserted:

  C1  A_dir is flat across the asymmetry sweep      docs/review/, docs/replanteamiento/
  C2  per-flow asymmetry separates attacks          docs/replanteamiento/
  C3  24 of 49 CLASSIC_FEATURES are directional     docs/protocolo/, README
  C4  permutation importance collapses on copies    docs/protocolo/
  C5  SHAP group-sum survives, permutation's does not   docs/protocolo/
  C6  A_ent saturates at -ln(eps) = 23.0259         docs/review/ finding 1.5
  C7  single-edge graphs no longer crash            docs/review/ finding 2.1

Tolerances are deliberately loose: the point is that the phenomenon reproduces,
not that a stochastic pipeline returns bit-identical figures. Where a claim is
directional ("collapses", "stays flat") the assertion is on the direction and
order of magnitude, not the digits.

Usage
-----
    python scripts/validate_claims.py            # C3..C7, about a minute
    python scripts/validate_claims.py --full     # adds C1, C2; several minutes

Exit code is the number of failed claims.
"""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

GREEN, RED, YELLOW, BLUE, BOLD, NC = (
    "\033[0;32m", "\033[0;31m", "\033[1;33m", "\033[0;34m", "\033[1m", "\033[0m",
)

_results: list[tuple[str, bool, str]] = []


def check(claim: str, passed: bool, detail: str) -> None:
    tag = f"{GREEN}[REPRODUCED]{NC}" if passed else f"{RED}[DIVERGED]{NC}  "
    print(f"{tag} {claim}\n             {detail}")
    _results.append((claim, passed, detail))


def header(msg: str) -> None:
    print(f"\n{BOLD}{msg}{NC}\n{'-' * len(msg)}")


# --------------------------------------------------------------------------- C3
def claim_directional_features() -> None:
    from src.ingest.loader import CLASSIC_FEATURES

    directional = [c for c in CLASSIC_FEATURES if "fwd" in c or "bwd" in c]
    n = len(directional)
    check(
        "C3  24/49 CLASSIC_FEATURES are directional",
        n == 24 and len(CLASSIC_FEATURES) == 49,
        f"found {n}/{len(CLASSIC_FEATURES)} directional (documented: 24/49)",
    )


# --------------------------------------------------------------------------- C6
def claim_entropic_ceiling() -> None:
    import torch
    from torch_geometric.data import Data

    from src.iag.index import entropic_asymmetry

    g = Data(
        edge_index=torch.tensor([[0], [1]]), edge_attr=torch.ones(1, 1), num_nodes=2
    )
    value = entropic_asymmetry(g)
    expected = -np.log(1e-10)
    check(
        "C6  A_ent saturates at -ln(eps) = 23.0259",
        abs(value - expected) < 1e-6,
        f"single-edge graph gives {value:.6f} (expected {expected:.6f})",
    )


# --------------------------------------------------------------------------- C7
def claim_single_edge_fixed() -> None:
    import torch
    from torch_geometric.data import Data

    from src.iag.index import compute_iag

    try:
        r = compute_iag(
            Data(edge_index=torch.tensor([[0], [1]]), edge_attr=torch.ones(1, 1), num_nodes=2)
        )
        passed = bool(np.isfinite(r["iag_combined"]))
        detail = f"compute_iag returned {r['iag_combined']:.4f}"
    except Exception as exc:  # noqa: BLE001
        passed, detail = False, f"still raises {type(exc).__name__}: {exc}"
    check("C7  single-edge graphs no longer crash", passed, detail)


# ----------------------------------------------------------------------- C4, C5
def _redundant_dataset(n=4000, imbalance=0.05, n_copies=3, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, 10))
    logit = 2.5 * X[:, 0] + 2.0 * X[:, 1]
    p = 1.0 / (1.0 + np.exp(-(logit - np.quantile(logit, 1 - imbalance))))
    y = (rng.random(n) < p).astype(int)
    if n_copies:
        copies = np.column_stack(
            [X[:, 0] + rng.normal(scale=0.03, size=n) for _ in range(n_copies)]
        )
        X = np.hstack([X, copies])
    return X, y


def claim_permutation_collapse() -> None:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.inspection import permutation_importance

    imps, ranks = [], []
    for n_copies in (0, 3):
        X, y = _redundant_dataset(n_copies=n_copies, seed=1)
        m = RandomForestClassifier(n_estimators=150, random_state=0).fit(X, y)
        pi = permutation_importance(
            m, X, y, n_repeats=4, random_state=0, scoring="average_precision"
        ).importances_mean
        imps.append(pi[0])
        ranks.append(int(np.where(np.argsort(-pi) == 0)[0][0]) + 1)

    collapsed = imps[1] < 0.05 * imps[0] and ranks[1] > 3
    check(
        "C4  permutation importance collapses when copies are added",
        collapsed,
        f"x0: {imps[0]:.4f} (rank {ranks[0]}) -> {imps[1]:.4f} (rank {ranks[1]}) "
        f"| documented: 0.6978 rank 1 -> ~0.000 rank 11",
    )


def claim_shap_vs_permutation_groupsum() -> None:
    import shap
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.inspection import permutation_importance

    group = [0, 10, 11, 12]
    sums = {}
    for label, n_copies, cols in (("with", 3, group), ("without", 0, [0])):
        sh, pe = [], []
        for seed in range(3):
            X, y = _redundant_dataset(n_copies=n_copies, seed=seed)
            m = RandomForestClassifier(n_estimators=120, random_state=0).fit(X, y)
            sv = shap.TreeExplainer(m).shap_values(X[:300])
            sv = sv[..., 1] if sv.ndim == 3 else sv
            sh.append(np.abs(sv).mean(0)[cols].sum())
            pi = permutation_importance(
                m, X, y, n_repeats=3, random_state=0, scoring="average_precision"
            ).importances_mean
            pe.append(pi[cols].sum())
        sums[label] = (float(np.mean(sh)), float(np.mean(pe)))

    shap_ret = sums["with"][0] / sums["without"][0]
    perm_ret = sums["with"][1] / sums["without"][1]
    passed = shap_ret > 0.7 and perm_ret < 0.1
    check(
        "C5  SHAP group-sum survives copies; permutation's does not",
        passed,
        f"group-sum retained -- SHAP {shap_ret:.0%}, permutation {perm_ret:.1%} "
        f"| documented: 116% and 0.8%",
    )


# ----------------------------------------------------------------------- C1, C2
def claim_adir_flat() -> None:
    from src.graphs.builder import WindowConfig, build_temporal_graphs
    from src.iag.index import directional_asymmetry
    from src.simulator.agents import AttackType, SimulationConfig, run_simulation

    vals = []
    for level in (0.0, 0.5, 0.8):
        df = run_simulation(
            SimulationConfig(
                attack_type=AttackType.PORT_SCAN, asymmetry_level=level,
                duration_seconds=600, seed=1,
            )
        )
        all_g = build_temporal_graphs(df, WindowConfig(window_seconds=60))
        graphs = [g for g in all_g if g.has_attack]
        vals.append(
            float(np.mean([directional_asymmetry(g) for g in graphs]))
            if graphs else float("nan")
        )

    flat = max(vals) < 0.01
    check(
        "C1  A_dir stays flat across half the asymmetry domain",
        flat,
        f"asymmetry 0.0/0.5/0.8 -> A_dir {vals[0]:.4f}/{vals[1]:.4f}/{vals[2]:.4f} "
        f"| documented: 0.0008/0.0008/0.0012",
    )


def claim_perflow_auc() -> None:
    from sklearn.metrics import roc_auc_score

    from src.simulator.agents import AttackType, SimulationConfig, run_simulation

    out = {}
    for attack in (AttackType.PORT_SCAN, AttackType.DDOS):
        df = run_simulation(
            SimulationConfig(
                attack_type=attack, asymmetry_level=0.8, duration_seconds=300, seed=7
            )
        )
        fwd = np.log1p(df["totlen_fwd_pkts"].to_numpy())
        bwd = np.log1p(df["totlen_bwd_pkts"].to_numpy())
        r = fwd - bwd
        out[attack.value] = roc_auc_score(df["is_attack"].to_numpy(), r)

    passed = out["PortScan"] > 0.95 and out["DDoS"] > 0.90
    check(
        "C2  per-flow asymmetry separates attacks with no graph",
        passed,
        f"AUC PortScan {out['PortScan']:.4f}, DDoS {out['DDoS']:.4f} "
        f"| documented: 0.9978 and 0.9464",
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--full", action="store_true", help="also run the slow simulator claims (C1, C2)"
    )
    args = ap.parse_args()

    header("Re-deriving the repository's headline numbers on this machine")

    claim_directional_features()
    claim_entropic_ceiling()
    claim_single_edge_fixed()
    claim_permutation_collapse()
    claim_shap_vs_permutation_groupsum()

    if args.full:
        header("Simulator claims (slow)")
        claim_adir_flat()
        claim_perflow_auc()
    else:
        print(
            f"\n{YELLOW}[SKIPPED]{NC}    C1, C2 (simulator claims)"
            " -- pass --full to include them"
        )

    header("Summary")
    failed = [c for c, ok_, _ in _results if not ok_]
    print(f"{len(_results) - len(failed)}/{len(_results)} claims reproduced")
    if failed:
        print(f"\n{RED}Diverged:{NC}")
        for claim in failed:
            print(f"  - {claim}")
        print(
            "\nA divergence is information, not necessarily a defect: library versions move and\n"
            "some of these are stochastic. Check the recorded value in the linked document before\n"
            "concluding either that the code broke or that the documentation was wrong."
        )
    else:
        print(f"{GREEN}Every claim checked here reproduces on this machine.{NC}")
    return len(failed)


if __name__ == "__main__":
    raise SystemExit(main())
