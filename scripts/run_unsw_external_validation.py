#!/usr/bin/env python3
"""UNSW-NB15 external validation of H3 (mechanism-dependent directional
asymmetry). Executes exactly the plan frozen in
docs/methodology/UNSW_EXTERNAL_VALIDATION_FREEZE.md SS7 -- nothing here may
deviate from it; anything added later is labeled POST-HOC in its output.

    python scripts/run_unsw_external_validation.py \\
        --data-dir "C:\\Users\\DavidG\\Downloads\\UNSW-NB15"

Reproduces results/unsw/*.csv|json and results/figures/unsw_*.pdf.

AUC is computed from counts over the distinct feature values (Mann-Whitney,
ties 1/2 -- identical to sklearn.metrics.roc_auc_score, asserted at runtime),
which makes B=2000 stratified bootstraps over 2.5M rows tractable.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.ingest.unsw_nb15 import (  # noqa: E402
    CATEGORIES,
    FLOW_FILES,
    GT_FILE,
    attacker_ips,
    load_unsw,
)

# ---- frozen parameters (FREEZE SS7) -----------------------------------------
B = 2000
SEED = 20260922
NEUTRAL = 0.05           # |AUC - 0.5| < 0.05 -> near-neutral (SS7.5)
ROLE_MIN = 0.90          # src_is_attacker threshold (SS7.6) / resolve (SS7.4)
QUANTILES = {"p10": 0.10, "p25": 0.25, "median": 0.50, "p75": 0.75, "p90": 0.90}
ALL = "ALL (descriptive)"
FEATURES = ["A_bytes", "A_packets", "A_bytes_attack_oriented"]
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "unsw"
FIG = ROOT / "results" / "figures"


def _np(o):
    """json default: numpy scalars (np.bool_, np.float64) -> Python."""
    return o.item()


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---- counting primitives ----------------------------------------------------
def auc_lookup(benign_counts: np.ndarray) -> np.ndarray:
    """Per distinct value u: (#benign < u) + 0.5 * (#benign == u)."""
    return np.cumsum(benign_counts) - 0.5 * benign_counts


def auc_from_codes(lookup: np.ndarray, attack_codes: np.ndarray, n_benign: int) -> float:
    """P(attack > benign) + 0.5 P(tie); codes index the sorted distinct values."""
    return float(lookup[attack_codes].mean() / n_benign)


def quantile_from_counts(counts: np.ndarray, values: np.ndarray, q: float) -> float:
    """np.quantile(..., method='inverted_cdf') computed from value counts."""
    cum = np.cumsum(counts)
    return float(values[np.searchsorted(cum, q * cum[-1], side="left")])


def orientation(auc: float) -> str:
    d = round(auc - 0.5, 12)  # 0.45 - 0.5 is -0.0499..9 in floating point
    return "positive" if d >= NEUTRAL else "negative" if d <= -NEUTRAL else "near-neutral"


def confident(auc: float, lo: float, hi: float) -> bool:
    o = orientation(auc)
    return (o == "positive" and lo > 0.5) or (o == "negative" and hi < 0.5)


# ---- verdict (SS7.6) ----------------------------------------------------------
def criterion(rows: list[dict]) -> str:
    """'consistent' | 'inconclusive (role)' | 'not met' for one feature."""
    rows = [r for r in rows if r["category"] in CATEGORIES and r["computed"]]
    pos = [r for r in rows if r["confident"] and r["orientation"] == "positive"]
    neg = [r for r in rows if r["confident"] and r["orientation"] == "negative"]
    if not (pos and neg):
        return "not met"
    if any(r["src_is_attacker"] >= ROLE_MIN for r in pos) and any(
        r["src_is_attacker"] >= ROLE_MIN for r in neg
    ):
        return "consistent"
    return "inconclusive (role)"


def verdict(table: list[dict]) -> dict:
    by = {f: [r for r in table if r["feature"] == f] for f in ("A_bytes", "A_packets")}
    cb, cp = criterion(by["A_bytes"]), criterion(by["A_packets"])
    if cb == "consistent":
        v = "STRONG REPLICATION" if cp == "consistent" else "PARTIAL REPLICATION"
    elif cb == "inconclusive (role)":
        v = "INCONCLUSIVE (ROLE)"
    else:
        v = "NO REPLICATION"
    cat = {r["category"]: r for r in by["A_bytes"]}
    dos, exp = cat["DoS"], cat["Exploits"]
    h3dir = {
        "DoS_negative": dos["orientation"] == "negative",
        "DoS_negative_confident": dos["orientation"] == "negative" and dos["confident"],
        "Exploits_positive": exp["orientation"] == "positive",
        "Exploits_positive_confident": exp["orientation"] == "positive" and exp["confident"],
    }
    return {"verdict": v, "criterion_A_bytes": cb, "criterion_A_packets": cp, "H3_dir": h3dir}


# ---- analysis -----------------------------------------------------------------
def analyze(df: pl.DataFrame, attackers: set[str], population: str, rng: np.random.Generator):
    fb = np.log1p(df["fwd_bytes"].to_numpy().astype(np.float64))
    bb = np.log1p(df["bwd_bytes"].to_numpy().astype(np.float64))
    fp = np.log1p(df["fwd_packets"].to_numpy().astype(np.float64))
    bp = np.log1p(df["bwd_packets"].to_numpy().astype(np.float64))
    a_bytes, a_pkts = fb - bb, fp - bp
    att = list(attackers)
    src_att = df["src_ip"].is_in(att).to_numpy()
    dst_att = df["dst_ip"].is_in(att).to_numpy()
    a_orient = np.where(src_att, a_bytes, np.where(dst_att, -a_bytes, np.nan))

    label = df["label"].to_numpy()
    cat = df["attack_category"].fill_null("").to_numpy()
    benign = label == 0
    groups = {c: (label == 1) & (cat == c) for c in CATEGORIES}
    groups[ALL] = label == 1

    # Benign always carries raw A_bytes for the attack-oriented feature (SS7.4).
    raw = {"A_bytes": a_bytes, "A_packets": a_pkts,
           "A_bytes_attack_oriented": np.where(benign, a_bytes, a_orient)}
    values, codes = {}, {}
    for f, x in raw.items():
        ok = ~np.isnan(x)
        values[f], inv = np.unique(x[ok], return_inverse=True)
        codes[f] = np.full(len(x), -1, dtype=np.int64)
        codes[f][ok] = inv

    n_b = int(benign.sum())
    b_codes = {f: codes[f][benign] for f in FEATURES}
    role, members = {}, {}
    for g, m in groups.items():
        role[g] = {"src_is_attacker": float(src_att[m].mean()),
                   "dst_is_attacker": float(dst_att[m].mean()),
                   "resolved": float((src_att[m] | dst_att[m]).mean())}
        members[g] = {}
        for f in FEATURES:
            if f == "A_bytes_attack_oriented" and role[g]["resolved"] < ROLE_MIN:
                continue
            c = codes[f][m]
            members[g][f] = c[c >= 0]

    # Point estimates.
    point, dist = {}, []
    for f in FEATURES:
        bc = np.bincount(b_codes[f], minlength=len(values[f]))
        lk = auc_lookup(bc)
        b_med = quantile_from_counts(bc, values[f], 0.5)
        row = {"population": population, "feature": f, "group": "Benign", "n": n_b}
        row |= {k: quantile_from_counts(bc, values[f], q) for k, q in QUANTILES.items()}
        dist.append(row)
        for g, fm in members.items():
            if f not in fm:
                continue
            ac = np.bincount(fm[f], minlength=len(values[f]))
            row = {"population": population, "feature": f, "group": g, "n": len(fm[f])}
            row |= {k: quantile_from_counts(ac, values[f], q) for k, q in QUANTILES.items()}
            row["iqr"] = row["p75"] - row["p25"]
            dist.append(row)
            point[(f, g)] = (auc_from_codes(lk, fm[f], n_b), row["median"] - b_med)
    for r in dist:
        r.setdefault("iqr", r["p75"] - r["p25"])

    # Stratified bootstrap (SS7.3): one benign resample per iteration, shared.
    draws = {k: np.empty((B, 2)) for k in point}
    t0 = time.time()
    for b in range(B):
        bi = rng.integers(0, n_b, n_b)
        lks, bmed = {}, {}
        for f in FEATURES:
            bc = np.bincount(b_codes[f][bi], minlength=len(values[f]))
            lks[f] = auc_lookup(bc)
            bmed[f] = quantile_from_counts(bc, values[f], 0.5)
        for g, fm in members.items():
            n_a = len(fm["A_bytes"])
            ai = rng.integers(0, n_a, n_a)
            for f, c in fm.items():
                idx = ai if len(c) == n_a else rng.integers(0, len(c), len(c))
                s = c[idx]
                k = int(np.ceil(0.5 * len(s))) - 1  # inverted_cdf median
                med = values[f][np.partition(s, k)[k]]
                draws[(f, g)][b] = (auc_from_codes(lks[f], s, n_b), med - bmed[f])
        if b % 200 == 0:
            _log(f"  {population}: bootstrap {b}/{B} ({time.time() - t0:.0f}s)")

    table, boot = [], []
    for (f, g), (auc, dmed) in point.items():
        lo, hi = np.percentile(draws[(f, g)][:, 0], [2.5, 97.5])
        mlo, mhi = np.percentile(draws[(f, g)][:, 1], [2.5, 97.5])
        a = draws[(f, g)][:, 0]
        slo, shi = np.percentile(np.maximum(a, 1 - a), [2.5, 97.5])
        table.append({
            "population": population, "feature": f, "category": g,
            "n_attack": len(members[g][f]), "n_benign": n_b,
            "auc_signed": auc, "ci_lo": lo, "ci_hi": hi,
            "auc_sep": max(auc, 1 - auc), "sep_ci_lo": slo, "sep_ci_hi": shi,
            "delta": auc - 0.5,
            "orientation": orientation(auc), "confident": confident(auc, lo, hi),
            "median_diff": dmed, "median_diff_ci_lo": mlo, "median_diff_ci_hi": mhi,
            **role[g], "computed": True,
        })
        boot += [{"population": population, "feature": f, "category": g, "b": i,
                  "auc_signed": d[0], "median_diff": d[1]}
                 for i, d in enumerate(draws[(f, g)])]
    # Categories whose attack-oriented feature was not computable (SS7.4).
    for g in groups:
        if "A_bytes_attack_oriented" not in members[g]:
            table.append({"population": population, "feature": "A_bytes_attack_oriented",
                          "category": g, "n_attack": int(groups[g].sum()),
                          "n_benign": n_b, **role[g], "computed": False})
    return table, boot, dist, (values, codes, benign, groups)


def sklearn_check(table: list[dict], df: pl.DataFrame) -> None:
    """The counting AUC must equal roc_auc_score (the CICIDS convention)."""
    from sklearn.metrics import roc_auc_score

    x = np.log1p(df["fwd_bytes"].to_numpy().astype(float)) - np.log1p(
        df["bwd_bytes"].to_numpy().astype(float))
    y, cat = df["label"].to_numpy(), df["attack_category"].fill_null("").to_numpy()
    for r in table:
        if r["feature"] == "A_bytes" and r["category"] in CATEGORIES:
            m = (y == 0) | (cat == r["category"])
            ref = roc_auc_score(y[m], x[m])
            assert abs(ref - r["auc_signed"]) < 1e-9, (r["category"], ref, r["auc_signed"])


# ---- figures (primary population, fixed order SS7.5) --------------------------
def figures(table: list[dict], ecdf_src) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    blue, orange, gray = "#2a78d6", "#eb6834", "#8a8a85"
    x = np.arange(len(CATEGORIES))
    rows = {(r["feature"], r["category"]): r for r in table if r["computed"]}

    panels = [("auc_signed", "unsw_signed_auc.pdf", "AUC signed (attack vs. Normal)"),
              ("auc_sep", "unsw_separability_auc.pdf", "AUC sep = max(AUC, 1 − AUC)")]
    for key, fname, ylab in panels:
        fig, ax = plt.subplots(figsize=(8, 4))
        if key == "auc_signed":
            ax.axhspan(0.5 - NEUTRAL, 0.5 + NEUTRAL, color=gray, alpha=0.15, lw=0,
                       label="near-neutral band")
        ax.axhline(0.5, color=gray, lw=1)
        for off, f, col in [(-0.12, "A_bytes", blue), (0.12, "A_packets", orange)]:
            r = [rows[(f, c)] for c in CATEGORIES]
            y = np.array([q[key] for q in r])
            lo_k, hi_k = ("ci_lo", "ci_hi") if key == "auc_signed" else ("sep_ci_lo", "sep_ci_hi")
            err = [y - [q[lo_k] for q in r], [q[hi_k] for q in r] - y]
            ax.errorbar(x + off, y, yerr=err, fmt="o", ms=5, color=col, lw=1.5,
                        capsize=3, label=f)
        ax.set_xticks(x, CATEGORIES, rotation=30, ha="right")
        ax.set_ylim(0, 1) if key == "auc_signed" else ax.set_ylim(0.45, 1)
        ax.set_ylabel(ylab)
        ax.set_title("UNSW-NB15, per-category vs. Normal, 95% bootstrap CI (B=2000)")
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.25)
        ax.legend(frameon=False, fontsize=8)
        fig.tight_layout()
        fig.savefig(FIG / fname)
        plt.close(fig)

    values, codes, benign, groups = ecdf_src
    v, c = values["A_bytes"], codes["A_bytes"]
    grid = np.linspace(-12, 12, 481)

    def ecdf(mask):
        cnt = np.bincount(c[mask], minlength=len(v))
        cum = np.cumsum(cnt) / cnt.sum()
        i = np.searchsorted(v, grid, side="right") - 1
        return np.where(i >= 0, cum[np.clip(i, 0, None)], 0.0)

    eb = ecdf(benign)
    fig, axes = plt.subplots(3, 3, figsize=(10, 8), sharex=True, sharey=True)
    for ax, cat_ in zip(axes.flat, CATEGORIES):
        ax.step(grid, eb, where="post", color=gray, lw=1.5, label="Normal")
        ax.step(grid, ecdf(groups[cat_]), where="post", color=blue, lw=2, label=cat_)
        ax.axvline(0, color=gray, lw=0.5, ls=":")
        ax.set_title(f"{cat_} (n={int(groups[cat_].sum()):,})", fontsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0, 0].legend(["Normal", "attack category"], frameon=False, fontsize=8)
    fig.supxlabel("A_bytes = log(1+sbytes) − log(1+dbytes)   (>0: source→destination dominates)")
    fig.supylabel("ECDF")
    fig.tight_layout()
    fig.savefig(FIG / "unsw_asymmetry_distributions.pdf")
    plt.close(fig)


# ---- provenance -----------------------------------------------------------------
def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def metadata(data_dir: Path) -> dict:
    def run(*a: str) -> str:
        return subprocess.run(a, cwd=ROOT, capture_output=True, text=True).stdout.strip()

    git, dirty = run("git", "rev-parse", "HEAD"), bool(run("git", "status", "--porcelain"))
    return {
        "git_commit": git, "git_dirty": dirty, "python": platform.python_version(),
        "packages": {p: md.version(p) for p in ("numpy", "polars", "matplotlib", "scikit-learn")},
        "dataset_sha256": {f: sha256(data_dir / f) for f in FLOW_FILES + [GT_FILE]},
        "bootstrap_B": B, "bootstrap_seed": SEED, "near_neutral": NEUTRAL, "role_min": ROLE_MIN,
        "freeze_doc": "docs/methodology/UNSW_EXTERNAL_VALIDATION_FREEZE.md",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)

    meta = metadata(args.data_dir)
    attackers = attacker_ips(args.data_dir)
    rng = np.random.default_rng(SEED)
    tables, boots, dists, verdicts, preflight = [], [], [], {}, {}
    for population, dedup in [("primary_all_rows", False), ("sensitivity_dedup", True)]:
        _log(f"loading {population}")
        df = load_unsw(args.data_dir, dedup=dedup)
        cnt = df.group_by("attack_category").len().rows()
        preflight[population] = {
            "rows": df.height, "benign": int((df["label"] == 0).sum()),
            "attack": int((df["label"] == 1).sum()),
            "per_category": {str(k): v for k, v in cnt if k is not None},
            "null_counts": df.null_count().row(0, named=True),
        }
        table, boot, dist, ecdf_src = analyze(df, attackers, population, rng)
        if not dedup:
            sklearn_check(table, df)
            _log("sklearn roc_auc_score agrees with counting AUC")
            figures(table, ecdf_src)
        verdicts[population] = verdict(table)
        tables += table
        boots += boot
        dists += dist
    preflight["attacker_ips_from_GT"] = sorted(attackers)

    order = {c: i for i, c in enumerate(CATEGORIES + [ALL])}
    tables.sort(key=lambda r: (r["population"], FEATURES.index(r["feature"]), order[r["category"]]))
    pl.DataFrame(tables).write_csv(OUT / "asymmetry_by_attack.csv")
    pl.DataFrame(boots).write_csv(OUT / "asymmetry_bootstrap.csv")
    pl.DataFrame(dists).write_csv(OUT / "asymmetry_distributions.csv")
    (OUT / "preflight.json").write_text(json.dumps(preflight, indent=2, default=_np))
    (OUT / "verdict.json").write_text(json.dumps(verdicts, indent=2, default=_np))
    meta["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "run_metadata.json").write_text(json.dumps(meta, indent=2, default=_np))
    print(json.dumps(verdicts, indent=2, default=_np))


if __name__ == "__main__":
    main()
