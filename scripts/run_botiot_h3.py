#!/usr/bin/env python3
"""BoT-IoT external validation of H3. Executes the plan frozen in
docs/methodology/BOTIOT_H3_FREEZE.md SS4-SS8 (Phase 0 in SS9.1). Anything
not listed there is labeled POST-HOC in its output.

    python scripts/run_botiot_h3.py \\
        --data-dir "C:\\Users\\DavidG\\Downloads\\OneDrive_2026-09-23\\Entire Dataset"

Rule-bearing code is imported UNCHANGED from
scripts/run_unsw_external_validation.py (FREEZE SS5): orientation, confident,
criterion, auc_lookup, auc_from_codes, quantile_from_counts, B, SEED,
NEUTRAL, ROLE_MIN. `criterion` reads the module-global CATEGORIES, which is
rebound to the ten BoT-IoT groups -- the function body is untouched.

Bootstrap: stratified, B=2000. Resampling with replacement is implemented
as a multinomial draw over each class's distinct-value counts -- the
distributionally identical form SS5 allows, required at 73M rows. The AUC of
a draw is the count-weighted form of auc_from_codes over auc_lookup.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import importlib.util
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ingest.bot_iot import (  # noqa: E402
    ATTACKERS,
    FLOW_FILES,
    GROUP_MAP,
    GROUPS,
    NAMES_FILE,
    duplicate_count,
    load_botiot,
)

_spec = importlib.util.spec_from_file_location(
    "unsw_run", ROOT / "scripts" / "run_unsw_external_validation.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)
run.CATEGORIES = GROUPS  # criterion() filters on this module global (see docstring)

B, SEED, ROLE_MIN = run.B, run.SEED, run.ROLE_MIN
QUANTILES = {"p10": 0.10, "p25": 0.25, "median": 0.50, "p75": 0.75, "p90": 0.90}
FEATURES = ["A_bytes", "A_packets", "S_bytes_C1", "A_bytes_attack_oriented"]
CATS = ["DDoS", "DoS", "Reconnaissance", "Theft"]
ALL = "ALL (descriptive)"
OUT = ROOT / "results" / "botiot"
FIG = ROOT / "results" / "figures"

# SS6.2 secondary predictions. Neither enters the verdict.
H3_DIR = {"DDoS/HTTP": "negative", "DoS/HTTP": "negative",
          "DDoS/TCP": "negative", "DoS/TCP": "negative",
          "DDoS/UDP": "negative", "DoS/UDP": "negative",
          "Theft/Keylogging": "positive"}
H3_ENV = {"DDoS/HTTP": "negative", "DoS/HTTP": "negative",
          "DDoS/TCP": "positive", "DoS/TCP": "positive",
          "DDoS/UDP": "positive", "DoS/UDP": "positive"}
HPING = ["DDoS/TCP", "DoS/TCP", "DDoS/UDP", "DoS/UDP"]
GOLDENEYE = ["DDoS/HTTP", "DoS/HTTP"]


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _np(o):
    return o.item()


# ---- verdict (SS6) -------------------------------------------------------------
def score_predictions(rows: dict, preds: dict) -> dict:
    out = {}
    for g, want in preds.items():
        r = rows[g]
        out[g] = {"predicted": want, "observed": r["orientation"], "confident": r["confident"],
                  "held": r["orientation"] == want,
                  "held_confident": r["orientation"] == want and r["confident"]}
    return out


def verdict(table: list[dict]) -> dict:
    by = {f: [r for r in table if r["feature"] == f] for f in ("A_bytes", "A_packets")}
    cb, cp = run.criterion(by["A_bytes"]), run.criterion(by["A_packets"])
    if cb == "consistent":
        v = "STRONG REPLICATION" if cp == "consistent" else "PARTIAL REPLICATION"
    elif cb == "inconclusive (role)":
        v = "INCONCLUSIVE (ROLE)"
    else:
        v = "NO REPLICATION"
    rows = {r["category"]: r for r in by["A_bytes"]}
    conf_neg = lambda g: rows[g]["orientation"] == "negative" and rows[g]["confident"]  # noqa: E731
    conf_pos = lambda g: rows[g]["orientation"] == "positive" and rows[g]["confident"]  # noqa: E731
    return {
        "verdict": v, "criterion_A_bytes": cb, "criterion_A_packets": cp,
        "H3_dir": score_predictions(rows, H3_DIR),
        "H3_env": score_predictions(rows, H3_ENV),
        # SS7 abandonment conditions for the secondary readings.
        "abandon_H3_env": any(conf_neg(g) for g in HPING),
        "abandon_H3_dir": any(conf_pos(g) for g in GOLDENEYE),
    }


# ---- analysis ------------------------------------------------------------------
def analyze(df: pl.DataFrame, population: str, rng: np.random.Generator):
    fb = np.log1p(df["fwd_bytes"].to_numpy().astype(np.float64))
    bb = np.log1p(df["bwd_bytes"].to_numpy().astype(np.float64))
    fp = np.log1p(df["fwd_packets"].to_numpy().astype(np.float64))
    bp = np.log1p(df["bwd_packets"].to_numpy().astype(np.float64))
    a_bytes = fb - bb
    size = np.log1p((df["fwd_bytes"] + df["bwd_bytes"]).to_numpy().astype(np.float64))
    src_att = df["src_ip"].cast(pl.String).is_in(ATTACKERS).to_numpy()
    dst_att = df["dst_ip"].cast(pl.String).is_in(ATTACKERS).to_numpy()
    label = df["label"].to_numpy()
    benign = label == 0
    a_orient = np.where(benign, a_bytes,
                        np.where(src_att, a_bytes, np.where(dst_att, -a_bytes, np.nan)))
    raw = {"A_bytes": a_bytes, "A_packets": fp - bp, "S_bytes_C1": size,
           "A_bytes_attack_oriented": a_orient}
    del fb, bb, fp, bp

    grp = df["attack_category"].fill_null("").to_numpy()
    groups = {g: (label == 1) & (grp == g) for g in GROUPS}
    for c in CATS:
        members = [g for (cc, _), g in GROUP_MAP.items() if cc == c]
        groups[c] = (label == 1) & np.isin(grp, members)
    groups[ALL] = label == 1

    role = {g: {"src_is_attacker": float(src_att[m].mean()),
                "dst_is_attacker": float(dst_att[m].mean()),
                "resolved": float((src_att[m] | dst_att[m]).mean())}
            for g, m in groups.items()}

    n_b = int(benign.sum())
    values, bcodes, gcounts = {}, {}, {}
    for f, x in raw.items():
        ok = ~np.isnan(x)
        values[f], inv = np.unique(x[ok], return_inverse=True)
        codes = np.full(len(x), -1, dtype=np.int64)
        codes[ok] = inv
        bcodes[f] = codes[benign]
        gcounts[f] = {}
        for g, m in groups.items():
            if f == "A_bytes_attack_oriented" and role[g]["resolved"] < ROLE_MIN:
                continue
            c = codes[m]
            c = c[c >= 0]
            u, k = np.unique(c, return_counts=True)  # this group's distinct values
            gcounts[f][g] = (u, k, c)
        _log(f"  {population}: {f} has {len(values[f]):,} distinct values")
    del raw

    point, dist = {}, []
    for f in FEATURES:
        bc = np.bincount(bcodes[f], minlength=len(values[f]))
        lk = run.auc_lookup(bc)
        b_med = run.quantile_from_counts(bc, values[f], 0.5)
        dist.append({"population": population, "feature": f, "group": "Benign", "n": n_b}
                    | {k: run.quantile_from_counts(bc, values[f], q) for k, q in QUANTILES.items()})
        for g, (u, k, c) in gcounts[f].items():
            full = np.zeros(len(values[f]), dtype=np.int64)
            full[u] = k
            row = {"population": population, "feature": f, "group": g, "n": int(k.sum())}
            row |= {kk: run.quantile_from_counts(full, values[f], q) for kk, q in QUANTILES.items()}
            dist.append(row)
            point[(f, g)] = (run.auc_from_codes(lk, c, n_b), row["median"] - b_med)
    for r in dist:
        r["iqr"] = r["p75"] - r["p25"]
    for f in FEATURES:
        for g in gcounts[f]:
            gcounts[f][g] = gcounts[f][g][:2]  # drop per-row codes; counts suffice now

    draws = {k: np.empty((B, 2)) for k in point}
    t0 = time.time()
    for b in range(B):
        bi = rng.integers(0, n_b, n_b)
        for f in FEATURES:
            bc = np.bincount(bcodes[f][bi], minlength=len(values[f]))
            lk = run.auc_lookup(bc)
            b_med = run.quantile_from_counts(bc, values[f], 0.5)
            for g, (u, k) in gcounts[f].items():
                n = int(k.sum())
                w = rng.multinomial(n, k / n)
                auc = float((lk[u] * w).sum() / n / n_b)
                med = run.quantile_from_counts(w, values[f][u], 0.5)
                draws[(f, g)][b] = (auc, med - b_med)
        if b % 200 == 0:
            _log(f"  {population}: bootstrap {b}/{B} ({time.time() - t0:.0f}s)")

    table, boot = [], []
    for (f, g), (auc, dmed) in point.items():
        d = draws[(f, g)]
        lo, hi = np.percentile(d[:, 0], [2.5, 97.5])
        slo, shi = np.percentile(np.maximum(d[:, 0], 1 - d[:, 0]), [2.5, 97.5])
        mlo, mhi = np.percentile(d[:, 1], [2.5, 97.5])
        table.append({
            "population": population, "feature": f, "category": g,
            "n_attack": int(gcounts[f][g][1].sum()), "n_benign": n_b,
            "auc_signed": auc, "ci_lo": lo, "ci_hi": hi,
            "auc_sep": max(auc, 1 - auc), "sep_ci_lo": slo, "sep_ci_hi": shi,
            "delta": auc - 0.5, "orientation": run.orientation(auc),
            "confident": run.confident(auc, lo, hi),
            "median_diff": dmed, "median_diff_ci_lo": mlo, "median_diff_ci_hi": mhi,
            **role[g], "computed": True,
        })
        boot += [{"population": population, "feature": f, "category": g, "b": i,
                  "auc_signed": x[0], "median_diff": x[1]} for i, x in enumerate(d)]
    for g in groups:
        if g not in gcounts["A_bytes_attack_oriented"]:
            table.append({"population": population, "feature": "A_bytes_attack_oriented",
                          "category": g, "n_attack": int(groups[g].sum()), "n_benign": n_b,
                          **role[g], "computed": False})
    return table, boot, dist, (values["A_bytes"], bcodes["A_bytes"], gcounts["A_bytes"])


def sklearn_check(table: list[dict], df: pl.DataFrame) -> None:
    """Counting AUC must equal roc_auc_score (the CICIDS/UNSW convention)."""
    from sklearn.metrics import roc_auc_score

    x = np.log1p(df["fwd_bytes"].to_numpy().astype(float)) - np.log1p(
        df["bwd_bytes"].to_numpy().astype(float))
    y = df["label"].to_numpy()
    grp = df["attack_category"].fill_null("").to_numpy()
    for r in table:
        if r["feature"] == "A_bytes" and r["category"] in GROUPS:
            m = (y == 0) | (grp == r["category"])
            ref = roc_auc_score(y[m], x[m])
            assert abs(ref - r["auc_signed"]) < 1e-9, (r["category"], ref, r["auc_signed"])


# ---- figures (primary population, fixed SS2 order) -----------------------------
def figures(table: list[dict], ecdf_src) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    blue, orange, gray = "#2a78d6", "#eb6834", "#8a8a85"
    rows = {(r["feature"], r["category"]): r for r in table if r["computed"]}
    x = np.arange(len(GROUPS))
    for key, fname, ylab in [
            ("auc_signed", "botiot_signed_auc.pdf", "AUC signed (attack vs. Normal)"),
            ("auc_sep", "botiot_separability_auc.pdf", "AUC sep = max(AUC, 1 − AUC)")]:
        fig, ax = plt.subplots(figsize=(9, 4.2))
        if key == "auc_signed":
            ax.axhspan(0.45, 0.55, color=gray, alpha=0.15, lw=0, label="near-neutral band")
        ax.axhline(0.5, color=gray, lw=1)
        lo_k, hi_k = ("ci_lo", "ci_hi") if key == "auc_signed" else ("sep_ci_lo", "sep_ci_hi")
        for off, f, col in [(-0.12, "A_bytes", blue), (0.12, "A_packets", orange)]:
            r = [rows[(f, g)] for g in GROUPS]
            y = np.array([q[key] for q in r])
            # A percentile CI need not contain the point (e.g. AUC_sep near 0.5, small n):
            # clip so the bar still spans [lo, hi] as far as it extends past the point.
            err = np.clip([y - [q[lo_k] for q in r], [q[hi_k] for q in r] - y], 0, None)
            ax.errorbar(x + off, y, yerr=err, fmt="o", ms=5, color=col, lw=1.5, capsize=3,
                        label=f)
        ax.set_xticks(x, GROUPS, rotation=35, ha="right", fontsize=8)
        ax.set_ylim(0, 1) if key == "auc_signed" else ax.set_ylim(0.45, 1)
        ax.set_ylabel(ylab)
        ax.set_title("BoT-IoT, per mechanism group vs. Normal, 95% bootstrap CI (B=2000)")
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.25)
        ax.legend(frameon=False, fontsize=8)
        fig.tight_layout()
        fig.savefig(FIG / fname)
        plt.close(fig)

    v, bcodes, gcounts = ecdf_src
    grid = np.linspace(-12, 12, 481)

    def ecdf(u, k):
        full = np.zeros(len(v))
        full[u] = k
        cum = np.cumsum(full) / full.sum()
        i = np.searchsorted(v, grid, side="right") - 1
        return np.where(i >= 0, cum[np.clip(i, 0, None)], 0.0)

    bu, bk = np.unique(bcodes, return_counts=True)
    eb = ecdf(bu, bk)
    fig, axes = plt.subplots(2, 5, figsize=(14, 5.6), sharex=True, sharey=True)
    for ax, g in zip(axes.flat, GROUPS):
        u, k = gcounts[g]
        ax.step(grid, eb, where="post", color=gray, lw=1.5)
        ax.step(grid, ecdf(u, k), where="post", color=blue, lw=2)
        ax.axvline(0, color=gray, lw=0.5, ls=":")
        ax.set_title(f"{g} (n={int(k.sum()):,})", fontsize=8)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0, 0].legend(["Normal", "attack group"], frameon=False, fontsize=7)
    fig.supxlabel("A_bytes = log(1+sbytes) − log(1+dbytes)   (>0: source→destination dominates)")
    fig.supylabel("ECDF")
    fig.tight_layout()
    fig.savefig(FIG / "botiot_asymmetry_distributions.pdf")
    plt.close(fig)


# ---- provenance -------------------------------------------------------------------
def metadata(data_dir: Path) -> dict:
    def sh(*a: str) -> str:
        return subprocess.run(a, cwd=ROOT, capture_output=True, text=True).stdout.strip()

    pre = json.loads((OUT / "preflight.json").read_text())["files"]
    manifest = hashlib.sha256("".join(pre[f]["sha256"] for f in FLOW_FILES).encode()).hexdigest()
    return {
        "git_commit": sh("git", "rev-parse", "HEAD"),
        "git_dirty": bool(sh("git", "status", "--porcelain")),
        "python": platform.python_version(),
        "packages": {p: md.version(p) for p in ("numpy", "polars", "matplotlib", "scikit-learn")},
        "data_dir": str(data_dir),
        "dataset_manifest_sha256": manifest,
        "names_file": NAMES_FILE,
        "bootstrap_B": B, "bootstrap_seed": SEED, "near_neutral": run.NEUTRAL,
        "role_min": ROLE_MIN, "freeze_doc": "docs/methodology/BOTIOT_H3_FREEZE.md",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    FIG.mkdir(parents=True, exist_ok=True)
    meta = metadata(args.data_dir)

    _log("loading (all rows as released)")
    df = load_botiot(args.data_dir)
    unmapped = df.filter((pl.col("label") == 1) & pl.col("attack_category").is_null()).height
    assert unmapped == 0, f"{unmapped} attack rows map to no frozen group"
    _log("counting exact duplicates (SS4 dedup definition)")
    n_dup = duplicate_count(args.data_dir)
    meta["dedup_duplicate_rows"] = n_dup
    if n_dup != 0:
        raise SystemExit(f"{n_dup} duplicates found; SS9.1 recorded 0 -- stop and investigate")

    rng = np.random.default_rng(SEED)
    tables, boots, dists, verdicts = [], [], [], {}
    table, boot, dist, ecdf_src = analyze(df, "primary_all_rows", rng)
    sklearn_check(table, df)
    _log("sklearn roc_auc_score agrees with counting AUC on all ten groups")
    figures(table, ecdf_src)
    verdicts["primary_all_rows"] = verdict(table)
    tables, boots, dists = table, boot, dist
    # SS4 sensitivity. 0 duplicates => the deduplicated population IS the primary
    # one; it is still run (fresh bootstrap draws, same RNG stream) and reported.
    table, boot, dist, _ = analyze(df, "sensitivity_dedup", rng)
    verdicts["sensitivity_dedup"] = verdict(table) | {
        "note": "0 exact duplicates (SS9.1): population identical to primary"}
    tables += table
    boots += boot
    dists += dist

    order = {g: i for i, g in enumerate(GROUPS + CATS + [ALL])}
    tables.sort(key=lambda r: (r["population"], FEATURES.index(r["feature"]),
                               order[r["category"]]))
    pl.DataFrame(tables).write_csv(OUT / "asymmetry_by_attack.csv")
    pl.DataFrame(boots).write_csv(OUT / "asymmetry_bootstrap.csv")
    pl.DataFrame(dists).write_csv(OUT / "asymmetry_distributions.csv")
    (OUT / "verdict.json").write_text(json.dumps(verdicts, indent=2, default=_np))
    meta["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "run_metadata.json").write_text(json.dumps(meta, indent=2, default=_np))
    print(json.dumps(verdicts, indent=2, default=_np))


if __name__ == "__main__":
    main()
