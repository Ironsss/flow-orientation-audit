#!/usr/bin/env python3
"""A4 reviewer audit: same-traffic flow-representation sensitivity,
canonical CICFlowMeter CSE-CIC-IDS2018 vs. NF-CSE-CIC-IDS2018-v2.

POST-HOC REVIEWER ROBUSTNESS AUDIT. Implements the frozen protocol
docs/reviewer_audit/A4_REPRESENTATION_SENSITIVITY.md (freeze commit 946337f)
exactly; nothing here chooses a threshold, weight, pair, tier or case rule.

Order of execution (the freeze's own):
  1. canonical load + canonical reproduction gates -> exit non-zero on any
     failure, BEFORE the NF file is opened;
  2. NF SHA256 + row-count gate -> exit non-zero on mismatch;
  3. PRIMARY (fine labels), Q5 ordering, SECONDARY (standardized coarse),
     DIAGNOSTIC (raw coarse + envelope), TERTIARY (benign-free pairs), reply
     rates, absolute-vs-relative, case assignment.

Category AUCs are always recomputed from pooled rows (`pooled_auc`), never
averaged from per-label AUCs. Weighted sums of per-label AUCs appear only
where the freeze defines them: the SECONDARY standardized values and the
pooling-identity gates.

    python scripts/audit_a4_representation.py --canonical-dir data/raw --canonical-only
    python scripts/audit_a4_representation.py --canonical-dir data/raw --nf-path <NF csv>
"""
from __future__ import annotations

import argparse
import csv
import hashlib
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

_spec = importlib.util.spec_from_file_location(
    "a2", ROOT / "scripts" / "audit_a2_reply_conditional.py")
a2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a2)
run = a2.run  # scripts/run_unsw_external_validation.py: orientation, NEUTRAL

OUT = ROOT / "results" / "audit" / "a4_representation"
FREEZE_COMMIT = "946337f"
NEUTRAL = run.NEUTRAL  # 0.05, unchanged
FLOOR = 1_000          # well-supported: n_attack >= 1,000 on BOTH sides
TOL = 1e-9
FEATURES = ["A_bytes", "A_packets"]
PRIMARY_FEATURE = "A_bytes"

NF_SHA256 = "16a545a3e139b2e85d08b1b7d9d40328c3689a49d0deaafce6dcf8d7b63e1257"
NF_GATE = {"rows": 18_893_708, "benign": 16_635_567, "attack": 2_258_141}
CAN_BENIGN = 13_467_970
ARTIFACT = "Label"  # 3 header-artifact rows in canonical, excluded

# label -> (coarse category, canonical n, NF n); frozen in A4_FEATURE_MAPPING.md
LABELS = {
    "DDOS attack-HOIC": ("DDoS", 668_461, 1_080_858),
    "DDOS attack-LOIC-UDP": ("DDoS", 1_730, 2_112),
    "DDoS attacks-LOIC-HTTP": ("DDoS", 576_191, 307_300),
    "DoS attacks-Hulk": ("DoS", 434_873, 432_648),
    "DoS attacks-SlowHTTPTest": ("DoS", 19_462, 14_116),
    "DoS attacks-GoldenEye": ("DoS", 41_455, 27_723),
    "DoS attacks-Slowloris": ("DoS", 10_285, 9_512),
    "Bot": ("Bot", 282_310, 143_097),
    "Infilteration": ("Infilteration", 161_897, 116_361),
    "FTP-BruteForce": ("Brute Force", 39_352, 25_933),
    "SSH-Bruteforce": ("Brute Force", 117_322, 94_979),
    "Brute Force -Web": ("Brute Force", 611, 2_143),
    "Brute Force -XSS": ("Brute Force", 230, 927),
    "SQL Injection": ("injection", 87, 432),
}
WELL_SUPPORTED = [lab for lab, (_, nc, nn) in LABELS.items() if nc >= FLOOR and nn >= FLOOR]

# SECONDARY: well-supported sub-labels only (Bot, Infilteration repeat primary).
SECONDARY = {
    "DDoS": ["DDOS attack-HOIC", "DDoS attacks-LOIC-HTTP", "DDOS attack-LOIC-UDP"],
    "DoS": ["DoS attacks-Hulk", "DoS attacks-GoldenEye", "DoS attacks-SlowHTTPTest",
            "DoS attacks-Slowloris"],
    "Brute Force": ["SSH-Bruteforce", "FTP-BruteForce"],
}
# DIAGNOSTIC: NF's published merge procedure; injection excluded.
DIAGNOSTIC = {
    "DDoS": SECONDARY["DDoS"],
    "DoS": SECONDARY["DoS"],
    "Bot": ["Bot"],
    "Infilteration": ["Infilteration"],
    "Brute Force": ["FTP-BruteForce", "SSH-Bruteforce", "Brute Force -Web", "Brute Force -XSS"],
}
# TERTIARY: the 4 fixed, exhaustive same-capture pairs (X, Y).
PAIRS = [
    ("DDOS attack-LOIC-UDP", "DDOS attack-HOIC"),
    ("DoS attacks-SlowHTTPTest", "DoS attacks-Hulk"),
    ("DoS attacks-Slowloris", "DoS attacks-GoldenEye"),
    ("FTP-BruteForce", "SSH-Bruteforce"),
]
# Q5 gap readouts: (label, reference label)
GAPS = [("DDOS attack-LOIC-UDP", "DDOS attack-HOIC"),
        ("DDoS attacks-LOIC-HTTP", "DDOS attack-HOIC")]
# Canonical pooled values printed in the freeze's envelope table (4 dp; DDoS A_bytes 6 dp).
FREEZE_POOLED = {
    ("DDoS", "A_bytes"): (0.475455, 6), ("DoS", "A_bytes"): (0.6688, 4),
    ("Bot", "A_bytes"): (0.7794, 4), ("Infilteration", "A_bytes"): (0.5106, 4),
    ("Brute Force", "A_bytes"): (0.5739, 4),
    ("DDoS", "A_packets"): (0.5732, 4), ("DoS", "A_packets"): (0.8004, 4),
    ("Bot", "A_packets"): (0.4652, 4), ("Infilteration", "A_packets"): (0.4316, 4),
    ("Brute Force", "A_packets"): (0.3520, 4),
}

NN = "near-neutral"
PRESERVED, REVERSED, NEUTRALIZED, EMERGED, BOTH_NEUTRAL = (
    "PRESERVED", "REVERSED", "NEUTRALIZED", "EMERGED", "BOTH NEUTRAL")


# ---- pure helpers (unit-tested) --------------------------------------------
def directional(fwd: np.ndarray, bwd: np.ndarray) -> np.ndarray:
    """log1p(fwd) - log1p(bwd). Direction fixed by the freeze, never flipped.
    Missing values are an error, not a silent 0."""
    fwd, bwd = np.asarray(fwd, dtype=np.float64), np.asarray(bwd, dtype=np.float64)
    if np.isnan(fwd).any() or np.isnan(bwd).any():
        raise ValueError("missing value in a directional field")
    return np.log1p(fwd) - np.log1p(bwd)


def orientation(auc: float) -> str:
    return run.orientation(auc)  # positive | negative | near-neutral, band 0.05


def cross_status(o_can: str, o_nf: str) -> str:
    c, n = o_can != NN, o_nf != NN
    if c and n:
        return PRESERVED if o_can == o_nf else REVERSED
    return NEUTRALIZED if c else EMERGED if n else BOTH_NEUTRAL


def auc_sep(auc: float) -> float:
    return max(auc, 1 - auc)


def magnitude_change(sep_can: float, sep_nf: float) -> bool:
    return round(abs(sep_nf - sep_can), 12) >= NEUTRAL  # same fp guard as orientation


def reading(status: str, mag: bool) -> str:
    if status == REVERSED:
        return "C-like"
    if status == NEUTRALIZED:
        return "D-like"
    if status == EMERGED:
        return "E-like"
    return "B-like" if mag else "A-like"


def assign_case(rows: list[dict]) -> str:
    """Frozen aggregate rule, checked in order D, C, E, B, A.
    rows: dicts with 'status', 'magnitude_change', 'canonical_orientation'."""
    n_conf = sum(r["canonical_orientation"] != NN for r in rows)
    lost = sum(r["status"] in (REVERSED, NEUTRALIZED) for r in rows)
    if n_conf and 2 * lost > n_conf:
        return "D"
    if any(r["status"] == REVERSED for r in rows):
        return "C"
    if any(r["status"] in (NEUTRALIZED, EMERGED) for r in rows):
        return "E"
    return "B" if any(r["magnitude_change"] for r in rows) else "A"


def tie_share(x: np.ndarray, y: np.ndarray) -> float:
    """Fraction of (x, y) pairs with x == y: the P(tie) inside AUC_pair."""
    _, inv = np.unique(np.concatenate([x, y]), return_inverse=True)
    cx = np.bincount(inv[: len(x)], minlength=inv.max() + 1).astype(np.float64)
    cy = np.bincount(inv[len(x):], minlength=inv.max() + 1).astype(np.float64)
    return float((cx * cy).sum() / (len(x) * len(y)))


def gap_readout(g_can: float, g_nf: float) -> str:
    """ORDER PRESERVED / CONVERGED / INVERTED, relative to canonical's sign."""
    d = round(g_nf, 12)
    if abs(d) < NEUTRAL:
        return "CONVERGED"
    return "ORDER PRESERVED" if (d > 0) == (g_can > 0) else "INVERTED"


def weights(labels: list[str], scheme: str) -> dict[str, float]:
    if scheme == "equal_mechanism":
        return {lab: 1 / len(labels) for lab in labels}
    idx = {"canonical_row_share": 1, "nf_row_share": 2}[scheme]
    tot = sum(LABELS[lab][idx] for lab in labels)
    return {lab: LABELS[lab][idx] / tot for lab in labels}


WEIGHTINGS = ["canonical_row_share", "nf_row_share", "equal_mechanism"]


class Side:
    """One representation: attack labels, benign mask, A_bytes/A_packets, reply masks."""

    def __init__(self, name, label, benign, fb, bb, fp, bp, capture=None, fhash=None):
        self.name = name
        self.label = np.asarray(label)
        self.benign = np.asarray(benign, dtype=bool)
        self.x = {"A_bytes": directional(fb, bb), "A_packets": directional(fp, bp)}
        self.reply = {"bytes": np.asarray(bb) > 0, "packets": np.asarray(bp) > 0}
        self.capture = capture
        self.fhash = fhash

    def mask(self, labels: list[str]) -> np.ndarray:
        return ~self.benign & np.isin(self.label, labels)

    def pooled_auc(self, labels: list[str], feat: str) -> tuple[float, int]:
        """AUC_signed of the POOLED attack rows of `labels` vs. this side's
        global benign. Never an average of per-label AUCs."""
        m = self.mask(labels)
        return a2.counting_auc(self.x[feat][self.benign], self.x[feat][m]), int(m.sum())

    def describe(self, labels: list[str], feat: str) -> dict:
        """AUC_signed/AUC_sep (relative) + absolute direction + reply rates."""
        m = self.mask(labels)
        auc, n = self.pooled_auc(labels, feat)
        xa, xb = self.x[feat][m], self.x[feat][self.benign]
        return {
            "n_attack": n, "n_benign": int(self.benign.sum()),
            "auc_signed": auc, "auc_sep": auc_sep(auc), "orientation": orientation(auc),
            "median_A_attack": float(np.median(xa)), "p_A_attack_gt0": float((xa > 0).mean()),
            "median_A_benign": float(np.median(xb)), "p_A_benign_gt0": float((xb > 0).mean()),
            "reply_attack_bytes": float(self.reply["bytes"][m].mean()),
            "reply_benign_bytes": float(self.reply["bytes"][self.benign].mean()),
            "reply_attack_packets": float(self.reply["packets"][m].mean()),
            "reply_benign_packets": float(self.reply["packets"][self.benign].mean()),
        }

    def pair_auc(self, x_lab: str, y_lab: str, feat: str) -> float:
        """AUC_pair(X vs Y): X rows in the attack role, Y rows as reference."""
        return a2.counting_auc(self.x[feat][self.mask([y_lab])], self.x[feat][self.mask([x_lab])])


# ---- loading -----------------------------------------------------------------
def load_canonical(data_dir: Path) -> Side:
    """load_csv per file (== load_directory: per-file .unique(), then concat)."""
    from src.ingest.loader import load_csv
    cols = ["label", "is_attack", "totlen_fwd_pkts", "totlen_bwd_pkts",
            "tot_fwd_pkts", "tot_bwd_pkts"]
    frames = []
    for p in sorted(data_dir.glob("*.csv")):
        print(f"  canonical: {p.name}", flush=True)
        frames.append(load_csv(p).collect().select(cols).with_columns(
            pl.col("label").str.strip_chars(), pl.lit(p.name).alias("capture_file")))
    df = pl.concat(frames).filter(pl.col("label") != ARTIFACT)
    feats = cols[2:]
    nulls = df.select(pl.col(feats).null_count()).row(0, named=True)
    if any(nulls.values()):
        raise ValueError(f"canonical directional fields have nulls: {nulls}")
    return Side("canonical", df["label"].to_numpy(), (df["is_attack"] == 0).to_numpy(),
                *[df[c].to_numpy() for c in feats], capture=df["capture_file"].to_numpy())


def load_nf(path: Path) -> tuple[Side, dict]:
    from src.ingest.nf_cse_cicids2018_v2 import load_nf_cse_cicids2018_v2
    df, info = load_nf_cse_cicids2018_v2(path)
    return Side("nf", df["Attack"].to_numpy(), (df["Label"] == 0).to_numpy(),
                df["IN_BYTES"].to_numpy(), df["OUT_BYTES"].to_numpy(),
                df["IN_PKTS"].to_numpy(), df["OUT_PKTS"].to_numpy(),
                fhash=df["feature_hash"].to_numpy()), info


# ---- canonical gates -----------------------------------------------------------
def committed_global() -> dict[tuple[str, str], tuple[float, int, int]]:
    out = {}
    with open(ROOT / "results/audit/a2_reply/auc_by_slice.csv", newline="") as fh:
        for r in csv.DictReader(fh):
            if r["dataset"] == "cicids" and r["slice"] == "all" and r["group"] != ARTIFACT:
                out[(r["group"], r["feature"])] = (
                    float(r["auc_signed"]), int(r["n_attack"]), int(r["n_benign"]))
    return out


def canonical_gates(can: Side) -> tuple[list[dict], dict]:
    gates: list[dict] = []

    def g(gate, item, feature, expected, got, tol):
        diff = abs(got - expected)
        gates.append(dict(gate=gate, item=item, feature=feature, expected=expected, got=got,
                          abs_diff=diff, tol=tol, passed=bool(diff <= tol)))

    com = committed_global()
    per_label = {}
    for lab, (_, n_can, _) in LABELS.items():
        for feat in FEATURES:
            auc, n = can.pooled_auc([lab], feat)
            per_label[(lab, feat)] = auc
            exp_auc, exp_n, exp_b = com[(lab, feat)]
            g("G1 per-label global-benign AUC vs auc_by_slice.csv", lab, feat, exp_auc, auc, TOL)
            g("G1 n_attack vs auc_by_slice.csv", lab, feat, exp_n, n, 0)
            g("G1 n_attack vs frozen count", lab, feat, n_can, n, 0)
    g("G1 n_benign", "global benign", "", CAN_BENIGN, int(can.benign.sum()), 0)

    def nweighted_committed(labels, feat):
        ns = [com[(lab, feat)][1] for lab in labels]
        return sum(com[(lab, feat)][0] * n for lab, n in zip(labels, ns)) / sum(ns)

    for cat, labs in SECONDARY.items():
        w = weights(labs, "canonical_row_share")
        for feat in FEATURES:
            pooled, _ = can.pooled_auc(labs, feat)
            std = sum(w[lab] * per_label[(lab, feat)] for lab in labs)
            g("G2 SECONDARY pooling identity: canonical-row-share value vs direct pooled",
              cat, feat, pooled, std, TOL)
            g("G2 SECONDARY direct pooled vs n-weighted mean of committed per-label AUCs",
              cat, feat, nweighted_committed(labs, feat), pooled, TOL)
    for cat, labs in DIAGNOSTIC.items():
        for feat in FEATURES:
            pooled, _ = can.pooled_auc(labs, feat)
            g("G3 DIAGNOSTIC direct pooled vs n-weighted mean of committed per-label AUCs",
              cat, feat, nweighted_committed(labs, feat), pooled, TOL)
            val, dp = FREEZE_POOLED[(cat, feat)]
            g("G3 DIAGNOSTIC direct pooled vs value printed in freeze envelope table",
              cat, feat, val, pooled, 0.5 * 10 ** -dp + 1e-12)

    # G4: capture-matched per-label AUCs reproduce committed a3_cicids_labels.csv.
    cm = capture_matched(can)
    with open(ROOT / "results/audit/a3_cicids_labels.csv", newline="") as fh:
        a3 = {(r["capture_file"], r["label"]): r for r in csv.DictReader(fh)
              if r["label"] != ARTIFACT}
    if set(a3) != {(r["capture_file"], r["label"]) for r in cm}:
        gates.append(dict(gate="G4 capture-matched (file,label) set vs a3", item="set",
                          feature="", expected=len(a3), got=len(cm), abs_diff=None, tol=0,
                          passed=False))
    for r in cm:
        ref = a3.get((r["capture_file"], r["label"]))
        if ref is None:
            continue
        item = f'{r["capture_file"]}|{r["label"]}'
        g("G4 capture-matched n vs a3_cicids_labels.csv", item, "", int(ref["n"]), r["n"], 0)
        g("G4 capture-matched AUC vs a3_cicids_labels.csv", item, "A_bytes",
          float(ref["auc_signed_bytes"]), r["auc_signed_bytes"], TOL)
        g("G4 capture-matched AUC vs a3_cicids_labels.csv", item, "A_packets",
          float(ref["auc_signed_packets"]), r["auc_signed_packets"], TOL)
    return gates, per_label


def capture_matched(can: Side) -> list[dict]:
    """Context only (canonical-only, no NF counterpart): each label vs its own
    capture file's benign, as Phase I A3."""
    rows = []
    for f in np.unique(can.capture):
        in_f = can.capture == f
        ben = in_f & can.benign
        for lab in np.unique(can.label[in_f & ~can.benign]):
            m = in_f & ~can.benign & (can.label == lab)
            rows.append({
                "capture_file": str(f), "label": str(lab), "n": int(m.sum()),
                "n_benign_capture": int(ben.sum()),
                "auc_signed_bytes": a2.counting_auc(can.x["A_bytes"][ben], can.x["A_bytes"][m]),
                "auc_signed_packets": a2.counting_auc(can.x["A_packets"][ben],
                                                      can.x["A_packets"][m]),
                "note": "canonical-only, no NF counterpart; takes no part in any case"})
    return rows


# ---- tiers ----------------------------------------------------------------------
def primary(can: Side, nf: Side) -> tuple[list[dict], dict]:
    fine, desc = [], {}
    for lab, (cat, _, _) in LABELS.items():
        for feat in FEATURES:
            dc, dn = can.describe([lab], feat), nf.describe([lab], feat)
            desc[(lab, feat)] = (dc, dn)
            st = cross_status(dc["orientation"], dn["orientation"])
            mag = magnitude_change(dc["auc_sep"], dn["auc_sep"])
            ws = lab in WELL_SUPPORTED
            for side, d in (("canonical", dc), ("nf", dn)):
                fine.append({
                    "side": side, "label": lab, "coarse_category": cat, "feature": feat, **d,
                    "status": st, "magnitude_change": mag,
                    "per_label_reading": reading(st, mag) if ws else "UNDER-SUPPORTED",
                    "well_supported": ws, "enters_case": ws and feat == PRIMARY_FEATURE,
                    "q2_nf_sep_ge_0_55": (dn["auc_sep"] >= 0.55)
                    if st in (REVERSED, NEUTRALIZED) else None})
    return fine, desc


def case_rows(fine: list[dict], feat: str) -> list[dict]:
    return [{"label": r["label"], "status": r["status"],
             "magnitude_change": r["magnitude_change"],
             "canonical_orientation": r["orientation"]}
            for r in fine if r["side"] == "canonical" and r["feature"] == feat
            and r["well_supported"]]


def ddos_ordering(desc: dict) -> list[dict]:
    rows = []
    for lab, ref in GAPS:
        for feat in FEATURES:
            (c1, n1), (c0, n0) = desc[(lab, feat)], desc[(ref, feat)]
            gc, gn = c1["auc_signed"] - c0["auc_signed"], n1["auc_signed"] - n0["auc_signed"]
            rows.append({"label": lab, "reference_label": ref, "feature": feat,
                         "G_canonical": gc, "G_nf": gn, "G_change": gn - gc,
                         "readout": gap_readout(gc, gn), "assigns_case": False})
    return rows


def secondary(desc: dict) -> list[dict]:
    rows = []
    for cat, labs in SECONDARY.items():
        for feat in FEATURES:
            vals = {}
            for wname in WEIGHTINGS:
                w = weights(labs, wname)
                for i, side in enumerate(("canonical", "nf")):
                    vals[(wname, side)] = sum(w[lab] * desc[(lab, feat)][i]["auc_signed"]
                                              for lab in labs)
            frag = {}
            for side in ("canonical", "nf"):
                v = [vals[(wn, side)] for wn in WEIGHTINGS]
                frag[side] = (round(max(v) - min(v), 12) >= NEUTRAL
                              or len({orientation(x) for x in v}) > 1)
            cross = {wn: cross_status(orientation(vals[(wn, "canonical")]),
                                      orientation(vals[(wn, "nf")])) for wn in WEIGHTINGS}
            conv_dep = len(set(cross.values())) > 1
            for wn in WEIGHTINGS:
                w = weights(labs, wn)
                for side in ("canonical", "nf"):
                    v = vals[(wn, side)]
                    rows.append({
                        "category": cat, "weighting": wn, "side": side, "feature": feat,
                        "weights": ";".join(f"{lab}={w[lab]:.6f}" for lab in labs),
                        "auc_signed_standardized": v, "auc_sep": auc_sep(v),
                        "orientation": orientation(v), "cross_side_status": cross[wn],
                        "weighting_fragile_this_side": frag[side],
                        "convention_dependent": conv_dep, "assigns_case": False})
    return rows


def diagnostic(can: Side, nf: Side, desc: dict, fine: list[dict]) -> list[dict]:
    rows = []
    for cat, labs in DIAGNOSTIC.items():
        for feat in FEATURES:
            dc, dn = can.describe(labs, feat), nf.describe(labs, feat)
            sub = [desc[(lab, feat)][0]["auc_signed"] for lab in labs]
            lo, hi = min(sub), max(sub)
            if len(labs) == 1:
                indeterminate = dn["auc_signed"] == lo
            else:
                indeterminate = lo <= dn["auc_signed"] <= hi
            st = cross_status(dc["orientation"], dn["orientation"])
            sub_st = sorted({r["status"] for r in fine if r["side"] == "canonical"
                             and r["feature"] == feat and r["label"] in labs
                             and r["well_supported"]})
            rows.append({
                "category": cat, "feature": feat, "sub_labels": ";".join(labs),
                "canonical_n_attack": dc["n_attack"], "nf_n_attack": dn["n_attack"],
                "canonical_n_benign": dc["n_benign"], "nf_n_benign": dn["n_benign"],
                "canonical_auc_signed_raw": dc["auc_signed"], "nf_auc_signed_raw": dn["auc_signed"],
                "canonical_auc_sep": dc["auc_sep"], "nf_auc_sep": dn["auc_sep"],
                "canonical_orientation": dc["orientation"], "nf_orientation": dn["orientation"],
                "status": st, "magnitude_change": magnitude_change(dc["auc_sep"], dn["auc_sep"]),
                "envelope_min": lo, "envelope_max": hi,
                "composition_indeterminate": indeterminate,
                "primary_statuses_of_well_supported_sub_labels": ";".join(sub_st),
                "agrees_with_primary": sub_st == [st],
                "coarse_artifact": (not indeterminate) and st not in sub_st,
                "label": "DIAGNOSTIC - composition exposed; never evidence of a "
                         "representation effect"})
    return rows


def tertiary(can: Side, nf: Side) -> list[dict]:
    rows = []
    for x_lab, y_lab in PAIRS:
        mx, my = nf.mask([x_lab]), nf.mask([y_lab])
        hx, hy = nf.fhash[mx], nf.fhash[my]
        ident = (int(np.isin(hx, hy).sum()), int(np.isin(hy, hx).sum()))
        for feat in FEATURES:
            per = {}
            for side in (can, nf):
                xs, ys = side.x[feat][side.mask([x_lab])], side.x[feat][side.mask([y_lab])]
                auc = side.pair_auc(x_lab, y_lab, feat)
                per[side.name] = (auc, len(xs), len(ys), tie_share(xs, ys))
            st = cross_status(orientation(per["canonical"][0]), orientation(per["nf"][0]))
            for name, (auc, nx, ny, ties) in per.items():
                rows.append({
                    "X": x_lab, "Y": y_lab, "side": name, "feature": feat,
                    "n_X": nx, "n_Y": ny, "auc_pair": auc, "auc_sep": auc_sep(auc),
                    "orientation": orientation(auc), "cross_side_status": st,
                    "tie_share": ties,
                    "n_X_rows_feature_identical_to_a_Y_row": ident[0] if name == "nf" else None,
                    "n_Y_rows_feature_identical_to_an_X_row": ident[1] if name == "nf" else None,
                    "assigns_case": False})
    return rows


# ---- output --------------------------------------------------------------------
def write(name: str, rows: list[dict]) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / name
    pl.DataFrame(rows, infer_schema_length=None).write_csv(p)
    print(f"wrote {p} ({len(rows)} rows)", flush=True)
    return p


def side_table(fine: list[dict], diag_desc: list[dict], side: str) -> list[dict]:
    keep = ["n_attack", "n_benign", "auc_signed", "auc_sep", "orientation", "median_A_attack",
            "p_A_attack_gt0", "median_A_benign", "p_A_benign_gt0", "reply_attack_bytes",
            "reply_benign_bytes", "reply_attack_packets", "reply_benign_packets"]
    out = [{"level": "fine_label (PRIMARY)", "name": r["label"], "feature": r["feature"],
            "well_supported": r["well_supported"], **{k: r[k] for k in keep}}
           for r in fine if r["side"] == side]
    out += [{"level": "coarse_raw (DIAGNOSTIC - composition exposed)", "name": d["category"],
             "feature": d["feature"], "well_supported": None, **{k: d[side][k] for k in keep}}
            for d in diag_desc]
    return out


def comparison(desc: dict) -> list[dict]:
    rows = []
    for lab in WELL_SUPPORTED:
        c, n = desc[(lab, PRIMARY_FEATURE)]
        rows.append({
            "category": lab,
            "canonical_auc_signed": c["auc_signed"], "nfv2_auc_signed": n["auc_signed"],
            "delta_auc_signed": n["auc_signed"] - c["auc_signed"],
            "canonical_orientation": c["orientation"], "nfv2_orientation": n["orientation"],
            "same_side_0_5": bool((c["auc_signed"] - 0.5) * (n["auc_signed"] - 0.5) > 0),
            "canonical_auc_sep": c["auc_sep"], "nfv2_auc_sep": n["auc_sep"],
            "delta_auc_sep": n["auc_sep"] - c["auc_sep"],
            "canonical_reply_attack": c["reply_attack_bytes"],
            "nfv2_reply_attack": n["reply_attack_bytes"],
            "canonical_reply_benign": c["reply_benign_bytes"],
            "nfv2_reply_benign": n["reply_benign_bytes"]})
    return rows


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 24), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                          text=True).stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canonical-dir", type=Path, required=True)
    ap.add_argument("--nf-path", type=Path)
    ap.add_argument("--canonical-only", action="store_true",
                    help="run the canonical reproduction gates and stop (NF never opened)")
    args = ap.parse_args()
    if not args.canonical_only and args.nf_path is None:
        ap.error("--nf-path is required unless --canonical-only")
    assert len(WELL_SUPPORTED) == 11, WELL_SUPPORTED

    prov = {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "git_head": git_head(), "freeze_commit": FREEZE_COMMIT,
            "command": " ".join(sys.argv), "python": sys.version,
            "platform": platform.platform(), "polars": pl.__version__,
            "numpy": np.__version__}
    print(json.dumps(prov, indent=1), flush=True)

    print("loading canonical", flush=True)
    can = load_canonical(args.canonical_dir)
    gates, _ = canonical_gates(can)
    write("canonical_reproduction.csv", gates)
    failed = [x for x in gates if not x["passed"]]
    print(f"canonical gates: {len(gates) - len(failed)}/{len(gates)} passed", flush=True)
    if failed:
        for x in failed:
            print("FAILED", x)
        sys.exit("BLOCKED: canonical reproduction gate failed; NF not touched")
    if args.canonical_only:
        return

    print("NF SHA256 check", flush=True)
    s256 = sha256(args.nf_path)
    if s256 != NF_SHA256:
        sys.exit(f"BLOCKED: NF SHA256 {s256} != frozen {NF_SHA256}")
    nf, info = load_nf(args.nf_path)
    found = {"rows": info["n_raw"], "benign": info["n_benign_raw"],
             "attack": info["n_attack_raw"]}
    if found != NF_GATE:
        sys.exit(f"BLOCKED: NF row-count gate {found} != {NF_GATE}")
    nf_counts = {lab: int(nf.mask([lab]).sum()) for lab in LABELS}
    if nf_counts != {lab: v[2] for lab, v in LABELS.items()} or set(
            np.unique(nf.label[~nf.benign])) != set(LABELS):
        sys.exit(f"BLOCKED: NF label counts differ from the frozen table: {nf_counts}")
    prov.update(nf_sha256=s256, nf_gate=found,
                nf_exact_duplicates_removed=info["n_exact_duplicates_removed"])

    print("PRIMARY", flush=True)
    fine, desc = primary(can, nf)
    print("SECONDARY / DIAGNOSTIC / TERTIARY", flush=True)
    sec = secondary(desc)
    diag = diagnostic(can, nf, desc, fine)
    diag_desc = [{"category": cat, "feature": feat, "canonical": can.describe(labs, feat),
                  "nf": nf.describe(labs, feat)}
                 for cat, labs in DIAGNOSTIC.items() for feat in FEATURES]
    pairs = tertiary(can, nf)

    cases = {}
    for feat in FEATURES:
        cases[f"primary_{feat}"] = assign_case(case_rows(fine, feat))
        cases[f"diagnostic_raw_coarse_{feat}"] = assign_case(
            [{"status": d["status"], "magnitude_change": d["magnitude_change"],
              "canonical_orientation": d["canonical_orientation"]}
             for d in diag if d["feature"] == feat])
    prov["case_primary_A_bytes (the A4 case)"] = cases["primary_A_bytes"]
    prov["case_primary_A_packets (reported, NOT assigned per freeze)"] = cases["primary_A_packets"]
    prov["case_if_diagnostic_raw_coarse_were_primary_A_bytes (Q6, NOT assigned)"] = cases[
        "diagnostic_raw_coarse_A_bytes"]
    prov["diagnostic_would_suggest_different_case"] = (
        cases["diagnostic_raw_coarse_A_bytes"] != cases["primary_A_bytes"])

    reply = [{"side": r["side"], "level": "fine_label", "name": r["label"],
              "n_attack": r["n_attack"], "n_benign": r["n_benign"],
              **{k: r[k] for k in ("reply_attack_bytes", "reply_benign_bytes",
                                   "reply_attack_packets", "reply_benign_packets")},
              "byte_vs_packet_gap_attack": r["reply_attack_packets"] - r["reply_attack_bytes"]}
             for r in fine if r["feature"] == PRIMARY_FEATURE]
    reply += [{"side": s, "level": "coarse_raw (DIAGNOSTIC)", "name": d["category"],
               "n_attack": d[s]["n_attack"], "n_benign": d[s]["n_benign"],
               **{k: d[s][k] for k in ("reply_attack_bytes", "reply_benign_bytes",
                                       "reply_attack_packets", "reply_benign_packets")},
               "byte_vs_packet_gap_attack": d[s]["reply_attack_packets"]
               - d[s]["reply_attack_bytes"]}
              for d in diag_desc if d["feature"] == PRIMARY_FEATURE for s in ("canonical", "nf")]

    paths = [
        write("fine_label_auc.csv", fine),
        write("comparison.csv", comparison(desc)),
        write("ddos_ordering.csv", ddos_ordering(desc)),
        write("coarse_standardized.csv", sec),
        write("coarse_diagnostic.csv", diag),
        write("pair_contrast.csv", pairs),
        write("reply_rates.csv", reply),
        write("canonical_capture_matched.csv", capture_matched(can)),
        write("canonical_categories.csv", side_table(fine, diag_desc, "canonical")),
        write("nfv2_categories.csv", side_table(fine, diag_desc, "nf")),
    ]
    prov["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    prov["output_sha256"] = {p.name: sha256(p) for p in
                             [OUT / "canonical_reproduction.csv", *paths]}
    (OUT / "run_summary.json").write_text(json.dumps(prov, indent=1))
    print(json.dumps(prov, indent=1))


if __name__ == "__main__":
    main()
