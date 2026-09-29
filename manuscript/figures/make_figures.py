#!/usr/bin/env python3
"""Figures for manuscript/main.tex. Run from the repository root:

    python manuscript/figures/make_figures.py

UNSW-NB15 and BoT-IoT numbers are read from results/{unsw,botiot}/asymmetry_by_attack.csv
(the confirmatory outputs of scripts/run_unsw_external_validation.py and
scripts/run_botiot_h3.py). CICIDS-2018
per-capture AUCs are copied from docs/datos-reales/ANALISIS-DATOS-REALES.tex
(SS Completitud, 10-capture table), produced by
scripts/analyze_real_data.py::perflow_auc -- no CI was computed there, so none
is drawn.
"""

from pathlib import Path

import matplotlib
import polars as pl

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent

# (capture, attack labels, AUC_signed) -- ANALISIS-DATOS-REALES.tex, 10-capture table.
CICIDS = [
    ("Wed-21-02", "DDoS HOIC/LOIC-UDP", 0.003),
    ("Fri-16-02", "DoS Hulk/SlowHTTPTest", 0.023),
    ("Tue-20-02", "DDoS LOIC-HTTP", 0.381),
    ("Wed-28-02", "Infiltration", 0.494),
    ("Thu-01-03", "Infiltration", 0.537),
    ("Thu-15-02", "DoS GoldenEye/Slowloris", 0.590),
    ("Wed-14-02", "SSH/FTP brute force", 0.631),
    ("Thu-22-02", "Web brute force/XSS/SQLi", 0.633),
    ("Fri-23-02", "Web brute force/XSS/SQLi", 0.694),
    ("Fri-02-03", "Bot", 0.838),
]
UNSW_ORDER = ["Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits", "Generic",
              "Reconnaissance", "Shellcode", "Worms"]
BOTIOT_ORDER = ["Recon/Service scan", "Recon/OS fingerprint", "DDoS/TCP", "DDoS/UDP",
                "DDoS/HTTP", "DoS/TCP", "DoS/UDP", "DoS/HTTP", "Theft/Keylogging",
                "Theft/Data theft"]
BLUE, ORANGE, AQUA, GRAY = "#2a78d6", "#eb6834", "#1baf7a", "#8a8a85"


def _primary_bytes(path: Path) -> dict:
    t = pl.read_csv(path).filter(
        (pl.col("population") == "primary_all_rows") & (pl.col("feature") == "A_bytes"))
    return {r["category"]: r for r in t.iter_rows(named=True)}


def _panel(ax, order, rows, color, title):
    y = [rows[c]["auc_signed"] for c in order]
    err = [[rows[c]["auc_signed"] - rows[c]["ci_lo"] for c in order],
           [rows[c]["ci_hi"] - rows[c]["auc_signed"] for c in order]]
    ax.errorbar(range(len(order)), y, yerr=err, fmt="o", ms=7, color=color, capsize=3)
    ax.set_xticks(range(len(order)), order, rotation=40, ha="right", fontsize=8)
    ax.set_title(title, fontsize=10)


def main() -> None:
    u = _primary_bytes(ROOT / "results/unsw/asymmetry_by_attack.csv")
    b = _primary_bytes(ROOT / "results/botiot/asymmetry_by_attack.csv")

    fig, (a, c, d) = plt.subplots(1, 3, figsize=(15, 4.4), sharey=True,
                                  gridspec_kw={"width_ratios": [10, 9, 10]})
    for ax in (a, c, d):
        ax.axhspan(0.45, 0.55, color=GRAY, alpha=0.15, lw=0)
        ax.axhline(0.5, color=GRAY, lw=1)
        ax.set_ylim(0, 1)
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.25)

    a.plot(range(len(CICIDS)), [x[2] for x in CICIDS], "o", ms=7, color=ORANGE)
    a.set_xticks(range(len(CICIDS)), [x[1] for x in CICIDS], rotation=40, ha="right", fontsize=8)
    a.set_title("CICIDS-2018 (discovery), per capture", fontsize=10)
    a.set_ylabel(r"$AUC_{signed}$ of $A_{bytes}$ (attack vs. benign)")
    _panel(c, UNSW_ORDER, u, BLUE, "UNSW-NB15 (test 1): no replication")
    _panel(d, BOTIOT_ORDER, b, AQUA, "BoT-IoT (test 2): strong replication")

    fig.tight_layout()
    fig.savefig(OUT / "fig_orientation.pdf")


if __name__ == "__main__":
    main()
