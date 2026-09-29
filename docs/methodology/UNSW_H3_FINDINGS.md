# UNSW-NB15 external validation of H3 -- findings

**Verdict (script-evaluated, FREEZE SS7.6): NO REPLICATION.** Same verdict in
the pre-registered deduplicated sensitivity run.

Every one of the nine UNSW-NB15 attack categories has `AUC_signed > 0.5` on
both pre-registered features, with the 95% CI above 0.5 in every case. No
category is inverted, so there is no opposite-sign pair and the H3 criterion
is not met. The CICIDS observation "the sign of per-flow asymmetry depends on
the attack mechanism" **did not transport to an independent dataset.**

- Freeze: `docs/methodology/UNSW_EXTERNAL_VALIDATION_FREEZE.md`, commit
  `6ba17f9` (2026-09-22 21:50 -06:00), pushed before any code ran (PR #37).
- Code: `4d7bc8f` (adapter + script), pushed before the first run.
- Numbers below: `fac0dac`.
- Command: `python scripts/run_unsw_external_validation.py --data-dir "C:\Users\DavidG\Downloads\UNSW-NB15"`
  (~5 min). Outputs: `results/unsw/`, `results/figures/unsw_*.pdf`.

**Execution record.** The first run (on `4d7bc8f`) finished both
populations, then crashed writing `verdict.json` because `np.bool_` is not
JSON-serializable. Its numbers were not inspected. `fac0dac` changes
serialization only, and the re-run used the same seed.
`run_metadata.json` says `git_dirty: true` only because the crashed run left
`results/unsw/` untracked. No source file differed from `fac0dac`.

## Primary result (all rows as released, B=2000, seed 20260922)

n_benign = 2,218,764. The role check applies to every row below:
`src_is_attacker = 1.000` and `dst_is_attacker = 0.000`.

| Category | n attack | AUC signed bytes | 95% CI | AUC sep | AUC signed packets | 95% CI | Orientation |
|---|--:|--:|--|--:|--:|--|--|
| Fuzzers | 24,246 | 0.8426 | [0.8413, 0.8438] | 0.8426 | 0.8810 | [0.8799, 0.8821] | positive |
| Analysis | 2,677 | 0.7965 | [0.7888, 0.8037] | 0.7965 | 0.9017 | [0.8976, 0.9055] | positive |
| Backdoors | 2,329 | 0.8654 | [0.8603, 0.8702] | 0.8654 | 0.9138 | [0.9091, 0.9180] | positive |
| DoS | 16,353 | 0.8410 | [0.8383, 0.8438] | 0.8410 | 0.8981 | [0.8957, 0.9005] | positive |
| Exploits | 44,525 | 0.6788 | [0.6758, 0.6817] | 0.6788 | 0.7405 | [0.7375, 0.7434] | positive |
| Generic | 215,481 | 0.8913 | [0.8908, 0.8918] | 0.8913 | 0.9394 | [0.9390, 0.9397] | positive |
| Reconnaissance | 13,987 | 0.8290 | [0.8275, 0.8304] | 0.8290 | 0.8821 | [0.8808, 0.8833] | positive |
| Shellcode | 1,511 | 0.8778 | [0.8737, 0.8818] | 0.8778 | 0.8966 | [0.8939, 0.8993] | positive |
| Worms | 174 | 0.7086 | [0.6607, 0.7532] | 0.7086 | 0.7238 | [0.6755, 0.7689] | positive |
| *All attacks (descriptive)* | 321,283 | 0.8518 | [0.8511, 0.8524] | 0.8518 | 0.9020 | [0.9014, 0.9026] | positive |

`AUC_sep = AUC_signed` everywhere because nothing is inverted, so H3b
(separability apart from orientation) adds no information here.
`A_bytes_attack_oriented` equals `A_bytes` exactly: the attacker is always
the source, so no row is flipped.

**Deduplicated sensitivity** (2,059,414 rows; attacks 321,283 → 99,643,
Generic 215,481 → 25,378): all nine categories stay positive and confident.
`A_bytes` ranges from 0.6412 (Exploits) to 0.9413 (Shellcode), and DoS is
0.7875 [0.7803, 0.7947]. Full table: `results/unsw/asymmetry_by_attack.csv`.

**H3-dir (secondary, CICIDS-derived, SS7.7):** "DoS negative": **failed**
(0.8410, confidently positive). "Exploits positive": held (0.6788,
confident). UNSW DoS goes the opposite way from CICIDS floods (0.003–0.381).

**Distributions (`A_bytes`, primary):** Benign median −0.219 (IQR 2.66).
Attack medians range from +1.67 (Exploits) to +5.30 (Analysis, Backdoors,
DoS). Every category's median-difference CI is above zero. See
`results/unsw/asymmetry_distributions.csv` and
`results/figures/unsw_asymmetry_distributions.pdf`.

## POST-HOC / EXPLORATORY -- why the signs are uniform

Not pre-registered and not part of the verdict. These are descriptive checks
run after the verdict to explain it, using this command:

```python
from pathlib import Path; import polars as pl
from src.ingest.unsw_nb15 import load_unsw, attacker_ips
d = Path(r"C:\Users\DavidG\Downloads\UNSW-NB15"); att = list(attacker_ips(d))
df = load_unsw(d).with_columns(pl.col("attack_category").fill_null("Normal"))
df.group_by("attack_category").agg(
    frac_dbytes0=(pl.col("bwd_bytes") == 0).mean(),
    frac_sbytes_gt_dbytes=(pl.col("fwd_bytes") > pl.col("bwd_bytes")).mean())
b = df.filter(pl.col("label") == 0)
b["src_ip"].is_in(att).sum(), b["dst_ip"].is_in(att).sum()
```

**1. Most UNSW attack flows receive no reply at all.**

| Category | share with `dbytes == 0` | share with `sbytes > dbytes` |
|---|--:|--:|
| Normal | 0.107 | 0.306 |
| Generic | 0.985 | 0.992 |
| Backdoors | 0.834 | 0.917 |
| DoS | 0.777 | 0.895 |
| Analysis | 0.765 | 0.774 |
| Shellcode | 0.504 | 1.000 |
| Reconnaissance | 0.498 | 0.996 |
| Exploits | 0.369 | 0.663 |
| Fuzzers | 0.361 | 0.983 |
| Worms | 0.121 | 0.822 |

The ECDF step at `A_bytes ≈ 5.30` for Analysis, Backdoors and DoS matches
`log(201)` with `dbytes = 0`, i.e. a fixed-size unanswered request. In
UNSW-NB15 the positive orientation is mostly produced by **targets that do
not answer**. The CICIDS mechanistic reading (a flood's server responds, so
fwd ≪ bwd) needs a target that responds. The UNSW testbed mostly does not
provide one. The sign therefore looks like a property of **target behaviour
in the capture environment**, not of the attack family name.

**2. The 100% "attacker is the source" is a labeling property, not a
network fact.** Among Label=0 ("Normal") rows, **214,378 have an attacker
host (175.45.176.0–3) as destination and 40,413 have one as source**. That is
about 11.5% of Normal touching attacker hosts. UNSW-NB15 labels as attack
only the flows the attacker initiates. This rules out the protocol-SS10
worry that the signs come from the exporter inverting src/dst. It also means
that some attacker-involved traffic sits in the negative class. Whether
those 254k flows are responses, callbacks, or IXIA background traffic from
the same hosts is not determinable from the CSVs; it would need the PCAPs.

**3. Labeling sensitivity (addendum 2026-09-22, raised in review of
manuscript v1).** Concern: do the 254,791 attacker-involved Normal rows
inflate `AUC_signed`? Removing them from Normal
(`scripts/unsw_posthoc_label_sensitivity.py`, same `analyze()`, same B and
seed; output `results/unsw/posthoc_label_sensitivity.csv`) **raises** every
family's `A_bytes` AUC by +0.072 to +0.097. For example, DoS goes from 0.841
to 0.925 and Exploits from 0.679 to 0.751. All nine families remain
confidently positive. The concern is refuted in direction: those rows
*deflate* the positive orientation, so the primary result is conservative
with respect to labeling. The reason is descriptive:

| Normal subset | n | median `A_bytes` | share `A > 0` | share `dbytes == 0` |
|---|--:|--:|--:|--:|
| destination = attacker host | 214,378 | +5.58 | 0.9999 | 0.9997 |
| source = attacker host | 40,413 | +1.09 | 0.883 | 0.254 |
| no attacker host | 1,963,973 | −0.27 | 0.218 | 0.007 |

Almost all of Normal's one-way flows (the 0.107 in item 1) are traffic that
touches the testbed's attacker hosts. The rest of Normal is essentially
never one-way. So the unanswered-flow signature is a property of traffic
involving those hosts **regardless of label**, which is further support for
the environment reading. It remains POST-HOC.

## Interpretation (protocol SS24, scenario 3: no replication)

- The pre-registered test was run as frozen and failed. **H3 is not
  supported on UNSW-NB15.** This does not get amended.
- What survives from CICIDS is narrower. On CICIDS, per-flow directional
  asymmetry had a family-dependent sign. On UNSW-NB15 the sign is uniform
  (source dominates) and only the magnitude varies (0.68–0.89). **Directional
  asymmetry does not carry a stable, mechanism-determined orientation across
  datasets.** Using it as a universal NIDS feature with a fixed sign would be
  wrong on at least one of the two datasets.
- The POST-HOC checks point to environment and acquisition (does the target
  reply? which flows get labeled?) as the likely driver. That is a
  hypothesis generated here. Testing it would need a new freeze on a
  dataset not yet examined (e.g. BoT-IoT). UNSW-NB15 cannot be reused as a
  confirmatory set for it.
- **H4 (combined > per-flow under partial observability) is not triggered.**
  The protocol (SS19) makes H4 conditional on H3 replicating.
