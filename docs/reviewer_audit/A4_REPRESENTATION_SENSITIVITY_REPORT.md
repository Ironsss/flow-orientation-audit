# A4 — Same-traffic flow-representation sensitivity: report (2026-09-27)

**Status: POST-HOC REVIEWER ROBUSTNESS AUDIT.** A4 is not preregistered and
not confirmatory. It does **not** modify H2 or H3, does **not** replace the
preregistered BoT-IoT verdict, and does **not** retroactively change any
Phase I result. It tests one thing: how sensitive the per-mechanism
directional orientation on CSE-CIC-IDS2018 is to the flow representation
(CICFlowMeter vs. NetFlow-v2) *together with* each representation's own
benign reference. It uses no new capture environment.

**Headline.** Pre-committed aggregate case: **CASE C**. Two of the eight
well-supported labels that are confident in canonical are REVERSED under NF
(DDOS attack-HOIC, DoS attacks-Hulk). That is below the Case D threshold
(at least 5 of 8). Because C2 is unexcluded, this is **not** evidence that
the exporter alone reverses the sign.

## 1. Question

For each attack mechanism, does the signed directional orientation
(`A_bytes`, `AUC_signed` against global benign) seen in canonical
CSE-CIC-IDS2018 (CICFlowMeter) persist when the same fine-labelled
mechanism is represented by NF-CSE-CIC-IDS2018-v2? The secondary questions
Q2-Q6 are as frozen.

## 2. Threat to validity addressed

A reviewer can argue that the manuscript's directional-orientation findings
are properties of CICFlowMeter's flow construction (payload-only bytes,
first-packet direction, its segmentation) and not of the traffic. A4
re-measures the same capture under a second, independent exporter.

## 3. Frozen analysis

`docs/reviewer_audit/A4_REPRESENTATION_SENSITIVITY.md`, frozen at
**`946337f47c6c048fb81189af939d4d3989d2f725`** (tier amendment; freeze
history `5c93a54` → `fb814d1` → `0b705ad` → `946337f`), plus
`A4_FEATURE_MAPPING.md` and `A4_DATA_PREFLIGHT.md`. None of these was
modified by this task.

- **Implementation commit:** `923c8f4` ("A4 implementation (pre-execution)
  ..."). It was pushed to `origin/reviewer-audit-phase1` **before** the
  canonical gates ran and before the NF file was opened.
- **Command:**
  `.venv/Scripts/python.exe scripts/audit_a4_representation.py --canonical-dir C:/Users/DavidG/iag-symmetry/data/raw --nf-path C:/Users/DavidG/Downloads/b3427ed8ad063a09_MOHANAD_A4706/b3427ed8ad063a09_MOHANAD_A4706/data/NF-CSE-CIC-IDS2018-v2.csv`.
  A `--canonical-only` run executed first, at 2026-09-27T23:34:59Z, and
  never opened the NF file.
- **Run window:** 2026-09-27T23:37:39Z to 23:45:12Z (UTC). `git_head` at
  run: `923c8f4ad6bb232ee6264842ccd14242be4ca043`.
- **Environment:** Python 3.11.16 (MSC v.1944, 64-bit), polars 1.44.1,
  numpy 2.4.6, Windows 10 (10.0.19045).
- **AUC engine:** `counting_auc` from `scripts/audit_a2_reply_conditional.py`,
  imported unchanged. The band is the unchanged `run_unsw_external_validation.orientation`
  (`|AUC − 0.5| < 0.05` is near-neutral).
- **Implementation choices (none of them thresholds):**
  - Magnitude change is `round(|ΔAUC_sep|, 12) ≥ 0.05`. This is the same
    floating-point guard that `orientation` already uses.
  - A BOTH NEUTRAL label with no magnitude change gets the per-label reading
    "A-like". The freeze's per-label table does not list that combination;
    Case A's own definition covers it (see §16).
  - Category AUCs are always recomputed from the pooled rows. Weighted sums
    of per-label AUCs are computed only for the SECONDARY standardized
    values and the gates, as the freeze specifies.

## 4. Data provenance

| side | source | rows used |
|---|---|---|
| Canonical | `src/ingest/loader.py::load_csv` applied per file (identical to `load_directory`: per-file `.unique()`, inf/NaN→0), 10 files in `C:\Users\DavidG\iag-symmetry\data\raw` (the worktree's `data/raw` is empty because it is gitignored). Labels are `.str.strip_chars()`-ed. The 3 `"Label"` header-artifact rows are dropped | benign = `is_attack == 0`: 13,467,970. Attack rows are taken per fine label. There are 0 nulls in the four directional fields |
| NF | Standalone `NF-CSE-CIC-IDS2018-v2.csv` (UQ bag `b3427ed8ad063a09_MOHANAD_A4706`), loaded by the new `src/ingest/nf_cse_cicids2018_v2.py`. Every column is read as text, the four directional fields are cast strictly, and missing values are an error | 18,893,708 rows. Benign = `Label == 0`: 16,635,567. Attack: 2,258,141. **Exact full-row duplicates removed: 0** |

The run stops at the first gate that fails, in this order: SHA256 check,
row-count gate (18,893,708 / 16,635,567 / 2,258,141), then the 14 per-label
NF counts against the frozen table. All three passed. The merged
`NF-UQ-NIDS-v2.csv` was not read.

## 5. Dataset hashes

| file | SHA256 |
|---|---|
| `NF-CSE-CIC-IDS2018-v2.csv` (3,221,378,977 B) | `16a545a3e139b2e85d08b1b7d9d40328c3689a49d0deaafce6dcf8d7b63e1257`. Recomputed at run time and equal to the frozen value |
| `NF-UQ-NIDS-v2.csv` | not an input. Provenance only: `7e55364a…20c8` |
| canonical `data/raw/*.csv` | not rehashed. Identity is established by reproduction gate G1-G4 (§8) |

## 6. Feature-semantic mapping

As frozen (`A4_FEATURE_MAPPING.md`) and never flipped:

- `A_bytes`: canonical `log1p(totlen_fwd_pkts) − log1p(totlen_bwd_pkts)`,
  which counts **payload only**. NF `log1p(IN_BYTES) − log1p(OUT_BYTES)`,
  which counts **whole packets, including at least the IP header**.
- `A_packets`: `tot_fwd/bwd_pkts` vs. `IN/OUT_PKTS`, rated APPROXIMATELY
  COMPARABLE.

The NF loader keeps the NF field names. It does not rename them to
canonical names.

The source-endpoint rule is UNVERIFIED. In NF, bytes > 0 ⇔ packets > 0 by
construction, so NF's byte and packet reply rates are identical by
definition. That identity is **not** a finding.

## 7. Common label taxonomy

The mapping is the identity on 14 fine label strings. Eleven labels are
well-supported (`n_attack ≥ 1,000` on both sides). The three
under-supported labels (Brute Force -Web, -XSS, SQL Injection) are reported
and labelled UNDER-SUPPORTED, and they enter no case. The coarse categories
are the frozen ones: SECONDARY uses the well-supported sub-labels only;
DIAGNOSTIC follows NF's merge procedure (Brute Force = FTP + SSH + Web +
XSS), with injection excluded. The 4 tertiary pairs are the frozen,
exhaustive list.

## 8. Canonical reproduction check (before any NF number)

All gates are in `canonical_reproduction.csv`. **171 of 171 passed.**

| gate | checks | max abs diff | tol |
|---|---|---|---|
| G1 per-label global-benign `AUC_signed` vs. `results/audit/a2_reply/auc_by_slice.csv` (14 labels × 2 features) | 28 | **0.0** | 1e-9 |
| G1 `n_attack` vs. `auc_by_slice.csv` and vs. the frozen counts; `n_benign` = 13,467,970 | 57 | 0 | exact |
| G2 SECONDARY pooling identity: canonical-row-share Σ w·AUC vs. **direct pooled** AUC (DDoS, DoS, BF = SSH+FTP; × 2 features) | 6 | 1.1e-16 | 1e-9 |
| G2 direct pooled vs. n-weighted mean of committed per-label AUCs | 6 | 1.1e-16 | 1e-9 |
| G3 DIAGNOSTIC direct pooled vs. n-weighted mean of committed values (5 categories × 2) | 10 | 1.1e-16 | 1e-9 |
| G3 direct pooled vs. the value printed in the freeze's envelope table | 10 | 4.3e-5 | half the printed last digit (DDoS `A_bytes` 0.475455: 1.9e-7) |
| G4 capture-matched per-label AUC (`A_bytes`, `A_packets`) and n vs. committed `results/audit/a3_cicids_labels.csv` (18 file×label rows) | 54 | **0.0** | 1e-9 |

Canonical pooled values, recomputed from the raw rows: DDoS `A_bytes`
0.475455, DoS 0.668770, Brute Force (4 labels) 0.573858, Brute Force
(SSH+FTP) 0.573328, Bot 0.779423, Infilteration 0.510575. The new pipeline
therefore reproduces the committed canonical pipeline bit-for-bit.

`tests/test_cicids_capture_reference.py` (unmodified) passes in the full
suite. It covers the published per-capture figures.

## 9. Results

Sources: `fine_label_auc.csv`, `comparison.csv`, `ddos_ordering.csv`,
`coarse_standardized.csv`, `coarse_diagnostic.csv`, `pair_contrast.csv`.
Every tier uses global benign: canonical n_benign = 13,467,970; NF n_benign
= 16,635,567.

### 9.1 PRIMARY: fine-label-matched, `A_bytes` (the only tier that assigns a case)

| label | can n | NF n | can AUC_signed | NF AUC_signed | can AUC_sep | NF AUC_sep | status | magnitude Δ≥0.05 | reading |
|---|---|---|---|---|---|---|---|---|---|
| DDOS attack-HOIC | 668,461 | 1,080,858 | 0.5765 (+) | **0.2232 (−)** | 0.5765 | 0.7768 | **REVERSED** | yes | C-like |
| DDOS attack-LOIC-UDP | 1,730 | 2,112 | 1.0000 (+) | 1.0000 (+) | 1.0000 | 1.0000 | PRESERVED | no | A-like |
| DDoS attacks-LOIC-HTTP | 576,191 | 307,300 | 0.3567 (−) | 0.1289 (−) | 0.6433 | 0.8711 | PRESERVED | yes | B-like |
| DoS attacks-Hulk | 434,873 | 432,648 | 0.6807 (+) | **0.3493 (−)** | 0.6807 | 0.6507 | **REVERSED** | no | C-like |
| DoS attacks-SlowHTTPTest | 19,462 | 14,116 | 0.7087 (+) | 0.8745 (+) | 0.7087 | 0.8745 | PRESERVED | yes | B-like |
| DoS attacks-GoldenEye | 41,455 | 27,723 | 0.4668 (nn) | 0.5090 (nn) | 0.5332 | 0.5090 | BOTH NEUTRAL | no | A-like |
| DoS attacks-Slowloris | 10,285 | 9,512 | 0.9040 (+) | 0.9392 (+) | 0.9040 | 0.9392 | PRESERVED | no | A-like |
| Bot | 282,310 | 143,097 | 0.7794 (+) | 0.8728 (+) | 0.7794 | 0.8728 | PRESERVED | yes | B-like |
| Infilteration | 161,897 | 116,361 | 0.5106 (nn) | 0.4829 (nn) | 0.5106 | 0.5171 | BOTH NEUTRAL | no | A-like |
| FTP-BruteForce | 39,352 | 25,933 | 0.7087 (+) | 0.8745 (+) | 0.7087 | 0.8745 | PRESERVED | yes | B-like |
| SSH-Bruteforce | 117,322 | 94,979 | 0.5279 (nn) | **0.7067 (+)** | 0.5279 | 0.7067 | **EMERGED** | yes | E-like |
| *Brute Force -Web (under-supported)* | 611 | 2,143 | 0.7598 (+) | 0.3092 (−) | | | *REVERSED* | yes | UNDER-SUPPORTED |
| *Brute Force -XSS (under-supported)* | 230 | 927 | 0.4414 (−) | 0.2466 (−) | | | *PRESERVED* | yes | UNDER-SUPPORTED |
| *SQL Injection (under-supported)* | 87 | 432 | 0.5077 (nn) | 0.2516 (−) | | | *EMERGED* | yes | UNDER-SUPPORTED |

Summary over the 11 well-supported labels:

- 6 PRESERVED: LOIC-UDP and Slowloris with no magnitude change; LOIC-HTTP,
  SlowHTTPTest, Bot and FTP with a magnitude change, NF stronger in each.
- 2 REVERSED: HOIC and Hulk.
- 1 EMERGED: SSH.
- 2 BOTH NEUTRAL: GoldenEye and Infilteration.
- 0 NEUTRALIZED.

**`A_packets` primary (reported, no case assigned):**

- HOIC REVERSED (0.671 → 0.355).
- LOIC-UDP PRESERVED.
- LOIC-HTTP EMERGED (0.458 → 0.803).
- Hulk PRESERVED+mag (0.844 → 0.616).
- SlowHTTPTest PRESERVED+mag (0.288 → 0.353, both −).
- GoldenEye PRESERVED+mag (0.594 → 0.911).
- Slowloris PRESERVED+mag.
- Bot EMERGED (0.465 → 0.351, −).
- Infilteration PRESERVED.
- FTP PRESERVED+mag.
- SSH NEUTRALIZED (0.370 → 0.532).

Applying the case rule to `A_packets` would also give C. This is reported
only; the freeze assigns cases from `A_bytes` alone.

**Observed coincidence (descriptive).** In NF, SlowHTTPTest and
FTP-BruteForce again have almost identical `A_bytes` AUCs (0.874538 vs.
0.874549), and their `A_packets` AUCs are equal to 4 dp (0.3533). This
mirrors the canonical coincidence already disclosed in Phase I (0.7087 /
0.2884 for both). On the NF side the per-flow values were not investigated
further.

**Canonical SlowHTTPTest and FTP-BruteForce are exactly constant
(data-quality disclosure).** Checked afterwards from the raw rows
(`load_csv` per file, labels stripped): canonical `A_bytes` has **one
distinct value, exactly 0**, on all 19,462 SlowHTTPTest rows and all 39,352
FTP-BruteForce rows. Every row has 1 forward and 1 backward packet with zero
payload in both directions. These values are not near-constant. They have
zero variance. For these two labels the canonical `AUC_signed` of 0.7087
therefore measures only where the shared benign distribution sits relative
to exactly 0: benign median −0.320, `P(A>0)` = 0.174. The attack rows
contribute no variation. Their canonical "confident positive" orientation
says something about the benign reference. It says nothing about the attack
traffic. (Hulk is not in this position: 94.1% of its rows are exactly 0,
not 100%. See §10.)

**Robustness of the case to this caveat.** Drop the two degenerate labels
from the confident-canonical denominator. Six confident labels remain:
HOIC, LOIC-UDP, LOIC-HTTP, Hulk, Slowloris and Bot (source:
`fine_label_auc.csv`, canonical `orientation` ≠ near-neutral). Two of the
six are REVERSED (HOIC, Hulk) and none is NEUTRALIZED. Case D's frozen rule
is "more than half", which here means at least 4 of 6. Two is short of
that, so the classification stays **Case C**. The case does not depend on
counting the degenerate labels. This check is POST-HOC and assigns no case
of its own.

### 9.2 Q5: DDoS ordering (gap readout, assigns no case)

| gap | feature | G canonical | G NF | change | readout |
|---|---|---|---|---|---|
| LOIC-UDP − HOIC | A_bytes | 0.4235 | 0.7768 | +0.3533 | ORDER PRESERVED |
| LOIC-UDP − HOIC | A_packets | 0.3288 | 0.6448 | +0.3159 | ORDER PRESERVED |
| LOIC-HTTP − HOIC | A_bytes | −0.2198 | −0.0943 | +0.1256 | ORDER PRESERVED |
| LOIC-HTTP − HOIC | A_packets | −0.2128 | +0.4474 | +0.6603 | INVERTED |

As the freeze records, ±0.05 applied to a difference is a reuse of
convention, not a derived threshold.

### 9.3 SECONDARY: composition-standardized coarse (no case)

`A_bytes`, standardized `AUC_signed`, shown as canonical → NF:

| category | canonical row share | NF row share | equal-mechanism | WEIGHTING-FRAGILE (can / NF) | CONVENTION-DEPENDENT |
|---|---|---|---|---|---|
| DDoS | 0.4755 → 0.1806 EMERGED | 0.5286 → 0.2035 EMERGED | 0.6444 → 0.4507 NEUTRALIZED | yes / yes | **yes** |
| DoS | 0.6688 → 0.3946 REVERSED | 0.6736 → 0.3854 REVERSED | 0.6900 → 0.6680 PRESERVED | no / yes | **yes** |
| Brute Force (SSH+FTP) | 0.5733 → 0.7489 PRESERVED | 0.5667 → 0.7427 PRESERVED | 0.6183 → 0.7906 PRESERVED | yes / no | no |

`A_packets`:

- DDoS: PRESERVED / NEUTRALIZED / PRESERVED across the three weightings,
  so CONVENTION-DEPENDENT.
- DoS: PRESERVED under all three.
- Brute Force: NEUTRALIZED / NEUTRALIZED / PRESERVED, so
  CONVENTION-DEPENDENT.

Every side is WEIGHTING-FRAGILE for DDoS and DoS `A_packets`.

### 9.4 DIAGNOSTIC: raw coarse, composition exposed (never evidence)

| category | feature | can raw | NF raw | status | canonical envelope | composition-indeterminate | primary statuses of sub-labels | agrees | coarse artifact |
|---|---|---|---|---|---|---|---|---|---|
| DDoS | A_bytes | 0.4755 | 0.2035 | EMERGED | [0.3567, 1.0000] | no (outside) | PRESERVED; REVERSED | no | **yes** |
| DoS | A_bytes | 0.6688 | 0.3854 | REVERSED | [0.4668, 0.9040] | no (outside) | BOTH NEUTRAL; PRESERVED; REVERSED | no | no (echoed by Hulk) |
| Bot | A_bytes | 0.7794 | 0.8728 | PRESERVED | point | no | PRESERVED | yes | no |
| Infilteration | A_bytes | 0.5106 | 0.4829 | BOTH NEUTRAL | point | no | BOTH NEUTRAL | yes | no |
| Brute Force | A_bytes | 0.5739 | 0.7315 | PRESERVED | [0.4414, 0.7598] | **yes** | EMERGED; PRESERVED | no | no |
| DDoS | A_packets | 0.5732 | 0.4551 | NEUTRALIZED | [0.4583, 1.0000] | no | EMERGED; PRESERVED; REVERSED | no | **yes** |
| DoS | A_packets | 0.8004 | 0.6320 | PRESERVED | [0.2884, 0.8437] | yes | PRESERVED | yes | no |
| Bot | A_packets | 0.4652 | 0.3510 | EMERGED | point | no | EMERGED | yes | no |
| Infilteration | A_packets | 0.4316 | 0.3901 | PRESERVED | point | no | PRESERVED | yes | no |
| Brute Force | A_packets | 0.3520 | 0.4923 | NEUTRALIZED | [0.2884, 0.8226] | yes | NEUTRALIZED; PRESERVED | no | no |

Envelope rule: for single-label categories, "indeterminate only on exact
equality", which does not occur, so Bot and Infilteration read as
"outside". By construction their raw value equals the primary value.

### 9.5 TERTIARY / DESCRIPTIVE: benign-free same-capture pairs (assigns no case)

| X vs. Y | feature | canonical AUC_pair (tie share) | NF AUC_pair (tie share) | cross-side | NF rows feature-identical across the pair (X→Y / Y→X) |
|---|---|---|---|---|---|
| LOIC-UDP vs. HOIC | A_bytes | 1.0000 (0.000) | 1.0000 (0.000) | PRESERVED | 0 / 0 |
| LOIC-UDP vs. HOIC | A_packets | 1.0000 (0.000) | 1.0000 (0.000) | PRESERVED | 0 / 0 |
| SlowHTTPTest vs. Hulk | A_bytes | 0.5288 (**0.941**) | 0.9988 (0.000) | EMERGED | 0 / 0 |
| SlowHTTPTest vs. Hulk | A_packets | 0.0502 (0.011) | 0.1120 (0.214) | PRESERVED | 0 / 0 |
| Slowloris vs. GoldenEye | A_bytes | 0.9323 (0.075) | 0.9943 (0.000) | PRESERVED | 0 / 0 |
| Slowloris vs. GoldenEye | A_packets | 0.7602 (0.103) | 0.9410 (0.000) | PRESERVED | 0 / 0 |
| FTP vs. SSH | A_bytes | 0.8998 (0.200) | 0.9999 (0.000) | PRESERVED | 0 / 0 |
| FTP vs. SSH | A_packets | 0.3356 (**0.570**) | 0.2370 (0.348) | PRESERVED | 0 / 0 |

The canonical SlowHTTPTest vs. Hulk `A_bytes` value of 0.5288 is dominated
by ties: 94.1% of pairs are tied, entirely at `A_bytes = 0` (zero payload in
both directions -- every tie is at exactly 0, since SlowHTTPTest is
constant at 0 and the tied Hulk rows are its own zero-payload short
records, §9.1/§10). Every SlowHTTPTest row is exactly 0 (§9.1), and 94.1%
of Hulk rows are short, unidirectional, zero-payload flow records at exactly 0
(§10). Its
"near-neutral" reading is therefore a tie artifact of those zero-payload
rows, not an ordering. None of the 2,988 NF cross-label
feature-identical rows involve any of these four pairs: 0 identical rows in
each direction for every pair.

## 10. Absolute vs. relative orientation

The source is `fine_label_auc.csv` (`A_bytes`). Three separate readings are
kept apart: absolute direction (median, `P(A>0)`), relative direction
(`AUC_signed` vs. benign), and separability (`AUC_sep`).

| label | can median / P(A>0) | NF median / P(A>0) | can → NF AUC_signed | can → NF AUC_sep |
|---|---|---|---|---|
| benign (reference) | −0.320 / 0.174 | −0.288 / 0.162 | — | — |
| HOIC | **0.000 / 0.000** | **−0.788 / 0.0004** | 0.577 → 0.223 | 0.577 → 0.777 |
| LOIC-UDP | 15.16 / 1.000 | 15.62 / 1.000 | 1.000 → 1.000 | 1.000 → 1.000 |
| LOIC-HTTP | −3.83 / 0.001 | −1.59 / 0.089 | 0.357 → 0.129 | 0.643 → 0.871 |
| Hulk | **0.000 / 0.0006** | **−0.621 / 0.003** | 0.681 → 0.349 | 0.681 → 0.651 |
| SlowHTTPTest | 0.000 / 0.000 | 0.404 / 1.000 | 0.709 → 0.875 | 0.709 → 0.875 |
| GoldenEye | −0.503 / 0.052 | −0.387 / 0.090 | 0.467 → 0.509 | 0.533 → 0.509 |
| Slowloris | 2.83 / 0.759 | 3.03 / 0.948 | 0.904 → 0.939 | 0.904 → 0.939 |
| Bot | 0.000 / 0.489 | 0.455 / 0.993 | 0.779 → 0.873 | 0.779 → 0.873 |
| Infilteration | −0.293 / 0.117 | −0.345 / 0.222 | 0.511 → 0.483 | 0.511 → 0.517 |
| FTP-BruteForce | 0.000 / 0.000 | 0.405 / 1.000 | 0.709 → 0.875 | 0.709 → 0.875 |
| SSH-Bruteforce | −0.324 / 0.000 | −0.194 / 0.0007 | 0.528 → 0.707 | 0.528 → 0.707 |

**What reversed, in absolute terms.** In neither representation is HOIC or
Hulk forward-dominant: `P(A>0)` ≤ 0.35% on both sides. The canonical "+"
for these two labels was never an absolute forward-dominance. It comes from
one kind of row.

**Mechanism (corrected; POST-HOC row-level check).** The following was
checked on the raw rows (canonical: `load_csv` per file; NF: the A4
loader). These counts are not in the frozen outputs.

- **Canonical HOIC.** 504,711 of 668,461 rows (75.5%) are short unidirectional
  flow records: exactly 2 forward packets, 0 backward packets, and 0 payload bytes
  in both directions. Their `A_bytes` is exactly 0. The other 163,750 rows
  (24.5%, the reply rate in §11) are answered flows. Their medians are 309
  forward / 935 backward payload bytes and 3 / 4 packets, with a median
  `A_bytes` of −1.11. All of these answered rows sit **below** the canonical
  benign median of −0.32.
- **Canonical Hulk.** 409,325 of 434,873 rows (94.1%) have the same
  pattern: 2 forward packets (347,761 rows) or 3 (61,564 rows), 0 backward
  packets, 0 payload, and `A_bytes` exactly 0. The 25,548 answered rows
  (5.9%) have medians of 350 / 935 bytes and 3 / 4 packets, with a median
  `A_bytes` of −0.98. Of these, 96.3% sit below the benign median.
- **NF.** HOIC has a reply on every row (1.000). Its medians are IN 521 /
  OUT 1,147 bytes and 5 / 5 packets, with `A_bytes` −0.79. Hulk has a reply
  rate of 0.9996, with only 161 unanswered rows. Its medians are IN 3,054 /
  OUT 5,955 bytes and 25 / 24 packets, with `A_bytes` −0.62. Both sit below
  the NF benign median of −0.29.

The canonical positive orientation of HOIC and Hulk is dominated by the
large mass of short, unidirectional, zero-payload flow records at
`A_bytes = 0`. The corresponding answered canonical flows are predominantly
negative relative to benign, while these zero-payload records are
essentially absent under NF-v2. This pattern implicates differences in flow
construction/segmentation (how CICFlowMeter and the NetFlow-v2 pipeline cut
these attacks' traffic into flow records), while C2 and label-assignment
differences prevent a causal attribution to segmentation or the exporter
alone.

The data do **not** point to byte-accounting convention (payload-only vs.
header-inclusive). The part of this argument that cannot fail: these
records have zero backward bytes under either accounting convention (no
reply packets exist to carry headers), so `A_bytes = log1p(fwd) −
log1p(bwd)` stays **non-negative** under either convention (`bwd = 0` ⇒
`log1p(bwd) = 0`): exactly 0 under payload-only counting (canonical's
convention, since `fwd` payload is also 0 on these records -- consistent
with "their `A_bytes` is exactly 0" above), and strictly positive under
header-inclusive counting (NF's convention, since `fwd` headers are always
present) -- these rows cannot become negative under any byte-accounting
convention. Re-counting the same short unidirectional records with headers included,
as NF does, would additionally give a larger positive `fwd` value (headers
are always present even with zero payload), which pushes these rows
further above benign -- unless benign's own header-inclusive value shifted
by more, which would require an implausibly large shift (benign's own
values would need to move by more than `log1p(~100 bytes)` ≈ 4.6 to
reverse this, far more than the −0.32 → −0.29 / 0.174 → 0.162 shift in
benign's median/`P(A>0)` actually observed between the two
representations, below). Header-inclusive
counting of the canonical rows would strengthen the canonical "+", not
reverse it.

The benign reference's median and `P(A>0)` moved little between sides
(−0.32 → −0.29, 0.174 → 0.162). What moved is the composition of the
attack rows. This is descriptive and POST-HOC. It names which of the
confounded factors (§16) the row-level data implicate. It does not isolate
that factor causally. The benign distributions differ in more than median
and `P(A>0)`, so it does **not** exclude C2 (§14). No causal exporter claim
is made.

## 11. Reply-structure comparison (Q3)

Sources: `reply_rates.csv`, `comparison.csv`.

| | canonical P(bwd bytes>0) | canonical P(bwd pkts>0) | NF P(OUT>0) (bytes ≡ packets) |
|---|---|---|---|
| **benign** | 0.697 | 0.800 | **0.931** |
| HOIC | 0.245 | 0.245 | **1.000** |
| LOIC-UDP | 0.000 | 0.000 | 0.000 |
| LOIC-HTTP | 0.502 | 0.502 | 0.912 |
| Hulk | 0.059 | 0.059 | **0.9996** |
| SlowHTTPTest | 0.000 | 1.000 | 1.000 |
| GoldenEye | 0.647 | 0.670 | 1.000 |
| Slowloris | 0.014 | 0.773 | 0.760 |
| Bot | 0.506 | 0.507 | 1.000 |
| Infilteration | 0.562 | 0.845 | 0.983 |
| FTP-BruteForce | 0.000 | 1.000 | 1.000 |
| SSH-Bruteforce | 0.800 | 1.000 | 1.000 |

- Reply structure differs materially. Under NF almost every flow carries
  return traffic: every label except LOIC-UDP (0) and Slowloris (0.76) is at
  ≥ 0.91, and benign is at 0.93.
- Canonical has a large byte-vs-packet gap. SlowHTTPTest, FTP and Slowloris
  have packet replies but zero reply payload.
- NF has no such gap, by construction (§6).
- The two REVERSED labels (HOIC, Hulk) are exactly the labels whose
  **byte-based** reply rate moves most: 0.24 → 1.00 and 0.06 → 1.00. (On the
  **packet-based** rate, canonical SlowHTTPTest and FTP-BruteForce move
  further in absolute terms, 0 → 1.00, but neither of those reverses --
  see §9.1's constant-value disclosure for why their canonical reading
  doesn't track packet replies the way HOIC/Hulk's byte reading does.)

No threshold was set. This is descriptive.

## 12. Interpretation against the pre-committed Cases A-E

The case is assigned over the 11 well-supported labels, `A_bytes`,
checking D, C, E, B, A in that order:

- **D?** 8 labels are confident in canonical. 2 of them are REVERSED or
  NEUTRALIZED (HOIC, Hulk). 2 < 5, so D does **not** apply.
- **C?** At least one label is REVERSED (HOIC, Hulk). **CASE C applies.**

Pre-committed conclusion, verbatim in substance: the signed orientation of
at least one mechanism differs between the two
representation-plus-reference pairs. This is consistent with the
measurement-validity / non-transportability interpretation. It weakens any
claim that orientation is intrinsic to a mechanism. It is **not** evidence
that the exporter alone reverses the sign, because C2 is an unexcluded
alternative.

- **Reversed:** DDOS attack-HOIC, DoS attacks-Hulk.
- **Preserved:** LOIC-UDP, LOIC-HTTP, SlowHTTPTest, Slowloris, Bot, FTP.
- **Emerged:** SSH.
- **Both neutral:** GoldenEye, Infilteration.

**Q2.** Under the frozen band, a REVERSED label keeps `AUC_sep` ≥ 0.55 by
construction (REVERSED means confident on both sides, i.e. |AUC_signed −
0.5| ≥ 0.05 on both sides), so "both ≥ 0.55" alone is not new information.
The informative result is the magnitude: HOIC's separability rose
(0.577 → 0.777) and Hulk's barely moved (0.681 → 0.651). A sign reversal
did not come with a loss of discriminative strength for either label; for
HOIC it came with a gain. "Only orientation changed" therefore
understates HOIC's case, where the magnitude changed too (§9.1 marks HOIC
`A_bytes` with a magnitude change, Δ|AUC_sep| ≥ 0.05).

**Q4.** Effects depend on the mechanism. Statuses range over PRESERVED,
REVERSED, EMERGED and BOTH NEUTRAL.

**Q5.** Against global benign, the DDoS gap LOIC-UDP ≫ HOIC is ORDER
PRESERVED and widens. LOIC-HTTP stays below HOIC under `A_bytes` (ORDER
PRESERVED) and inverts under `A_packets`. Tertiary context, which is
descriptive only: the same-capture LOIC-UDP vs. HOIC contrast is 1.000 on
both sides with no ties. The benign-free relative ordering of that pair
persists. None of the four pair contrasts reverses. The one status change,
SlowHTTPTest vs. Hulk `A_bytes` (EMERGED), comes from a canonical value
that is 94% ties.

**Q6.** The diagnostic raw coarse framing would also have produced Case C
(from DoS REVERSED). So the diagnostic reading would **not** have suggested
a different case. It would still have misled at the category level:

- **DDoS `A_bytes`** reads EMERGED (near-neutral → negative). No sub-label
  shows that status (HOIC REVERSED, LOIC-UDP and LOIC-HTTP PRESERVED), and
  the value is outside the envelope. By the frozen rule this is a
  **coarse artifact**.
- **DDoS `A_packets`** reads NEUTRALIZED. This is also a coarse artifact.
- **Brute Force `A_bytes`** reads PRESERVED. The primary tier shows SSH
  EMERGED under it, and the value is composition-indeterminate (inside the
  envelope).
- **DoS `A_bytes`** reads REVERSED for the category. Only Hulk reversed.
  GoldenEye is neutral, and SlowHTTPTest and Slowloris are preserved.

In the secondary tier, DDoS and DoS `A_bytes` are CONVENTION-DEPENDENT.
Under equal-mechanism weighting DoS reads PRESERVED rather than REVERSED,
and DDoS reads NEUTRALIZED rather than EMERGED.

## 13. What changed

- The sign against global benign changed for **HOIC** and **Hulk**
  (positive → negative). Separability did not disappear: HOIC's `AUC_sep`
  rose (0.577 → 0.777) and Hulk's barely moved (0.681 → 0.651) -- see Q2's
  caveat that "≥ 0.55 both sides" is true by construction for any REVERSED
  label, so the magnitude, not the bare threshold, is the finding.
- **SSH-Bruteforce** gained a positive orientation (0.528 → 0.707).
- Magnitude grew under NF for LOIC-HTTP, SlowHTTPTest, Bot, FTP, SSH and
  HOIC.
- Reply prevalence jumped. NF benign is at 0.93 (byte-based; 0.80
  packet-based, identical to bytes on NF by construction, §6) against
  canonical's 0.70 (byte-based), and HOIC and Hulk are at ≈1.0 against 0.24
  and 0.06 (canonical byte-based rates).
- The canonical zero-payload mass at `A_bytes = 0` does not exist in NF.
  For HOIC (75.5% of rows) and Hulk (94.1%), that mass consists of short
  unidirectional flow records with no reply and no payload. It dominates
  their canonical "+" (§10). The flow-construction difference, not the
  byte-accounting convention, is what the row-level data implicate --
  this is descriptive and POST-HOC (§10), and does not isolate
  segmentation from C2 or from label-assignment differences.

## 14. What did not change

- LOIC-UDP, LOIC-HTTP, SlowHTTPTest, Slowloris, Bot and FTP keep their
  orientation (2 of these 6 -- SlowHTTPTest, FTP-BruteForce -- are
  exactly-constant on the canonical side, §9.1, so their "preservation"
  is trivial: a fixed benign-relative reading that didn't change).
- GoldenEye and Infilteration stay near-neutral.
- The benign-free LOIC-UDP ≫ HOIC ordering and the other three same-capture
  pair orderings persist.
- `AUC_sep` ≥ 0.55 holds for every confident label on both sides -- this is
  true by construction for the two REVERSED labels (Q2); the informative
  part is that neither REVERSED label's separability *dropped*
  meaningfully (HOIC rose, Hulk moved by ~0.03).
- **C2 still stands.** The two global benign references are different
  populations: 13.47M vs. 16.64M rows, with byte-based reply rates of 0.70
  vs. 0.93. No per-label difference above can be separated from
  benign-reference composition. The fine-label match controls the attack
  side only.

## 15. Impact on manuscript claims

- Per-flow directional orientation on CICIDS is **not representation-invariant
  for every mechanism**. HOIC and Hulk reverse against global benign under
  NetFlow-v2. Their canonical "+" is dominated by short, unidirectional,
  zero-payload flow records (75.5% and 94.1% of rows) that are abundant in
  the CICFlowMeter data and essentially absent from NF-v2. The canonical rows
  that do have a reply already sit below benign (§10). The row-level data
  point to flow construction/segmentation, not to header-vs-payload byte
  accounting. With C2 unexcluded, no causal exporter claim is warranted.
- Any manuscript sentence that treats a CICIDS sign as a property of the
  attack mechanism, rather than of mechanism × flow representation ×
  benign reference, should be qualified. Phase I had already shown the
  CICIDS sign depends on the benign reference. A4 adds that, for some
  mechanisms, it also depends on the representation-plus-reference pair.
- Separability claims (`AUC_sep`) are not weakened. `AUC_sep` ≥ 0.55 for
  every confident label on both sides is true by construction for a
  REVERSED label (Q2); the substantive result is that neither reversed
  label's separability dropped -- HOIC's rose (0.577 → 0.777) and Hulk's
  barely moved (0.681 → 0.651). A sign reversal is not evidence that the
  feature stopped discriminating.
- Nothing here bears on the H3 BoT-IoT verdict (a different dataset and
  exporter) or on UNSW-NB15. Nothing transfers to them.
- `manuscript/main.tex` was **not** edited by this task.

## 16. Limitations

- **C2.** The benign references differ across representations and cannot
  be capture-matched: NF has no timestamp or capture field.
- The per-capture Phase I values (e.g. HOIC 0.0005 against its own
  capture's benign) have no NF counterpart. They are reported in
  `canonical_capture_matched.csv` for context only.
- At least four things change together: byte accounting (verified), the
  source-endpoint rule (UNVERIFIED), flow segmentation (row counts differ
  for every label), and label assignment. For HOIC and Hulk the row-level
  check (§10) implicates flow segmentation, not byte accounting:
  header-inclusive counting would make their short unidirectional records more positive,
  not less. This narrows which factor the data point to. It does not
  separate that factor from C2. **No causal exporter effect is claimed.**
- Canonical SlowHTTPTest and FTP-BruteForce `A_bytes` are exactly constant
  (0) (§9.1). Their canonical orientation is a statement about the benign
  reference only. Case C holds without them (2 of 6).
- NF-side "same capture" for the pairs is inferred from the label strings.
  It is not verified.
- There are no confidence intervals, as frozen. Point estimates are given
  with n. No significance is claimed.
- ±0.05 on AUC differences (Q5, magnitude) reuses a convention.
- The freeze's per-label reading table does not list "BOTH NEUTRAL, no
  magnitude change". It is shown as A-like (per Case A's definition). This
  affects only the descriptive per-label column for GoldenEye and
  Infilteration, not the case.
- On single-label categories the envelope rule is degenerate: it is
  indeterminate only on exact equality. This is as frozen.
- The cross-check of the merged file's coarse row counts is **not** run
  here. It belongs to a later task.

## 17. Output hashes (SHA256)

All files are in `results/audit/a4_representation/`. Hashes are recorded
at run time in `run_summary.json`.

| file | SHA256 |
|---|---|
| canonical_reproduction.csv | `a9d1a8ba56ac76e1e949502f59b15148826b3fc3d53de65271075791a91a286b` |
| fine_label_auc.csv | `8acf605401ae3d7a89011cf6b855e8ab9b29bf54df9465e9e03526de0a4d88e6` |
| comparison.csv | `cfecf67f78e9398c43a383db9db458e088bb935bbd0fd8d8933f6501108c959b` |
| ddos_ordering.csv | `c21bb9de5869328d67dc7ecde23907764fcd37299c37f697c7f9366ec34cf976` |
| coarse_standardized.csv | `fc23f2717030fa4a680e5fdb6b74f244c2e23c659fef740024953dc551063f94` |
| coarse_diagnostic.csv | `18587c67ecdae159804151c46e96524349a42601a0132e69fdd61a388b90fcdf` |
| pair_contrast.csv | `6c896e43639ead0ceffb951c2384ef038a5d03ac6659218d8538ea1fa92eee6a` |
| reply_rates.csv | `06ca0439bc8609a20f80a195c52887d27a1429961b1147d51855894a7339d12d` |
| canonical_capture_matched.csv | `8f236efd5f0f5dfc8bb99a1999c78379c0abb437b352e5ca8be0acf102ded6fb` |
| canonical_categories.csv | `e54fb9b38b7abec6d8483710d50da1977d1f2178672497e1057f0568f03345e6` |
| nfv2_categories.csv | `60435724b2a05babf43eadd18b71a661b856d86911b9838c612bb44188a9c6bd` |
| run_summary.json | `c29b98594b3f5eef5013d17df1ebaac6974a189064bee8026da688061f48cc08` |

**Final gate.** A4 stops here. No NF-UNSW-NB15-v2, NF-BoT-IoT-v2,
CIC-UNSW-NB15, CIC-BoT-IoT or other variant was downloaded or run. Any
extension needs a separate decision.
