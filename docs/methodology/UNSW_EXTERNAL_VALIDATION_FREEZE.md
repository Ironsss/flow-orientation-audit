# UNSW-NB15 external validation -- Phase 0 freeze (blind preflight)

**Status:** FROZEN, structural facts only. No label-conditioned statistic
(mean/AUC/correlation/feature importance/plot of any feature split by
`attack_cat` or `Label`) was computed to produce this document -- per the
protocol's own prohibition. Everything below is either (a) a structural
property of the files themselves, (b) something the protocol explicitly
permits at this stage (that `attack_cat` exists and enumerating its distinct
string values), or (c) a cross-check against the dataset's own pre-published
official metadata (`UNSW-NB15_LIST_EVENTS.csv`), not a statistic derived by
this project.

**Date:** 2026-09-20. **Commit at freeze time:** `1b6cc69e8f9802c6a8da5aaa7d5bfed5c59edc92`.

## H3 and H3b (frozen before any UNSW-conditioned number was computed)

**H3 -- mechanism-dependent directional asymmetry.** Directional flow
asymmetry is not universally oriented across malicious traffic; its sign and
discriminative magnitude vary by attack mechanism. Not "UNSW will reproduce
CICIDS's exact AUC values" -- that would be unjustifiably specific. The
question is whether `AUC_signed` varies systematically across categories,
with some categories inverted (`AUC_signed < 0.5`) and others not.

**H3b -- separability independent of orientation.**
`AUC_sep = max(AUC_signed, 1 - AUC_signed)`. A feature can carry information
even when inverted (`AUC_signed=0.10` implies `AUC_sep=0.90`). This
distinction is frozen now, before any UNSW number exists.

**Near-neutral threshold, frozen now:** `|AUC_signed - 0.5| < 0.05` labeled
"weak/near-neutral." Not to be adjusted after seeing results.

**What counts as evidence for H3:** at least two categories/mechanisms with
sufficiently separated CIs and orientations on opposite sides of 0.5, not
attributable solely to an arbitrary src/dst inversion. All results get
reported regardless of outcome -- no category dropped for contradicting the
pattern.

## 1. Files found

| File | Size (bytes) | SHA256 |
|---|---|---|
| `UNSW-NB15_1.csv` | 168,979,718 | `7d851bbeabd27894ce39c8e78835c73341fc946652fb7743b9eff193b55eb511` |
| `UNSW-NB15_2.csv` | 165,221,021 | `6130ad02873cc6069ae695cf2844f2e8c2e9a9a1b7532dd82ab8f202757cacf8` |
| `UNSW-NB15_3.csv` | 154,588,103 | `ae990a96c3dfcd425ce2801aadb1727a34d5e0ae6d8215dbcdae60dedfaef640` |
| `UNSW-NB15_4.csv` | 97,588,754 | `cdf563692d51d405541dd659ddcdad9fa01f001f05fe9fc4b67f00ca12fbc96a` |
| `NUSW-NB15_GT.csv` | 86,426,111 | `6d27542cb6457db599e0a78274ac141fec0296531f00ac5569551a276c5ab1a8` |
| `UNSW-NB15_LIST_EVENTS.csv` | 4,639 | `5b40f8128e2c87e691157c76debde04c328b0eb66bab97f1e7e17625f84497f2` |
| `The UNSW-NB15 description.pdf` | 189,112 | `20784d87509db0185b5d816f01a4ea04e60be180798e2d38cabb500f6dd13999` |

Location: `C:\Users\DavidG\Downloads\UNSW-NB15` (outside the repo, matching
the protocol's own suggested `--data-dir` usage; not committed, same
`data/raw/`-style exclusion as CICIDS).

**Missing: `UNSW-NB15_features.csv`** (spelled `UNSW-NB15_freatures.csv` in
the official description PDF, §"description"). This is the file the
official documentation names as the authoritative source for the 49 column
names and their semantics. It was not included in this download. The
protocol (SS5) explicitly requires verifying column semantics against
official documentation before computing anything, "no asumirla por el
nombre" -- this file's absence is a real gap against that requirement, not a
formality. See SS4 below for how this was handled and what remains
unverified as a result.

## 2. Row counts

| File | Rows (`wc -l`) | Fields/row |
|---|---|---|
| `UNSW-NB15_1.csv` | 700,001 | 49 |
| `UNSW-NB15_2.csv` | 700,001 | 49 |
| `UNSW-NB15_3.csv` | 700,001 | 49 |
| `UNSW-NB15_4.csv` | 440,044 | 49 |
| `NUSW-NB15_GT.csv` | 188,914 | 12 |
| `UNSW-NB15_LIST_EVENTS.csv` | 209 | 3 |

Total flow rows: 2,540,047 (via `wc -l`; polars reads 2,540,047 after
`has_header=False` parsing across all 4 files, consistent). The official
description PDF states "two millions and 540,044" (2,540,044) total records
-- a 3-row difference from the raw line count, most plausibly a trailing
blank/partial line in one of the source files, not investigated further at
this stage (structural note, not a blocker).

No header row in any of the four flow files -- confirmed by inspecting the
first line of each (data starts immediately). `NUSW-NB15_GT.csv` and
`UNSW-NB15_LIST_EVENTS.csv` both have a header row.

## 3. `NUSW-NB15_GT.csv` and `UNSW-NB15_LIST_EVENTS.csv` structure

`NUSW-NB15_GT.csv` header: `Start time, Last time, Attack category, Attack
subcategory, Protocol, Source IP, Source Port, Destination IP, Destination
Port, Attack Name, Attack Reference, .` (12 fields, trailing empty field per
row -- a formatting artifact of the original release, not a data column).
This is a per-attack-instance ground-truth log (one row per labeled attack
event with its time window and endpoints), not flow-level data -- relevant
later for SS10's "who is the attacker" question, since it carries `Source
IP`/`Destination IP` per labeled attack instance.

`UNSW-NB15_LIST_EVENTS.csv` header: `Attack category, Attack subcategory,
Number of events` (3 fields) -- the dataset's own pre-published category
breakdown table, 208 rows. First row: `normal,,2218761`. Reading this
pre-existing official file is not computing a new label-conditioned
statistic; it is the dataset's own documentation of its own composition,
same epistemic status as knowing `attack_cat` exists (explicitly permitted,
SS4 of the protocol).

## 4. Columns -- semantics VERIFIED (amended 2026-09-22)

*Amendment, 2026-09-22, before any label-conditioned statistic exists.* The
first draft of this section inferred the column names from memory and got
the order wrong (it omitted `stcpb` and `ct_srv_src` and placed `attack_cat`
at 47). It is replaced by the official feature-description file.

`NUSW-NB15_features.csv` (the file the description PDF calls
`UNSW-NB15_freatures.csv`) was not in the official download. It was obtained
from two independent GitHub mirrors of the official release
(`flerkenvn/unsw`, `harshilpatel1799/Iot-Cyber-Security-with-Machine-Learning-Research-Project`);
the two copies are **byte-identical**, SHA256
`c55f19cceebb6360dc50f44f8a5f246ccefbcf8a6c604ac1ad46e643869cafce`. A copy
is committed at `docs/methodology/unsw/NUSW-NB15_features.csv`. Residual
risk: both mirrors could descend from one altered copy; the structural check
below makes that implausible for the fields H3 uses.

Official order (`No.,Name`): 1 srcip, 2 sport, 3 dstip, 4 dsport, 5 proto,
6 state, 7 dur, 8 sbytes, 9 dbytes, 10 sttl, 11 dttl, 12 sloss, 13 dloss,
14 service, 15 Sload, 16 Dload, 17 Spkts, 18 Dpkts, 19 swin, 20 dwin,
21 stcpb, 22 dtcpb, 23 smeansz, 24 dmeansz, 25 trans_depth, 26 res_bdy_len,
27 Sjit, 28 Djit, 29 Stime, 30 Ltime, 31 Sintpkt, 32 Dintpkt, 33 tcprtt,
34 synack, 35 ackdat, 36 is_sm_ips_ports, 37 ct_state_ttl,
38 ct_flw_http_mthd, 39 is_ftp_login, 40 ct_ftp_cmd, 41 ct_srv_src,
42 ct_srv_dst, 43 ct_dst_ltm, 44 ct_src_ltm, 45 ct_src_dport_ltm,
46 ct_dst_sport_ltm, 47 ct_dst_src_ltm, 48 attack_cat, 49 Label.

**Directional fields, official semantics:**
- `sbytes` -- "Source to destination transaction bytes"; `dbytes` --
  "Destination to source transaction bytes".
- `Spkts` -- "Source to destination packet count"; `Dpkts` -- "Destination to
  source packet count".

Structural cross-check (no label involved): on the first data row,
`sbytes=132, Spkts=2, smeansz=66` and `dbytes=164, Dpkts=2, dmeansz=82` --
`sbytes/Spkts = smeansz` and `dbytes/Dpkts = dmeansz`, so cols 8/17/23 are
one direction and 9/18/24 the other, as documented.

**src/dst fields:** `srcip`/`dstip` (cols 1, 3), `sport`/`dsport` (cols 2, 4
-- see SS5, not uniformly numeric). "Source" is the Argus flow source, i.e.
the endpoint that sent the first observed packet of the flow -- not
necessarily the attacker. Protocol SS10 is addressed by the role check
pre-registered in SS7.4 below.

**Timestamps:** `Stime`/`Ltime` (cols 29-30), Unix epoch seconds, both
`0` nulls after numeric cast. Range: `Stime` 1421927377 to 1424262068 =
**2015-01-22 11:49:37 UTC to 2015-02-18 12:21:08 UTC**, ~27 days end-to-end
(consistent with UNSW-NB15's documented two capture sessions -- not
independently verified from this PDF).

**Row format:** `UNSW-NB15_1.csv` starts with a UTF-8 BOM before `59.166.0.0`;
the adapter strips it.

## 5. Data-quality findings (structural, not label-conditioned)

- **`sport` has 8 non-numeric values** (hex-formatted, e.g. `0x000c`,
  `0x000b`) **and `dsport` has 304** (e.g. `0xc0a8`, `0x20205321`), plus a
  `-` sentinel in both. Out of 2,540,047 rows this is a small fraction
  (<0.02%) but non-zero -- a known, previously-documented UNSW-NB15 quirk
  (third-party literature on this dataset reports the same hex-port
  artifact), not something this session introduced or is the first to see.
  Needs an explicit, pre-registered handling decision before Phase 1 (drop,
  parse-as-hex, or null) -- decided in SS7.1.
- **`proto` has 135 distinct raw string values** -- far more than the
  familiar `tcp`/`udp`/`icmp` set, consistent with this column encoding a
  wider IANA protocol-name/number vocabulary than commonly assumed. Not
  investigated further at this stage (structural note only).
- **`attack_cat` string values are inconsistent** -- 14 distinct raw strings
  collapse to the 9 official families (`Fuzzers, Analysis, Backdoor(s), DoS,
  Exploits, Generic, Reconnaissance, Shellcode, Worms`) only after trimming
  whitespace and reconciling `Backdoor` vs `Backdoors` (both appear as
  distinct raw strings, an inconsistency in the original release itself, not
  an artifact of this read). Observed raw distinct set: `' Fuzzers '`,
  `' Fuzzers'`, `'Fuzzers'` [implied by trimmed form], `' Reconnaissance '`,
  `'Reconnaissance'`, `' Shellcode '`, `'Shellcode'`, `'Analysis'`,
  `'Backdoor'`, `'Backdoors'`, `'DoS'`, `'Exploits'`, `'Generic'`,
  `'Worms'`, and `None` (empty, benign rows only). Normalization
  (trim + `Backdoor`->`Backdoors` or vice versa, one canonical spelling) is
  a Phase 1 adapter concern, decided in SS7.1.
- **Duplicate rows: 480,633 of 2,540,047 (18.9%) are fully identical rows**
  across all 49 fields. **526,481 (20.7%) share the same
  (`srcip,sport,dstip,dsport,proto,Stime,Ltime`) tuple** (a slightly larger
  count than full-row duplicates, meaning some same-tuple rows differ in a
  later field). This is a substantial, well-documented property of the
  UNSW-NB15 CSV release (widely reported by other users of this dataset) --
  recorded here, not silently deduplicated. Whether/how to deduplicate
  before H3 is decided in SS7.1.
- **`Label` is binary and internally consistent with `attack_cat`**:
  `Label=0` count is 2,218,764, `Label=1` count is 321,283 (sums to the
  total). `attack_cat` is null for exactly the 2,218,764 `Label=0` rows and
  non-null for exactly the `Label=1` rows -- a structural consistency check
  (the two columns agree on which rows are labeled attacks), not a
  label-conditioned statistic on any OTHER feature. Cross-check against the
  dataset's own `UNSW-NB15_LIST_EVENTS.csv`: it reports `normal,,2218761`
  (3 fewer than the 2,218,764 counted here) -- a small discrepancy,
  consistent with the same ~3-row difference noted in SS2, not investigated
  further at this stage.
- No nulls (empty string after CSV parse) observed in any of the first 10
  raw columns checked; the dataset appears to use in-band sentinels (`-`)
  rather than empty fields for "not applicable," at least for `service` and
  the non-numeric port entries noted above.

## 6. What is explicitly NOT in this document

No `AUC_signed`, no `AUC_sep`, no mean/median of `sbytes`/`dbytes` split by
`Label` or `attack_cat`, no correlation with the label, no plot of any
feature by class, no feature importance, no SHAP. Per the protocol (SS4):
these are the numbers that would reveal whether H3 holds, and none of them
exist yet.

## 7. Phase 1 pre-registration (frozen 2026-09-22, before execution)

Everything in this section is fixed before `scripts/run_unsw_external_validation.py`
is run for the first time. The freeze commit is pushed before that run so its
timestamp precedes any result. Any analysis not listed here is labeled
**POST-HOC / EXPLORATORY** wherever it appears.

### 7.1 Data handling

- All four flow files, header-less, names from SS4. BOM stripped.
- `attack_cat`: whitespace trimmed; `Backdoor` mapped to `Backdoors` (the
  official family name). Benign = `Label == 0`. Attack category k = rows with
  `Label == 1` and normalized `attack_cat == k`.
- **Primary analysis: all rows as released, duplicates included.** This is
  the population published UNSW-NB15 results use.
- **Pre-registered sensitivity analysis: exact duplicates removed** (identical
  across all 49 raw fields, one copy kept). Reported in full next to the
  primary; the verdict is taken from the primary.
- Ports: not used by H3. The canonical schema parses decimal and `0x` hex;
  `-` becomes null. No row is dropped for its port.
- No other row filtering. No per-category subsampling.

### 7.2 Features (two, no more)

- **Primary:** `A_bytes = log(1+sbytes) - log(1+dbytes)`.
- **Secondary:** `A_packets = log(1+Spkts) - log(1+Dpkts)`.
- Same formula as the CICIDS per-flow AUC
  (`scripts/analyze_real_data.py::perflow_auc`, `log1p(fwd) - log1p(bwd)`),
  with fwd = source->destination.
- Orientation fixed: `A > 0` means source->destination dominates. No sign
  flip conditioned on results, ever, in the signed analysis.

### 7.3 Metrics

- `AUC_signed` for Normal vs. Attack_k, attack = positive class, score = A,
  ties count 1/2 (identical to `sklearn.metrics.roc_auc_score`, the CICIDS
  convention). **Never** Normal vs. all attacks as a primary result (it is
  reported once, labeled descriptive).
- `AUC_sep = max(AUC_signed, 1 - AUC_signed)`; `Delta = AUC_signed - 0.5`.
- 95% percentile bootstrap CI, **B = 2000, seed = 20260922**. Stratified:
  benign and attack rows resampled separately, with replacement, at their
  own sizes. One benign resample per iteration is shared by all categories
  (each category's marginal CI stays valid; the shared draw only correlates
  categories' CIs).
- Distributions per category and benign: median, IQR, p10, p25, p75, p90,
  and bootstrap 95% CI of `median(attack_k) - median(benign)` from the same
  resamples.
- n_attack, n_benign reported for every row.

### 7.4 Role check (protocol SS10-11)

Attacker set = distinct `Source IP` values in `NUSW-NB15_GT.csv` (the
dataset's own ground truth of which host launched each attack), read with a
proper CSV parser. For each category: fraction of attack rows with `srcip`
in the attacker set (`src_is_attacker`) and with `dstip` in it
(`dst_is_attacker`).

Secondary `A_attack_oriented`: `A_raw` when `srcip` is an attacker, `-A_raw`
when only `dstip` is, row excluded otherwise; benign rows keep `A_raw`
(no attacker exists; exporter orientation = initiator). Computed and
reported for a category only if >= 90% of its attack rows resolve.

### 7.5 Orientation labels and category order

- Descriptive label from the point estimate: `positive` if `Delta >= 0.05`,
  `negative` if `Delta <= -0.05`, else `near-neutral`. Threshold fixed.
- **Confidently oriented**: labeled positive/negative AND the 95% CI lies
  entirely on the same side of 0.5.
- Fixed category order in every table and figure, taken from the official
  description PDF, not from results: Fuzzers, Analysis, Backdoors, DoS,
  Exploits, Generic, Reconnaissance, Shellcode, Worms.

### 7.6 Decision rule (evaluated by the script, not by a reader)

- **H3 consistent** (on `A_bytes`, primary population) iff there exist a
  confidently positive category and a confidently negative category (their
  CIs are then disjoint, separated by 0.5) that both have
  `src_is_attacker >= 0.90` -- the attacker is the source in both, so the
  opposite signs cannot be an exporter src/dst inversion.
  - Opposite confident orientations exist but no pair meets the role
    condition: **inconclusive (role)** -- reported, not upgraded.
- **Strong replication:** H3 consistent AND `A_packets` meets the same
  criterion.
- **Partial replication:** H3 consistent on `A_bytes` only.
- **No replication:** the `A_bytes` criterion is not met.
- The deduplicated sensitivity run gets the same labels, reported beside the
  primary; disagreement is reported, not resolved.

### 7.7 Secondary directional prediction from CICIDS (H3-dir)

CICIDS discovery: flooding negative, active payload delivery positive.
Pre-registered secondary prediction on `A_bytes`: **UNSW `DoS` is negative**
and **`Exploits` is positive**. Caveat fixed now: UNSW `DoS` is IXIA
PerfectStorm DoS strikes, not verified to be volumetric flooding like
CICIDS's HOIC/LOIC/Hulk, so a failure of H3-dir weighs on "the category
names transfer", not on H3. H3-dir does not enter the SS7.6 verdict.

### 7.8 Outputs and non-actions

Outputs per protocol SS21 (`results/unsw/`, `results/figures/unsw_*.pdf`),
plus `results/unsw/run_metadata.json` (commit, Python, package versions,
dataset SHA256, seed, B). No classifier, no graph, no topology, no
sampling/truncation (H2), no additional transformations of the two features.
If H3 fails, it failed.
