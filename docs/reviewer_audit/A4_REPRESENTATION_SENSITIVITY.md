# A4 — Same-Traffic Flow-Representation Sensitivity

**Frozen:** 2026-09-27. Every version of this document was committed and
pushed before any outcome was computed from NF data. `git log` for this file
records each version's commit SHA. The report will record the implementation
commit SHA, the execution command and the output SHA256.

**Freeze history (all before execution; no NF outcome had been computed at
any step):**

1. `5c93a54`. Coarse-taxonomy protocol on the merged `NF-UQ-NIDS-v2.csv`.
2. `fb814d1`. Composition-confound amendment: envelope rule, pooling-identity
   gate, benign-reference caveat C2, and a label-vocabulary gate on the
   standalone file.
3. `0b705ad`. **Fine-grained re-freeze.** The standalone
   `NF-CSE-CIC-IDS2018-v2.csv` was downloaded. It passed the published
   row-count gate exactly (18,893,708 rows = 16,635,567 benign + 2,258,141
   attack) and carries the same 14 fine label strings as canonical
   (`A4_DATA_PREFLIGHT.md`). The label gate from version 2 therefore
   resolves to "fine labels present". A4 is restructured as follows:
   - **PRIMARY:** a fine-label-matched comparison.
   - **SECONDARY:** composition-standardized coarse comparisons.
   - **DIAGNOSTIC ONLY:** the raw coarse comparison.
   - **TERTIARY / DESCRIPTIVE:** a benign-free, same-capture attack-pair
     contrast (4 fixed pairs). It assigns no case. (Added in the same
     re-freeze; moved to its own tier by a pre-execution review amendment,
     below.)
   - The envelope rule is kept as a **falsification bound** on the
     diagnostic numbers.

   Every number this version cites is one of three things: an
   already-committed canonical-side number, a structural label count, or
   taken from the published NF-v2 paper.
4. **This version: tier amendment (after review of `0b705ad`).** The same-capture
   attack-pair contrast moves out of the primary endpoint into an explicit
   TERTIARY / DESCRIPTIVE tier that assigns no case. Its exhaustiveness is
   stated, its "free of both confounds" wording is corrected to its actual
   limitations, and a tie-share output is required. The 2,988
   cross-label feature-identical NF rows (a label-blind structural count) are
   recorded in `A4_DATA_PREFLIGHT.md`.

## STATUS

**POST-HOC REVIEWER ROBUSTNESS AUDIT.** A4 is not preregistered. It is not a
confirmatory test, not an H3 replication, not a fourth validation benchmark,
and not an independent external replication. It uses no new capture
environment: NF-CSE-CIC-IDS2018-v2 is a re-export of the CSE-CIC-IDS2018
capture this repo already uses. Nothing here modifies, reruns or reinterprets
any Phase I result, any H2/H3 output, the H3 seeds, or the ±0.05
near-neutral band.

Inputs: `A4_DATA_PREFLIGHT.md`, `A4_FEATURE_MAPPING.md`,
`results/audit/a4_representation/data_manifest.csv`,
`preflight_inventory_finegrained.json`.

## PRIMARY QUESTION

For each attack mechanism, does the signed directional orientation observed
in canonical CSE-CIC-IDS2018 (CICFlowMeter) persist when **the same
mechanism** is represented by the NF-CSE-CIC-IDS2018-v2 (NetFlow-v2)
pipeline?

## SECONDARY QUESTIONS

- **Q2.** Does separability (`AUC_sep`) persist even where signed orientation changes?
- **Q3.** Does reply structure differ materially between the representations?
- **Q4.** Are representation effects uniform across mechanisms, or do they depend on the mechanism?
- **Q5 (named).** Does the canonical ordering of the DDoS sub-attacks
  (LOIC-UDP ≫ HOIC, with LOIC-HTTP on the other side of 0.5) persist,
  converge or invert under NF? See "Named sub-question", below, for what can
  and cannot be tested.
- **Q6.** How much would a coarse-category comparison have depended on the
  sub-attack weighting convention, and how much would the naive raw coarse
  framing have misled?

## Endpoint hierarchy (read this first)

| tier | comparison | role | composition confound |
|---|---|---|---|
| **PRIMARY** | fine label vs. **the same** fine label (canonical-HOIC vs. NF-HOIC, ...) | The only tier from which a case (A-E) is assigned | **None** for the 11 well-supported labels: the mapping is the identity |
| **SECONDARY** | coarse category, reconstructed from fine-label AUCs with the **same** weights on both sides (3 weightings) | Shows how much a coarse conclusion depends on the weighting. No case is assigned from it | Controlled by construction: the weights are identical across sides |
| **DIAGNOSTIC ONLY** | raw coarse category, each side pooled with its **own** row mix | Shows how the naive framing would have read. **Never** evidence of a representation effect | Fully exposed. The envelope rule is applied here as a falsification bound |
| **TERTIARY / DESCRIPTIVE** | fine attack label vs. **another** fine attack label from the same canonical capture, **no benign rows** (4 fixed pairs) | Answers a narrower question: does the relative attack-vs-attack ordering persist under NF? **Assigns no case (A-E)** and never changes one | None (single fine labels, not pooled). Free of C2 by construction, but has its own limitations (see its section) |

C2 (benign-reference composition, below) applies to the primary, secondary
and diagnostic tiers. Fine matching removes the attack-side composition
confound. It does not remove C2. The tertiary tier uses no benign rows, so
C2 does not apply to it.

## Data, frozen

| side | source | rows used |
|---|---|---|
| Canonical | `src/ingest/loader.py::load_directory("data/raw")`, 10 CICFlowMeter files, unchanged (dedup via `.unique()`, inf/NaN → 0) | Attack rows of each fine label. Benign: every row with `is_attack == 0` (13,467,970). The 3 `"Label"` header-artifact rows are excluded |
| NF | **Standalone `NF-CSE-CIC-IDS2018-v2.csv`**, SHA256 `16a545a3e139b2e85d08b1b7d9d40328c3689a49d0deaafce6dcf8d7b63e1257`, 18,893,708 rows. Exact duplicate rows are removed, which the preflight shows is 0 rows. The step is kept for symmetry with canonical, and the script reports the count it removed | Attack rows by `Attack` (fine label). Benign: `Attack == "Benign"` (`Label == 0`), 16,635,567 rows |

Before any comparison, the script checks the NF input's SHA256 against the
standalone row of `data_manifest.csv`. It also re-checks the row-count gate
(18,893,708 / 16,635,567 / 2,258,141). Either mismatch **stops** the run.

The merged `NF-UQ-NIDS-v2.csv` (SHA256 `7e55364a…20c8`) is **not** an A4
input any more. Its provenance stays in the manifest. A later task may use it
to cross-check that aggregating the standalone file's fine labels reproduces
its coarse row counts. That check is not part of this protocol's outcome
computation.

## Features, frozen (never flipped)

| | Canonical | NF |
|---|---|---|
| PRIMARY `A_bytes` | `log1p(totlen_fwd_pkts) − log1p(totlen_bwd_pkts)` | `log1p(IN_BYTES) − log1p(OUT_BYTES)` |
| SECONDARY `A_packets` | `log1p(tot_fwd_pkts) − log1p(tot_bwd_pkts)` | `log1p(IN_PKTS) − log1p(OUT_PKTS)` |

`A_packets` is included because `A4_FEATURE_MAPPING.md` rates the packet
fields APPROXIMATELY COMPARABLE. Both byte fields keep their own semantics
(payload-only vs. whole-packet). They are compared as representations and
not harmonised.

## Statistics, frozen

- **PRIMARY:** `AUC_signed = P(A_attack > A_benign) + 0.5 P(tie)`, computed
  exactly by `counting_auc` in `scripts/audit_a2_reply_conditional.py`,
  imported unchanged.
- **SECONDARY:** `AUC_sep = max(AUC_signed, 1 − AUC_signed)`.
- **Reply rates**, per fine label and per benign reference, for each side:
  `P(bwd_bytes > 0 | attack)`, `P(bwd_bytes > 0 | benign)`,
  `P(bwd_packets > 0 | attack)`, `P(bwd_packets > 0 | benign)`. On the NF side,
  bytes > 0 ⇔ packets > 0 holds on every row (verified label-blind, both NF
  files). The byte and packet reply rates are therefore identical there by
  construction, and the report says so rather than presenting it as a finding.
- `n_attack` and `n_benign` are reported with every number.
- **No confidence intervals.** A1 showed that flow-level resampling overstates
  precision on these benchmarks. NF has no timestamp, which rules out
  time-block resampling, and host-pair structure is not comparable across
  representations. A4 reports point estimates with their n and does not claim
  statistical significance for any difference.

## Per-label classification, frozen

The near-neutral band is the existing, unchanged `|AUC_signed − 0.5| < 0.05`.
**Confident** means outside the band.

| status | definition |
|---|---|
| PRESERVED | confident on the same side of 0.5 in both representations |
| REVERSED | confident on opposite sides |
| NEUTRALIZED | confident in canonical, near-neutral in NF |
| EMERGED | near-neutral in canonical, confident in NF |
| BOTH NEUTRAL | near-neutral in both |

**Magnitude change** means `|AUC_sep_NF − AUC_sep_canonical| ≥ 0.05`. The
unit is the existing band width, reused and not re-chosen.

This is done for `A_bytes` (primary) and `A_packets` (secondary) separately.
Cases are assigned from **`A_bytes` only**.

## PRIMARY ENDPOINT: fine-label-matched comparison

For every fine label present on both sides, `AUC_signed` of that label's
attack rows against that side's global benign is computed on each side and
classified as above. This is the "same mechanism, different exporter"
control. It replaces the coarse comparison as A4's primary evidence.

**Well-supported label** (fixed now): `n_attack ≥ 1,000` in **both**
representations. This is the support floor from version 1, unchanged. It is
a floor, not a pass rate.

| fine label (identical string on both sides) | canonical n | NF n | canonical `A_bytes` `AUC_signed` (global benign, committed) | canonical status | enters case assignment? |
|---|---|---|---|---|---|
| DDOS attack-HOIC | 668,461 | 1,080,858 | 0.5765 | confident + | yes |
| DDOS attack-LOIC-UDP | 1,730 | 2,112 | 1.0000 | confident + | yes |
| DDoS attacks-LOIC-HTTP | 576,191 | 307,300 | 0.3567 | confident − | yes |
| DoS attacks-Hulk | 434,873 | 432,648 | 0.6807 | confident + | yes |
| DoS attacks-SlowHTTPTest | 19,462 | 14,116 | 0.7087 | confident + | yes |
| DoS attacks-GoldenEye | 41,455 | 27,723 | 0.4668 | near-neutral | yes |
| DoS attacks-Slowloris | 10,285 | 9,512 | 0.9040 | confident + | yes |
| Bot | 282,310 | 143,097 | 0.7794 | confident + | yes |
| Infilteration | 161,897 | 116,361 | 0.5106 | near-neutral | yes |
| FTP-BruteForce | 39,352 | 25,933 | 0.7087 | confident + | yes |
| SSH-Bruteforce | 117,322 | 94,979 | 0.5279 | near-neutral | yes |
| Brute Force -Web | 611 | 2,143 | 0.7598 | (under-supported) | **no**: reported, labelled UNDER-SUPPORTED |
| Brute Force -XSS | 230 | 927 | 0.4414 | (under-supported) | **no**: as above |
| SQL Injection | 87 | 432 | 0.5077 | (under-supported) | **no**: as above |

Canonical values: `results/audit/a2_reply/auc_by_slice.csv`, dataset
`cicids`, slice `all`, pooled benign n = 13,467,970. These were already
published in Phase I. Of the 11 well-supported labels, 8 are confident in
canonical and 3 are near-neutral.

**Global benign vs. the Phase I per-capture extremes.** The most striking
Phase I contrast is HOIC 0.0005 vs. LOIC-UDP 1.0000
(`results/audit/a3_cicids_labels.csv`). It is measured against **each
capture file's own benign**. The NF file has no capture field (below), so
that reference cannot be rebuilt on the NF side. Against global benign,
which is the only reference available on both sides, canonical HOIC is
**0.5765**, not 0.0005. The per-capture HOIC value therefore **cannot** be
tested for persistence by A4. What A4 can test is Q5, below.

### Named sub-question Q5: the DDoS ordering

Two readouts, both frozen now and both computed per side.

1. **Gap against global benign.** `G = AUC_signed(LOIC-UDP) − AUC_signed(HOIC)`.
   Canonical `G` = 0.4235. The NF reading is **ORDER PRESERVED** if
   `G_NF ≥ 0.05`, **CONVERGED** if `|G_NF| < 0.05`, and **INVERTED** if
   `G_NF ≤ −0.05`. The change `G_NF − G_can` is reported alongside. The same
   readout is reported for `LOIC-HTTP` vs. `HOIC`. Canonical `G` is
   0.3567 − 0.5765 = −0.2198, so there "preserved" means `G_NF ≤ −0.05`.
2. **Benign-free within-capture contrast.** Defined in its own tier,
   "TERTIARY / DESCRIPTIVE", below. It is not part of the primary endpoint.

The gap readout reuses the ±0.05 near-neutral band as a threshold on a
**difference of two AUCs**. The band was defined for a single AUC's distance
from 0.5. This is a reuse of convention, not a fresh derivation: nothing
independently justifies ±0.05 for a difference. The gap readout assigns no
case.

## SECONDARY: composition-standardized coarse comparison

Coarse categories are reconstructed from **well-supported** fine labels
only. Brute Force is therefore FTP + SSH. injection is not reconstructed. Bot
and Infilteration are single labels, so for them the secondary tier repeats
the primary and is not listed again.

For a category with sub-labels *i* and a weight vector *w* (Σ w_i = 1),
each side's standardized AUC is `Σ w_i · AUC_i(side)`, where the `AUC_i` are
that side's primary per-label values. **The same w is used on both sides**,
so the cross-side difference contains no attack-composition difference.
Three weightings are reported. They were fixed now from row counts only:

| category | sub-label | w: canonical row share | w: NF row share | w: equal-mechanism |
|---|---|---|---|---|
| DDoS | HOIC | 53.63% | 77.74% | 33.33% |
| | LOIC-HTTP | 46.23% | 22.10% | 33.33% |
| | LOIC-UDP | 0.14% | 0.15% | 33.33% |
| DoS | Hulk | 85.93% | 89.39% | 25% |
| | GoldenEye | 8.19% | 5.73% | 25% |
| | SlowHTTPTest | 3.85% | 2.92% | 25% |
| | Slowloris | 2.03% | 1.97% | 25% |
| Brute Force (well-supported) | SSH-Bruteforce | 74.88% | 78.55% | 50% |
| | FTP-BruteForce | 25.12% | 21.45% | 50% |

(Shares from the row counts in `A4_FEATURE_MAPPING.md`. DDoS makes the
composition problem concrete: NF's DDoS is 78% HOIC, canonical's is 54%.)

Every (category × weighting × side) value is classified with the per-label
statuses, and the cross-side status is reported per weighting. Two flags are
pre-committed:

- **WEIGHTING-FRAGILE (per side):** the three weightings' values on that side
  span ≥ 0.05, or they do not share one status (confident +, near-neutral,
  confident −). This shows that the category's coarse number is a property
  of the weighting convention as much as of the traffic.
- **CONVENTION-DEPENDENT (cross-side):** the cross-side status (PRESERVED,
  REVERSED, ...) is not the same under all three weightings.

No case is assigned from this tier. Its role is to show how stable a coarse
conclusion would be.

**Pooling-identity gate (before any NF number).** For canonical, the
canonical-row-share value must equal the canonical AUC computed directly from
the pooled attack rows. Any difference above 1e-9 **stops** the run. (This
equality holds because all labels are scored against the same benign
reference: see the identity under "DIAGNOSTIC", below.) The DDoS and DoS
expected values are the pooled figures in the envelope table below (DDoS
`A_bytes` 0.475455). Brute Force here has 2 sub-labels, so its expected value
is the n-weighted mean of SSH and FTP from `auc_by_slice.csv`.

## DIAGNOSTIC ONLY: raw coarse comparison

**Never** to be used as evidence of a representation effect, at any tier or
in any case assignment. It is reported, labelled "DIAGNOSTIC — composition
exposed", next to the primary and secondary tables. Its purpose is to let a
reader see how far the naive coarse framing would have moved.

Each side pools its **own** rows of every sub-label of the category, using
NF's published merge procedure (NF-v2 paper §3.2; `A4_FEATURE_MAPPING.md`).
The categories are DDoS, DoS, Bot, Infilteration, and Brute Force =
FTP + SSH + Brute Force -Web + Brute Force -XSS. injection is excluded, as
before. On the NF side the rows come from the standalone file, aggregated by
fine label. The merged file is not read.

**The identity.** Let a category pool labels *i* = 1..k with attack rows
*n_i*, all scored against the **same** benign reference *B*. `AUC_signed` of
the pooled attack rows against *B* is the mean, over every (attack, benign)
pair, of 1[a > b] + 0.5·1[a = b]. Grouping the pairs by the label of the
attack row gives

    AUC_category = Σ n_i · AUC_i / Σ n_i

exactly. This is the **n-weighted** mean. Each side's raw coarse AUC is
therefore that side's own-row-share weighting. The canonical and NF raw
numbers use **different** weights, which is precisely the composition
confound. (The **unweighted** mean Σ AUC_i / k is not the pooled AUC. It is
the equal-mechanism weighting of the secondary tier and is only reported
there.)

### Envelope rule: falsification bound on the diagnostic numbers

Canonical category AUCs and envelopes, derived from committed data
(`auc_by_slice.csv`, cicids, slice `all`, pooled benign 13,467,970; derived
2026-09-27 with the stdlib `csv` module; the implementation re-derives them
as the pooling-identity gate):

| category | `A_bytes` pooled | `A_bytes` sub-label range (envelope) | `A_packets` pooled | `A_packets` envelope | sub-labels: `A_bytes` AUC (canonical row share) |
|---|---|---|---|---|---|
| DDoS | **0.4755** (near-neutral) | [0.3567, 1.0000] | 0.5732 | [0.4583, 1.0000] | HOIC 0.5765 (53.6%), LOIC-HTTP 0.3567 (46.2%), LOIC-UDP 1.0000 (0.14%) |
| DoS | 0.6688 | [0.4668, 0.9040] | 0.8004 | [0.2884, 0.8437] | Hulk 0.6807 (85.9%), GoldenEye 0.4668 (8.2%), SlowHTTPTest 0.7087 (3.8%), Slowloris 0.9040 (2.0%) |
| Bot | 0.7794 | point, 0.7794 | 0.4652 | point, 0.4652 | single label |
| Infilteration | 0.5106 (near-neutral) | point, 0.5106 | 0.4316 | point, 0.4316 | single label |
| Brute Force | **0.5739** (0.024 outside the band) | [0.4414, 0.7598] | 0.3520 | [0.2884, 0.8226] | SSH 0.5279 (74.5%), FTP 0.7087 (25.0%), BF-Web 0.7598 (0.39%), BF-XSS 0.4414 (0.15%) |

The rule, per diagnostic category and per feature:

1. NF raw coarse `AUC_signed` **inside** the canonical envelope →
   **COMPOSITION-INDETERMINATE**. The status is still reported. Such a value
   is fully explicable by a different mix of the same sub-attacks with no
   representation effect.
2. **Outside** the envelope → the raw coarse difference *could* include a
   representation effect. Composition is still not ruled out, because NF's
   sub-label AUCs themselves may differ.
3. Single-label categories have a point envelope. They are indeterminate
   only on exact equality.

**Its role now.** In version 2 this rule decided which categories could
assign a case. The primary tier now avoids the confound for every
well-supported label, so the rule no longer identifies anything. It is a
**falsification bound**, a sanity check on the diagnostic tier. The report
states, per category, whether the raw coarse reading agrees with the primary
fine-label readings of its sub-labels. Wherever the raw coarse status differs
from the primary statuses, the report cites that category as a concrete
instance of the naive framing misleading, and gives the envelope verdict next
to it. Wherever an outside-envelope diagnostic value is **not** echoed by any
sub-label's primary reading, the report flags it as a coarse artifact.

## TERTIARY / DESCRIPTIVE TIER — same-capture attack-pair contrast (benign-free)

**This tier assigns no Case A-E status and never changes one.** It is
benign-free by construction, so the benign-reference confound (C2, below),
which limits the primary, secondary and diagnostic tiers, does not apply to
it. It has its own, different limitations (below). It answers a narrower
question than the Cases were designed for: does the **relative**
attack-vs-attack directional ordering persist under NF, independent of any
benign reference? It does not answer the primary representation-sensitivity
question. It is Q5's second readout.

(Freeze note: this contrast was added in the fine-grained re-freeze under the
primary heading. A pre-execution review kept it and required it to be moved
here as an explicit tertiary tier. No NF outcome had been computed at either
step.)

**Statistic.** `AUC_pair(X vs. Y) = P(A_X > A_Y) + 0.5 P(tie)`. It is computed
with the same `counting_auc`, with label X's rows in the attack role and label
Y's rows in the reference role. No benign row enters. **Pair direction is
immaterial:** `AUC_pair(Y, X) = 1 − AUC_pair(X, Y)`, so which label is listed
first is not a choice that affects any reading.

**Pairs, fixed now and exhaustive.** Each pair is two well-supported labels
that share one canonical capture file:

| X | Y | shared canonical capture |
|---|---|---|
| DDOS attack-LOIC-UDP | DDOS attack-HOIC | Wednesday-21-02 |
| DoS attacks-SlowHTTPTest | DoS attacks-Hulk | Friday-16-02 |
| DoS attacks-Slowloris | DoS attacks-GoldenEye | Thursday-15-02 |
| FTP-BruteForce | SSH-Bruteforce | Wednesday-14-02 |

These are **every** pair of well-supported labels (`n_attack ≥ 1,000`, the
freeze's support floor) that share a canonical capture file. This was checked
against the `capture_file` column of the committed
`results/audit/a3_cicids_labels.csv` (canonical-side data only; labels
whitespace-stripped, the 3 `"Label"` header-artifact rows dropped). Each of
the 4 pairs shares exactly one file, and no other well-supported pair shares
any file. DDoS attacks-LOIC-HTTP (Thuesday-20-02) and Bot (Friday-02-03) are
alone in their files. Infilteration (Wednesday-28-02 and Thursday-01-03)
shares its files with no other well-supported label. None of the three can
form a same-capture pair. Their absence follows from the data structure. It
is not a selection choice. The under-supported Brute Force -Web / -XSS / SQL
Injection share files with each other but fall below the floor.

**Readout.** Each pair is read with the same statuses and band as the
per-label table, with `AUC_pair` in place of `AUC_signed`. The canonical
`AUC_pair` values are **not** yet computed. Both sides are computed at
execution.

**Tie share (mandatory output).** For each pair, side and feature, the
implementation MUST report, next to `AUC_pair`, the tie share: the fraction
of (X, Y) row pairs with `A_X = A_Y`, i.e. the `P(tie)` that enters
`0.5 P(tie)`. On the NF side it must also report how many rows of the pair's
two labels are feature-identical (all 43 NF features) to a row carrying the
other label of the pair. The tie share must not be absorbed silently into
`AUC_pair`. The fine-grained NF file has 2,988 rows that are
feature-identical to another row but carry a different fine `Attack` label
(`A4_DATA_PREFLIGHT.md`), so ties between attack labels are a known
structural possibility.

**What this tier is and is not free of.**

- Free of C2: it uses no benign rows at all.
- Free of the label-pooling / composition confound: it compares single fine
  labels directly, not pooled categories.
- **Not** free of NF's own flow segmentation and labelling **within** a
  label. NF's HOIC has 1,080,858 rows against canonical's 668,461 for the
  "same" mechanism. NF's flow export therefore produced a different number
  of HOIC flows, and very plausibly flows with different characteristics.
  This tier cannot separate "the representation changed the relative
  ordering" from "NF's segmentation or labelling changed what counts as HOIC
  and what counts as LOIC-UDP". Both remain live explanations for any
  observed difference.
- **NF-side "same capture" is an unverified inference from the label string
  alone.** The NF file has no capture, timestamp or date field (see "Benign
  reference, frozen"). Treating NF-HOIC and NF-LOIC-UDP rows as coming from
  one capture environment is an assumption carried over from the canonical
  capture structure. It is not verified in the NF data.

**Known properties of the canonical side (from committed numbers).**

- Canonical FTP-BruteForce and SlowHTTPTest have identical global-benign
  AUCs (0.7087, a known anomaly disclosed in Phase I's A2 report) and a 0%
  reply rate (`a3_cicids_labels.csv`). This suggests near-constant `A_bytes`
  values for these labels. Two of the four canonical pair contrasts may then
  reduce to reading the partner label's CDF at a single point rather than
  comparing two distributions.
- The canonical LOIC-UDP vs. HOIC contrast is nearly foreseeable from
  committed numbers: median `A_bytes` is 15.16 for LOIC-UDP and 0 for HOIC
  (`a3_cicids_labels.csv`). Only the NF-side outcome is genuinely unknown.

**Label normalization (all tiers).** The implementation applies
`.str.strip_chars()` to canonical labels, as
`scripts/audit_a2_reply_conditional.py` already does, before joining or
comparing them with NF `Attack` strings.

## Benign reference, frozen

1. **GLOBAL BENIGN (the only convention compared across representations).**
   For each side, all of that side's benign rows, as defined above.
2. **CAPTURE-MATCHED BENIGN. Still not reconstructible for NF.** The
   standalone file was checked structurally for a way to rebuild it. Its 45
   columns are the 43 documented flow fields plus `Label` and `Attack`. It has
   no timestamp, date, capture-day, source-file or `Dataset` field
   (`A4_DATA_PREFLIGHT.md`). Fine attack labels identify an attack's capture
   day by inference, because each canonical label comes from known files.
   They do **not** assign benign rows to days. Capture IDs will **not** be
   inferred from IP addresses, ports or row order. This remains a declared
   limitation. For context only, the canonical side reports the capture-matched
   `AUC_signed` per fine label (Phase I A3 already publishes these in
   `a3_cicids_labels.csv`). The report labels them **canonical-only, no NF
   counterpart**, and they take no part in any case.

Phase I showed that CICIDS signs depend on the reference (HOIC, Hulk and
SlowHTTPTest reverse between pooled and per-capture benign). The global
convention was fixed before any NF outcome existed. It was not chosen
because it makes the two representations agree.

**C2: benign-reference composition is uncontrolled across representations.**
The two global benign references are not the same population. NF has
16,635,567 benign rows. Canonical has 13,467,970 after dedup. The NF rows'
split across capture days is unknown, because NF has no day field. Phase I
already showed that this mechanism alone changes signs:

- A2 (`AUDIT_SYNTHESIS.md`, item 1): restricting only the BoT-IoT benign
  reference to answered flows (9,543 → 4,514 rows) turns all six negative
  groups positive. The attack rows barely change.
- A2 vs. A3 (`AUDIT_SYNTHESIS.md`, "Named finding: CICIDS sign is
  reference-dependent"): on this same CICIDS capture, HOIC, Hulk and
  SlowHTTPTest are confident-positive against pooled benign (0.577, 0.681,
  0.709) and confident-negative against their own capture file's benign
  (0.0005, 0.023, 0.025).

NF's global benign may weight the capture days differently from canonical's.
It also segments benign traffic into flows differently, which is why the row
count differs. Either way the reference changes, and it changes by the same
mechanism. Fine-label matching controls the attack side only. Without capture
matching, **an observed per-label cross-representation difference cannot be
separated from a benign-reference-composition difference**. This applies to
every primary, secondary and diagnostic number. The only exception is the
benign-free tertiary pair contrast, which assigns no case. Each case conclusion below carries this
qualification. It is not optional wording.

## Canonical reproduction gate (runs before any NF number)

Before computing anything from NF, the implementation recomputes the
canonical pooled-benign, all-flows `A_bytes` and `A_packets` `AUC_signed` for
the 14 fine labels. It compares them with
`results/audit/a2_reply/auc_by_slice.csv` (CICIDS, slice `all`). If any label
differs by more than 1e-9, the run **stops** without touching NF data. The
pooling-identity gates (secondary and diagnostic tiers, above) run in the
same step.

## PRE-COMMITTED INTERPRETATION

The primary result is the **per-label table** of the 11 well-supported fine
labels. The case label only summarises it. **There is no pass rate.** No
number of same-sign labels counts as "surviving".

**Per label** (primary, `A_bytes`), each well-supported label receives its
status and magnitude flag, read as follows:

| per-label reading | meaning for that mechanism |
|---|---|
| PRESERVED, no magnitude change | orientation and strength carry over (A-like) |
| PRESERVED or BOTH NEUTRAL, with magnitude change | orientation stable, strength differs (B-like) |
| REVERSED | orientation differs (C-like) |
| NEUTRALIZED | the canonical signal is lost under NF (D-like when common) |
| EMERGED | a signal appears under NF that canonical lacks (E-like) |

**In aggregate**, the case is assigned over the 11 well-supported labels,
checking in this order. The first case that matches applies.

In every case, "representation" means the NF pipeline as a whole *together
with* its own benign reference (C2). No case conclusion may attribute a
difference to the flow representation alone.

- **CASE D.** More than half of the well-supported labels that are confident
  in canonical (currently 8) are REVERSED or NEUTRALIZED, i.e. at least 5 of
  8. ("Most", read literally.)
  *Conclusion:* a substantial part of the per-mechanism CICIDS orientation
  did not carry over to the NF representation with its own benign reference.
  This is a valid result, not a failure of A4. It **cannot** be written up as
  "representation-dependent" without the C2 qualification.
- **CASE C.** At least one well-supported label is REVERSED, and D does not
  apply.
  *Conclusion:* signed orientation of at least one mechanism differs between
  the two representation-plus-reference pairs. This is consistent with the
  measurement-validity / non-transportability interpretation, and it weakens
  any claim that orientation is intrinsic to a mechanism. It is **not**
  evidence that the exporter alone reverses the sign, because C2 is an
  unexcluded alternative. The report names which labels reversed and which
  were preserved, and gives the tertiary benign-free pair contrasts that
  bear on them, as descriptive context only.
- **CASE E.** No well-supported label is REVERSED, at least one is
  NEUTRALIZED or EMERGED, and D does not apply.
  *Conclusion:* mechanism × representation-plus-reference interaction. No
  global exporter-independent or exporter-dependent conclusion is drawn, and
  C2 is stated as an unexcluded alternative.
- **CASE B.** Every well-supported label is PRESERVED or BOTH NEUTRAL, and at
  least one shows a magnitude change.
  *Conclusion:* directional magnitude and separability differ between the two
  representation-plus-reference pairs. Per-mechanism signed orientation is
  comparatively stable. The magnitude difference is not attributed to the
  representation alone (C2).
- **CASE A.** Every well-supported label is PRESERVED or BOTH NEUTRAL, with no
  magnitude change.
  *Conclusion:* the per-mechanism orientation relationships are not specific
  to the canonical CICFlowMeter representation and its benign reference.
  **This does not prove exporter independence**, because the two
  representations were not given identical benign references (C2).

`A_packets` gets the same per-label table, reported with no case assigned.
The secondary and diagnostic tiers never change the case. The report states
in one line whether the diagnostic raw coarse reading would have suggested a
**different** case if it had been used as primary. This is Q6's headline
number: how far the naive framing would have misled.

**Q2.** For each REVERSED or NEUTRALIZED label, the report states whether
`AUC_sep` in NF is still ≥ 0.55 (separability persists and only orientation
changed) or not.
**Q3.** Reply rates are reported per label, side by side, together with the
byte vs. packet reply gap on each side. The report is descriptive. No
threshold is set.
**Q4.** This is answered by the per-label table itself. If statuses differ
across mechanisms, the effect depends on the mechanism.
**Q5.** Answered by the DDoS-ordering gap readout (primary section) and the
tertiary pair-contrast table. Neither assigns a case.
**Q6.** Answered by the secondary WEIGHTING-FRAGILE and CONVENTION-DEPENDENT
flags, and by the diagnostic-vs-primary agreement notes.

## Scope limits (they bound any conclusion)

- A difference between the two representations cannot be attributed to the
  exporter alone. At least four things change together: byte accounting
  (payload-only vs. whole-packet, verified), the source-endpoint rule
  (UNVERIFIED), flow segmentation (row counts differ for every label), and
  label assignment (the NF authors' labels on re-exported flows, under the
  same names). Benign-reference composition (C2) confounds this directly.
  Fine matching removes attack-side composition for the primary tier only.
  **No causal exporter effect will be claimed.**
- Identical label strings do not guarantee that NF assigned the label to the
  same traffic. The NF-v2 paper does not publish its per-flow labelling
  procedure for the standalone file.
- Global benign only. Capture-matched comparisons, including the Phase I
  HOIC 0.0005 figure, are out of reach on the NF side.
- The results apply to CSE-CIC-IDS2018 alone. Nothing transfers to UNSW-NB15
  or BoT-IoT, which are not analysed here.
- The canonical category-level and standardized global-benign AUCs are new
  pooled numbers. They are not the manuscript's per-capture figures, and they
  do not replace them.

## Deliverables (future task, not this freeze)

- `scripts/audit_a4_representation.py`, committed and pushed **before** it is run once.
- `results/audit/a4_representation/`, containing:
  - `canonical_reproduction.csv`
  - `fine_label_auc.csv` (primary: per side × label × feature: n_attack,
    n_benign, AUC_signed, AUC_sep, status, magnitude flag, `well_supported`)
  - `ddos_ordering.csv` (Q5) and `pair_contrast.csv` (tertiary: per pair ×
    side × feature: n_X, n_Y, AUC_pair, status, tie share, count of
    cross-label feature-identical rows)
  - `coarse_standardized.csv` (secondary: category × weighting × side × feature,
    with the two flags)
  - `coarse_diagnostic.csv` (raw pooled per side, envelope min/max,
    `composition_indeterminate`, agreement with primary)
  - `reply_rates.csv`
  - `canonical_capture_matched.csv` (context only)
- `docs/reviewer_audit/A4_REPRESENTATION_SENSITIVITY_REPORT.md`, which records the
  implementation commit SHA, the execution command, the Python/polars versions
  and the SHA256 of every output file.

## Provenance at freeze

| item | value |
|---|---|
| NF input (primary) | `C:\Users\DavidG\Downloads\b3427ed8ad063a09_MOHANAD_A4706\b3427ed8ad063a09_MOHANAD_A4706\data\NF-CSE-CIC-IDS2018-v2.csv` (UQ BagIt bag `b3427ed8ad063a09_MOHANAD_A4706`), 3,221,378,977 B, SHA256 `16a545a3e139b2e85d08b1b7d9d40328c3689a49d0deaafce6dcf8d7b63e1257`, SHA1 `80ff7fd07e2bc31164197f07fe9d9606ee565f9a` (matches bag manifest), 18,893,708 rows. Its `NetFlow_v2_Features.csv` is byte-identical to the merged bag's (SHA256 `f20e86a9…e939`) |
| Row-count gate | UQ RDM `https://rdm.uq.edu.au/files/ce5161d0-ef9c-11ed-827d-e762de186848`: 18,893,708 / 16,635,567 / 2,258,141, matched exactly |
| Retained, not an A4 input | `NF-UQ-NIDS-v2.csv` 13,729,330,230 B, SHA256 `7e55364a20d98b9517097de77bbff168d1d0b047b8bb50bf4bb16287804920c8` (bag `9810e03bba4983da_MOHANAD_A4706`) |
| Schema / labels | `A4_DATA_PREFLIGHT.md`, `A4_FEATURE_MAPPING.md` |
| Fine-grained preflight UTC | 2026-09-27T22:49:24Z to 22:49:47Z, at HEAD `fb814d1` (`scripts/audit_a4_finegrained_preflight.py`) |
| Environment | Python 3.11.16, polars 1.44.1, `C:\Users\DavidG\iag-symmetry\.venv` |
| Freeze commits | `5c93a54` (v1), `ac7c768` (manifest), `fb814d1` (v2 amendment), `0b705ad` (fine-grained re-freeze). This tier amendment is the next commit touching this file (`git log -- docs/reviewer_audit/A4_REPRESENTATION_SENSITIVITY.md`) |
| Implementation commit, execution command, output SHA256 | not yet. Recorded in the report |
