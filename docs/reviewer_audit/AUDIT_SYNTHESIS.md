# Reviewer Robustness Audit — Phase I Synthesis (with Phase II/A4 closure)

**Date:** 2026-09-27 (corrected in the final-review fix wave, same date;
A1 60s/600s completion and CICIDS-convention resolution added, same date;
A1 benign-concentration diagnostic added, same date; Phase II/A4 closure
added at the end, same date)

Phase I ran three post-hoc robustness audits (A1, A2, A3) against data already
on disk, each frozen (`docs/reviewer_audit/A{1,2,3}_*.md`) before its analysis
code was written. This document classifies every manuscript claim they touch,
using the buckets each audit was frozen against — not a rosier or gloomier
reading than the actual numbers in
`docs/reviewer_audit/A1_BOT_DEPENDENCE_REPORT.md`,
`docs/reviewer_audit/A2_REPLY_CONDITIONAL_REPORT.md`, and
`docs/reviewer_audit/A3_FEATURE_SEMANTICS_REPORT.md` support. Nothing here
edits `results/unsw/`, `results/botiot/`, or any confirmatory verdict; per
`AUDIT_MASTER_PLAN.md`, this sprint is entirely post-hoc. Everything below
is POST-HOC ROBUSTNESS ANALYSIS, not a new confirmatory result.

## Main finding of Phase I: BoT-IoT's sign heterogeneity does not survive controlling for reply presence or pair weighting

This is the most consequential result of the audit for how the manuscript
describes BoT-IoT.

The manuscript makes two separate BoT-IoT claims
(`docs/methodology/CLAIMS_LEDGER.md`):

- (a) **"Sign heterogeneity (opposite, confident orientations across
  mechanism groups) exists in BoT-IoT"** — confirmatory, pre-registered,
  flow-level, scoped to `A_bytes`; this is the content of the STRONG
  REPLICATION verdict.
- (b) **"Target-response ('does the attack's target reply?') explains the
  sign"** (H3-env) — prospective support (6/6 flood groups predicted)
  plus observation, licensed as "associates the sign with", not causal.

What the audit's committed numbers show:

1. **A2, answered-only slice** (`results/audit/a2_reply/auc_by_slice.csv`,
   `A_bytes`): once both attack and benign are restricted to flows that got
   a reply, **every one of the 10 BoT-IoT groups is positive**, 0.585
   (Theft/Data theft) to 0.953 (DDoS/TCP). The six groups that were
   negative on all flows (DDoS/HTTP 0.320, DoS/HTTP 0.340, Recon/OS
   fingerprint 0.355, Recon/Service scan 0.360, Theft/Data theft 0.283,
   Theft/Keylogging 0.411) become 0.676, 0.719, 0.738, 0.745, 0.585, 0.869.
   The attack side barely changes (e.g. DDoS/HTTP 19,771 -> 19,769 rows;
   Theft unchanged); the benign reference drops from 9,543 to its 4,514
   answered rows.
2. **A1, cluster-weighted point** (`results/audit/a1_bot_dependence/comparison.csv`,
   `cluster_weighted_point`): with each host-pair weighted equally instead
   of by row count, **every one of the 8 verifiable groups is positive**,
   0.785 (DDoS/HTTP) to 0.934 (DDoS/UDP). The four verifiable groups that
   were negative on all flows become 0.785-0.869. (The two Theft groups
   have too few host-pairs for A1.)
3. **A1, benign host-pair concentration**
   (`results/audit/a1_bot_dependence/benign_concentration.csv`): one benign
   host-pair holds 25.2% of the 9,543 benign rows (top 5: 45.7%). Its
   median `A_bytes` (+5.18) lies above essentially every attack row of the
   four negative verifiable groups (and both Theft groups). Removing it
   alone moves those four from 0.320-0.360 to 0.427-0.481. Three of them
   land inside the near-neutral band.

Items 1-3 are one phenomenon seen through three lenses, not three
findings. BoT-IoT's benign reference is small, source-dominated (median
`A_bytes` +4.49), half unanswered, and concentrated in a few host-pairs,
one of which holds a quarter of it. The negative orientations are
produced by comparing replied-to attack flows against that particular
reference. Restricting it by reply presence (A2), weighting its pairs
equally (A1 cluster-weighted point), removing its dominant pair, or
resampling its pairs (A1 host-pair bootstrap) each moves the negative
groups toward or past 0.5. This reinforces the finding below; it does not
add independent evidence to it, since all of it comes from the same rows.

Combined implication:

- **For claim (b) — consistent, not contradicted.** The groups that are
  negative on all flows are exactly the ones whose flows almost always get
  a reply (attack reply rates 0.94-1.00), scored against a benign reference
  that is only 47.3% answered and heavily source-dominated
  (`docs/ESTADO-ACTUAL.md`: median `A_bytes` +4.49). The groups that stay
  positive are unanswered (UDP floods, reply rate ~0.00002) or mixed (TCP
  floods, 0.26 and 0.50). The sign tracks reply presence, which is what
  H3-env says.
- **For claim (a) — substantially weakened.** The "some groups positive,
  some confidently negative" pattern that constitutes BoT-IoT's sign
  heterogeneity disappears for `A_bytes` under *either* control: holding
  reply presence fixed (A2) or weighting host-pairs equally (A1). What is
  weakened is any reading that BoT-IoT's directional-asymmetry *magnitude*
  carries mechanism information beyond reply presence. The heterogeneity is
  a reply-presence pattern relative to this particular benign reference,
  not a magnitude signature of the attack mechanism.
- **Manuscript consequence.** The STRONG REPLICATION verdict stands as the
  result of the pre-registered flow-level test; nothing here reopens it. But
  the manuscript should not present BoT-IoT's sign heterogeneity as
  evidence that asymmetry magnitude distinguishes attack mechanisms. The
  accurate description is that the sign follows whether the target replies,
  and that the negative orientations depend on comparing replied-to attack
  flows against a half-unanswered synthetic benign reference.

Exceptions and limits, stated so the finding is not overstated:

- **Not every "positive" answered-only number has adequate support.**
  DDoS/UDP (406 answered attack rows of 18,965,106) and DoS/UDP (537 of
  20,659,491) are underpowered on that slice; Theft/Data theft (118 rows,
  4 host-pairs) and Theft/Keylogging (1,469 rows, 6 host-pairs) are too
  small for any dependence check. The statement "the negative orientations
  disappear" rests on the four formerly-negative verifiable groups
  (DDoS/HTTP, DoS/HTTP, Recon/OS fingerprint, Recon/Service scan), each
  with ~19,800 to ~1.38M answered attack rows; the two TCP floods are
  positive on large samples in both slices.

- **`A_packets` is not uniformly positive on the answered slice.**
  Theft/Data theft stays negative (0.171, n=118 attack rows, only 4
  host-pairs, not dependence-checkable); Recon/OS fingerprint (0.497),
  Recon/Service scan (0.499) and Theft/Keylogging (0.473) are near-neutral.
  So for `A_packets` the heterogeneity becomes positive-or-neutral plus one
  small negative group, rather than vanishing.
- **Residual heterogeneity in the unanswered stratum.** On the
  unanswered-only slice, the two Recon groups are strongly negative
  (`A_bytes` 0.067 and 0.020 on 12,640 and 84,784 attack rows — 3.5% and
  5.8% of each group) while the TCP/UDP floods are 0.59-0.64. Among flows
  that got no reply, magnitude does separate Recon from floods. This
  stratum is a small minority of the Recon groups.
- **The two controls are not independent** (see Cross-audit consistency
  below), so their agreement is one observation, not two.
- Both controls are POST-HOC. Neither is a confirmatory test, and neither
  can be re-run as one on BoT-IoT, which is spent for H3.

## Claim-by-claim table

The BoT-IoT "STRONG REPLICATION" verdict is not one claim but ten group-level
claims. A1 and A2 together resolve them differently enough (per
`AUDIT_MASTER_PLAN.md`'s pre-committed A1×A2 matrix) that collapsing them into
one row would hide the real result. The table below keeps that granularity.
A1's overall classification against its own frozen buckets is **bucket 2**
("a different subset survives — the dependence unit matters"). This is now
based on the complete freeze: time-block at 60s, 300s and 600s. At 60s,
which is computable for all 8 verifiable groups, time-block gives a
confident, flow-side orientation for all 8. Host-pair does so for 3.
Two-stage is not an independent check at BoT-IoT's scale (its CIs match
host-pair's to within 0.013). The 3 host-pair survivors (DDoS/TCP, DDoS/UDP,
DoS/UDP) are confident under every method computed, including 60s
time-block. **The disagreement on the other 5 has a measured cause, and
the count is 3 of 8, not "3 to 8."** Resampling only the benign
host-pairs, with attack rows fixed, reproduces 89-99% of the host-pair CI
width. Resampling only the attack-side pairs keeps all 8 confident. The
benign side is dominated by one host-pair (25.2% of rows) whose share
host-pair resampling varies widely (SD 0.182) and 60s time-block barely
varies (SD 0.019). Time-block's confidence on those 5 is therefore not an
alternative valid reading: that unit holds the relevant source of
variation fixed (`A1_BOT_DEPENDENCE_REPORT.md`, "Why host-pair and
time-block disagree"). The A1 column below reports both units.

| Claim | A1 (BoT dependence) | A2 (reply-conditional) | A3 (label/exporter semantics) | Classification |
|---|---|---|---|---|
| BoT-IoT sign heterogeneity exists (claim (a) above) | 3 of 8 groups confidently oriented (bucket 2). 60s time-block is confident for all 8, but it cannot vary the benign reference's dominant host-pair (25.2% of rows). For 4 of the 5 non-confident groups that pair is what drives host-pair's width (benign-only pair resampling reproduces the host-pair CIs); DoS/TCP is a partial exception (see its own row below). Cluster-weighted points: all 8 positive (0.785-0.934) | answered-only `A_bytes`: all 10 positive (0.585-0.953) | n/a | **WEAKENED, substantially** — see Main finding. Verdict string unchanged; its interpretation as magnitude-level mechanism evidence is not supported |
| BoT-IoT sign tracks target response (claim (b), H3-env) | n/a | sign follows reply presence: negative groups are the replied-to ones, sign flips when benign reference is restricted to answered flows | n/a | **SURVIVES** as an associative claim (consistent with A2); still not licensed as causal |
| BoT-IoT DDoS/TCP: directional asymmetry reflects attack mechanism | survives: all computed methods agree (`sign_stable=true`; 60s time-block [0.666, 0.736]) | persists, strengthens (0.703 → 0.953 answered, n=5.1M; unanswered 0.605) | n/a | **SURVIVES** — though A1 and A2 are not independent (same rows, same benign reference) |
| BoT-IoT DoS/TCP: same | not confident: host-pair CI [0.487, 0.804] straddles 0.5 (`sign_stable=false`); 60s time-block [0.603, 0.652] is confidently positive but cannot vary benign-pair composition. Marginal: benign-only pair resampling alone gives [0.520, 0.806], and the dominant benign pair is not extreme for this group | persists, strengthens (0.628 → 0.938 answered, n=6.2M; unanswered 0.643) | n/a | **SURVIVES WITH QUALIFICATION** — matrix row "weakens + survives": the phenomenon is real, but the original CI overstated precision |
| BoT-IoT DDoS/UDP, DoS/UDP: same | survives: all computed methods agree (`sign_stable=true`; 60s time-block [0.753, 0.814] and [0.761, 0.816]) | **persists, weakened**: answered-only unusable (406/537 rows), but the unanswered-only slice (>99.99% of attack rows, 5,029 benign) gives 0.592 and 0.600 vs. all-flows 0.785, 0.789; the drop comes from the benign side (attack n essentially unchanged) | n/a | **SURVIVES WITH QUALIFICATION** — orientation holds, but much weaker than the headline number once the benign reference is matched on reply presence; the manuscript does not currently carry this caveat |
| BoT-IoT DDoS/HTTP, DoS/HTTP, Recon/OS fingerprint, Recon/Service scan: same | not confident (`sign_stable=false`, all four): host-pair and two-stage straddle 0.5. Time-block is confidently negative (all four at 60s, the two Recon groups also at 300s and 600s), but the dominant benign pair (25.2% of the reference) sits above essentially every attack row of these groups and time-block cannot vary its share; without that pair the AUCs are 0.427-0.481 | flips sign (0.32–0.36 → 0.68–0.75 answered); attack side ~unchanged (94-100% of rows kept), benign 9,543 → 4,514; `A_packets` collapses to ~0.5 for the two Recon groups | n/a | **WEAKENED**, and **RETRACT** specifically for the "stable negative-oriented magnitude signature" reading of these four groups — matrix row "weakens + collapses/flips" = benchmark interaction / reply-structure artifact |
| BoT-IoT Theft/Data theft, Theft/Keylogging: same | not computed (< 10 host-pairs); Keylogging alone has a 60s time-block CI, [0.369, 0.453], confidently negative | flips (0.283 → 0.585, 0.411 → 0.869) by the same benign-reference mechanism as the HTTP groups — attack rows identical between `all` and `answered` (reply rate = 1.0) | n/a | **NOT ASSESSABLE via the A1×A2 matrix** — no A1 cell exists; report standalone, do not fold into the 3-of-8 pattern |
| UNSW-NB15: `A_bytes` carries directional info beyond reply presence (9 categories) | no A1-equivalent dependence audit exists for UNSW | **persists for 8/9** (several strengthen); **collapses for Analysis only** (0.796→0.506, n=630, a representative 23.5%-answered slice, falls inside the ±0.05 band). Generic drops (0.891→0.561) but stays outside the band -- by the frozen "collapses toward 0.5" definition (falls into the band), Generic PERSISTS, it does not collapse; the reading is weakened only by how unrepresentative its 1.5%-answered slice is, a separate sample-composition caveat on the persist classification | n/a | **SURVIVES WITH QUALIFICATION** — Analysis's collapse is solid and should be added as a named caveat; Generic persists but weakly, on an unrepresentative slice -- do not call it a collapse |
| CICIDS-2018: floods are an "unresolvable label mix" (reviewer-quoted framing) | n/a | n/a | **Rejected, as a label-identity claim.** 14 real, distinctly-named labels separate cleanly (per-file AUCs: 0.0005 HOIC to 1.0000 LOIC-UDP), matching the reviewer-quoted list exactly; nothing merges or collapses. (3 `"Label"` rows, n=1 each, are a known, disclosed CSV-header ingestion artifact, not a label.) Two qualifications on the strength of "separate": SlowHTTPTest and FTP-BruteForce are two of the 14 but are exactly-constant `A_bytes` (A4 report §9.1; their per-file/pooled AUC difference reflects only the benign reference, not attack-side variation, see row below); Brute Force -Web/-XSS and SQL Injection are under-supported (87-611 rows). Neither qualification revives the "unresolvable mix" framing -- the labels are still distinct and mostly non-degenerate -- but "different signs/magnitudes" should not be read as "14 informative magnitude measurements" without row 164's caveat | **RETRACT** — the "unresolvable mix" characterization does not hold and should be corrected wherever the manuscript uses it |
| CICIDS-2018: that per-label separation reflects measured *magnitude* asymmetry | n/a | 3 labels (`DDOS attack-LOIC-UDP`, `DoS attacks-SlowHTTPTest`, `FTP-BruteForce`) are 100% unanswered by bytes — `A_bytes` is a reply-presence indicator for them, not magnitude (for SlowHTTPTest and FTP-BruteForce, "unanswered" is itself a byte-accounting effect: 100% answered by packets); `DDOS attack-HOIC` and `DoS attacks-Hulk` flip relative to the pooled all-flows AUC | Confirms A2 for the same 3 labels; per-file AUCs (1.0000, 0.0248, 0.7605) are real numbers but not magnitude evidence. Per-file, HOIC and Hulk are already negative on all flows (see reference-dependence finding) | **WEAKENED, per-label** — the *separation* claim (row above) survives, but any sentence citing "clean separation across floods" as *magnitude* evidence must name which of the 14 labels the claim is safe for, and which benign reference convention the number uses |
| CICIDS-2018: a label's sign is a property of the label | n/a | pooled benign reference: HOIC 0.577, Hulk 0.681, SlowHTTPTest 0.709 | per-file benign reference: HOIC 0.0005, Hulk 0.023, SlowHTTPTest 0.025 | **REFERENCE-DEPENDENT** — see the named finding below |
| Exporter-independence: Argus and CICFlowMeter mean the same thing by "bytes" | n/a | bytes-based and packets-based reply rates match exactly for every UNSW/BoT-IoT group but differ for 10 of 14 CICIDS labels (POST-HOC, suggestive) | Verified different in kind: CICFlowMeter is payload-only (read from `BasicFlow.java` source); Argus's `sbytes`/`dbytes` are "transaction bytes" per UNSW-NB15's own feature list, undefined w.r.t. headers in that source. Neither dataset exports Argus's optional `sappbytes`/`dappbytes` (checked directly) | **UNRESOLVED, and relevant to A2** — the header-inclusion question directly affects how reply presence is operationalized for CICIDS (see Phase II) |

## Named finding: CICIDS sign is reference-dependent (A2 vs. A3)

A2 scores every CICIDS label against one pooled benign population (all
13,467,970 benign rows across the 10 capture files). A3 scores each label
against only its own capture file's benign rows. For three labels the two
conventions give **opposite orientations** of the all-flows `A_bytes` AUC:

| label | A2, pooled benign | A3, per-file benign | capture file (per-file benign median `A_bytes`) |
|---|---|---|---|
| DDOS attack-HOIC | 0.577 | 0.0005 | Wednesday-21-02 (1.105) |
| DoS attacks-Hulk | 0.681 | 0.023 | Friday-16-02 (0.975) |
| DoS attacks-SlowHTTPTest | 0.709 | 0.025 | Friday-16-02 (0.975) |

SlowHTTPTest's reference-dependence here is trivially true, not just
observed: its canonical `A_bytes` is exactly 0 on every row (A4 report
§9.1), so its AUC in either column is entirely a statement about where
that column's benign distribution sits relative to 0 -- there is no
attack-side variation for the benign reference to interact with. HOIC and
Hulk are the non-trivial cases: their canonical `A_bytes` does vary across
rows, so their reference-dependence reflects a real interaction between
the attack distribution and the choice of benign population.

(Sources: `results/audit/a2_reply/auc_by_slice.csv`, slice `all`;
`results/audit/a3_cicids_labels.csv`, `auc_signed_bytes`,
`median_a_bytes_benign`.) The other files' benign medians are between
-0.34 and -0.30, and no confident orientation reverses among the labels
scored in them; the only side-of-0.5 changes there are GoldenEye (0.467
pooled vs. 0.510 per-file) and Infilteration in Wednesday-28-02 (0.511
pooled vs. 0.494), both near-neutral under either convention. LOIC-UDP,
in the same file as HOIC, is 1.0000 under both. A CICIDS label's apparent sign therefore depends
heavily on which benign reference population it is scored against. This is
a reference-dependence finding, not a contradiction between A2 and A3:
both numbers are correctly computed for their own reference.

Consequences:

- A2's CICIDS "flips" for HOIC and Hulk are flips relative to the pooled
  all-flows number. Per file, both are already negative on all flows, and
  their answered-only negative result agrees with the per-file sign.
- **Confirmed: the manuscript's and `docs/datos-reales/`'s CICIDS numbers
  are per-capture-file AUCs that pool all attack labels in a file against
  that file's own benign rows.** Both documents say so
  (`manuscript/main.tex` line 195 and its Limitations, "The CICIDS values
  are per capture, and a capture may mix attacks";
  `docs/datos-reales/ANALISIS-DATOS-REALES.tex` line ~841, one row per
  file). The attack-count-weighted mean of A3's per-label AUCs reproduces
  all ten discovery figures to three decimals. Wednesday-21-02 gives
  (668,461 × 0.0005 + 1,730 × 1.0000) / 670,191 = 0.0031, which is the
  published "HOIC/LOIC-UDP 0.003" (details and command in
  `A3_FEATURE_SEMANTICS_REPORT.md`). The 0.003 is therefore consistent with
  A3's per-label HOIC 0.0005 and LOIC-UDP 1.0000, not in conflict with them.
  The capture is almost entirely HOIC, and the split shows that its two
  floods point in opposite directions.
- The same mechanism is at work in BoT-IoT (Main finding): an attack
  group's sign depends on the composition of the benign reference.

## Cross-audit consistency check

The three audits do not contradict each other, but their agreement is
weaker evidence than it looks, and two earlier versions of this paragraph
overstated it.

- **A1 vs. A2 overlap, not equality.** A1's `sign_stable=false` set in
  `comparison.csv` has **5** groups: Recon/Service scan, Recon/OS
  fingerprint, DDoS/HTTP, DoS/TCP, DoS/HTTP. A2 finds 4 of them flip
  (`A_bytes`) or collapse (`A_packets`, Recon) under reply-conditioning.
  The fifth, **DoS/TCP**, behaves oppositely under A2: it persists and
  strengthens (0.628 → 0.938). So the two sets overlap on 4 groups; they
  are not the same set.
- **A1 and A2 are not independent.** Both run on the same BoT-IoT rows
  against the same 9,543-row benign reference. A2 shows the negative
  orientations are set by that reference's reply mix; A1's cluster
  weighting changes the effective composition of the same reference.
  Agreement between them is structurally expected, not independent
  corroboration that the pattern is real. The benign-concentration
  diagnostic makes the shared cause explicit: one benign host-pair holds
  25.2% of the reference, and both A2's reply restriction and A1's pair
  weighting (and host-pair resampling) act on it.
- **No A1/A2 ↔ A3 cross-reference exists.** A3 is about CICIDS labels and
  exporters; A1 and A2's BoT-IoT groups are a different dataset with
  different attack categories. No BoT-IoT group "overlaps" a CICIDS label,
  and A3 neither confirms nor contradicts the BoT-IoT results. A2 and A3
  do overlap on CICIDS, where they agree on the 3 reply-degenerate labels
  and differ on orientation for 3 labels because of the benign reference
  (named finding above).

On the positive side, DDoS/TCP is the one group that is confident under A1
(`sign_stable=true`, and also confidently positive at 60s time-block) and
persists under A2 in both slices. DDoS/UDP and DoS/UDP are confident under
every A1 method, including 60s time-block, and persist, weakened, under
A2's unanswered-only slice.

A1's time-block result does not weaken the Main finding above. Time-block
shows only that the *flow-weighted* orientations are not an artifact of
temporal dependence. It does not show they are precise: the benign
reference's dominant host-pair keeps a near-constant share in every
time-block replicate, so time-block cannot detect the uncertainty that
pair creates. A2, the cluster-weighted point and the host-pair bootstrap
all show that the negative orientations depend on the composition of that
benign reference.

## Phase I closure, in four sentences

The canonical short result, to use verbatim rather than paraphrase:

> **Only 3 of 8 evaluable BoT-IoT groups retain a confident signed
> orientation under host-pair-aware dependence analysis.**

Not "3-8", not "depending on the resampling unit" -- the mechanism is
identified (below), not just observed, so this is a single number.

1. **Dependence.** Only 3/8 evaluable BoT-IoT groups (DDoS/TCP, DDoS/UDP,
   DoS/UDP) keep a confident orientation under every method computable for
   them (host-pair, two-stage, 60s time-block; 300s/600s weren't
   computable for these floods -- 5-9 blocks).
2. **Reference sensitivity.** Most of the apparent BoT-IoT heterogeneity
   traces to a small, highly concentrated benign population -- one
   host-pair is 25.2% of it, the top five are 45.7% -- not to a single
   pair flipping a sign outright. Removing it moves 3 of the 4
   pair-driven groups into the NEUTRAL band (0.454-0.481); the fourth
   (DDoS/HTTP) stays negative (0.427). (Theft/Keylogging, not one of
   these four and not one of the 8 evaluable groups, moves from 0.411 to
   0.549 -- also inside the NEUTRAL band.)
3. **Reply conditioning.** The observed sign also depends on which benign
   subpopulation constitutes the reference: several BoT-IoT negative
   results stop being negative once the comparison is restricted to
   answered flows on both sides.
4. **CICIDS.** The labels are separable (14 distinct labels, distinct
   AUCs -- though 2 of the 14, SlowHTTPTest and FTP-BruteForce, are
   exactly-constant and 3 are under-supported, A4 report §9.1), and the
   historical per-capture figures reproduce exactly as
   count-weighted aggregates of those labels (now a permanent regression
   test, `tests/test_cicids_capture_reference.py`) -- but some labels are
   reply-degenerate and do not license a magnitude-asymmetry reading on
   their own.

**A1 and A2 are not independent evidence for the same conclusion; they are
two complementary diagnostics on the same reference-population problem.**
A1 shows leverage/imbalance among benign host-pairs; A2 shows that changing
which benign rows enter the comparison (via reply-conditioning) changes
the signed AUC. Do not describe agreement between them as two
independently-arrived-at confirmations.

**A methodological point already in the manuscript (`main.tex` line ~53,
the "Orientation versus separability" subsection at ~94, and ~323),
worth applying explicitly to this audit's sign flips rather than treating
as new:** a signed orientation disappearing, neutralizing, or flipping
under a reference-population change does not by itself mean the
underlying feature lost separability/information. `AUC_signed` and
`AUC_sep = max(AUC_signed, 1-AUC_signed)` answer different questions --
orientation transport is a distinct, and separately falsifiable, property
from whether the feature discriminates at all. What's new here is not the
distinction but the finding: this audit's sign changes are consistently
orientation-level, not separability-level, changes.

**Retraction candidate for `CLAIMS_LEDGER.md`:** "attack mechanism
determines the sign of directional orientation" is not supported by the
above and should be replaced with: "signed directional orientation is not
an intrinsic property of an attack class; it is a relational measurement
whose observed sign can depend on the benign reference population, flow
weighting and dependence structure, reply composition, and potentially
flow representation." A4, if run, decides whether "potentially" can be
dropped from the last clause. See `docs/methodology/CLAIMS_LEDGER.md` for
the full row-level update. *(A4 has since run; the updated wording, which
drops "potentially" for CICIDS HOIC/Hulk only, is in "Phase II (A4)
closure" below.)*

Phase I ends here. No A1b/A2b/A3b is planned -- these three audits
answered the questions they were frozen to ask; reopening any of them on
the same data would be re-mining a spent confirmatory/post-hoc question.

## Phase I status: closed on all three fronts

- **A1: complete.** Time-block bootstrap has now run at all three frozen
  granularities (60s, 300s, 600s), so the earlier deviation is closed
  (`A1_BOT_DEPENDENCE_REPORT.md`). Bucket 2 stands:
  - DDoS/TCP, DDoS/UDP and DoS/UDP are confident under every method.
  - The other five verifiable groups are not confidently oriented. Their
    apparent confidence under time-block comes from a unit that cannot vary
    the benign reference's dominant host-pair (25.2% of rows). For four of
    those five (both Recon groups, DDoS/HTTP, DoS/HTTP) that one pair is
    what drives host-pair's width (benign-concentration diagnostic).
    DoS/TCP is a partial exception: its width instead reflects general
    benign between-pair heterogeneity, not chiefly the dominant pair (see
    `A1_BOT_DEPENDENCE_REPORT.md`). The count is 3 of 8.
  - Previously committed A1 values were verified unchanged by the rerun
    and by the diagnostic.
- **A2: complete**, as stated in `A2_REPLY_CONDITIONAL_REPORT.md`.
- **A3: complete.** The one open item was which CICIDS reference
  convention the manuscript's numbers use. It is resolved: the numbers are
  per-capture, pooling all labels in a file against that file's benign
  rows. All ten `docs/datos-reales/` figures are reproduced from A3's
  per-label AUCs (named finding above).

Nothing in Phase I is pending. Whatever follows is Phase II or manuscript
work, and both are the user's decisions.

## Phase II decision

**Framing.** NF-CSE-CIC-IDS2018-v2 is the same CICIDS-2018 traffic
re-exported by a different flow meter (nProbe NetFlow fields instead of
CICFlowMeter). A4 is therefore a **same-traffic, alternative
flow-representation sensitivity check**: does CICIDS's per-label
orientation and reply classification survive a different exporter's byte
accounting on the same packets? It is **not** a new external validation.
It adds no new capture environment, it cannot serve as a confirmatory set
for H3, and a positive result there would not extend any claim beyond
CICIDS-2018.

**Effect of the completed A1 on this recommendation: none.** A1 concerns
BoT-IoT dependence within one exporter (Argus). Its completion neither
strengthens nor weakens the case for A4, which concerns CICIDS byte
semantics.

**Not decided here — handed to the user, per `AUDIT_MASTER_PLAN.md`: A4 is a
separate, later decision, and this sprint does not start the download
unilaterally.**

Reasoning for a **partial/conditional recommendation**, not an outright
go or no-go:

- A3 already gave a partial, source-verified answer to the exporter-semantics
  question without needing new data: both UNSW-NB15 and BoT-IoT stick to
  plain `sbytes`/`dbytes` (no `sappbytes` application-byte fields), so the
  `sappbytes`-vs-`sbytes` confound A4 was originally motivated to check does
  not apply to either canonical adapter in this repo. That risk is retired.
- What A3 could **not** verify from any source on disk is whether Argus's
  "transaction bytes" include L2/L3/L4 headers, which determines whether
  CICFlowMeter's (verified) payload-only accounting is comparable to
  Argus's byte counts.
- **That open question is not orthogonal to A2's findings.** A2 defines
  reply presence through the byte field itself (`reply_bytes = bwd_bytes >
  0`), so how "reply presence" is operationalized depends directly on the
  exporter's byte accounting. `reply_rates.csv` shows this concretely: for
  every UNSW and BoT-IoT group, `reply_rate_attack_bytes` equals
  `reply_rate_attack_packets` exactly, while for CICIDS they differ for 10
  of 14 labels. The extreme cases are SlowHTTPTest and FTP-BruteForce,
  which are 100% *answered* by packets (1.0) and 100% *unanswered* by bytes
  (0.0), and Slowloris (0.773 vs. 0.014). Their "100% unanswered" status in
  A2's byte-based analysis is a consequence of CICFlowMeter counting
  payload bytes only: a backward direction carrying only header packets
  counts as "no reply." This is POST-HOC and suggestive, not proof, that
  the exporters differ on header inclusion in a way that changes A2's
  reply classification for CICIDS.
- So a common-exporter control (A4) is **more** relevant to A2 than the
  earlier version of this section said, not less: it would show whether
  CICIDS's reply-degenerate labels and opposite-sign floods persist when
  bytes are counted the same way as in UNSW/BoT-IoT. It would not change
  the BoT-IoT Main finding, which is within one exporter (Argus) and one
  dataset.
- Cost side: A4 means downloading a new external dataset
  (NF-CSE-CIC-IDS2018-v2), which is a heavier, harder-to-reverse commitment
  than anything in Phase I (which used only data already on disk). Per this
  repo's own rule ("what result would make me abandon this?" —
  `CLAUDE.md`), that bar should be set deliberately before starting, not
  after. The CICIDS reference-convention question that had to be settled
  first is now resolved without A4 (per-capture pooled; see the named
  finding above).

**Recommendation to the user:** A4 is defensible if the manuscript makes (or
the user wants to make) any cross-dataset claim that compares CICIDS
reply-presence or sign patterns with UNSW/BoT-IoT — those comparisons rest
on byte accounting that differs between exporters in a way that affects
reply classification. If the manuscript's CICIDS language is instead
qualified with what A3 and A2 already established (byte semantics differ
in kind; the `sappbytes` risk doesn't apply; reply presence by bytes and by
packets disagree for most CICIDS labels; a label's sign depends on the
benign reference), A4 can be deferred without leaving an unqualified claim.
This is a go/no-go/partial call for the user to make, not one this
synthesis makes for them.

## Phase II (A4) closure

The user chose to run A4. It ran once against its frozen protocol
(`A4_REPRESENTATION_SENSITIVITY.md`, amendments `fb814d1`, `0b705ad`,
`946337f`); the full result is in `A4_REPRESENTATION_SENSITIVITY_REPORT.md`
and `results/audit/a4_representation/`. Like Phase I, it is POST-HOC
robustness analysis on the same CICIDS-2018 traffic, not a new external
validation and not a confirmatory set for H3.

1. **Case C.** On the primary tier (fine-label-matched, `A_bytes`, each
   side against its own global benign), 2 of the 8 canonical-confident
   well-supported labels reverse under NetFlow-v2: HOIC (`AUC_signed`
   0.5765 -> 0.2232) and Hulk (0.6807 -> 0.3493). That is below the frozen
   Case D threshold (more than half), so Case C. Of the 11 well-supported
   labels, 6 preserve orientation (2 of these 6 -- SlowHTTPTest,
   FTP-BruteForce -- have constant canonical `A_bytes` and therefore
   provide no attack-side variation evidence in that representation, see
   item 2 below), 2 reverse, 1 emerges
   (SSH-Bruteforce) and 2 stay neutral. The reversals did not eliminate
   discriminative separation: `AUC_sep` is 0.777 for HOIC (up from 0.577)
   and 0.651 for Hulk (down from 0.681, a ~0.03 drop). Note that `AUC_sep`
   >= 0.55 on both sides is
   true *by construction* for any REVERSED label (REVERSED requires
   confident, i.e. |AUC-0.5| >= 0.05, on both sides) -- that threshold
   alone is not evidence; the actual finding
   is the magnitude, and it moved in opposite directions for the two
   labels: HOIC gained separation, Hulk lost some (modestly). "Only orientation changed"
   understates HOIC's case specifically, and overstates Hulk's. Coarse categories
   are unreliable: DDoS and DoS `A_bytes` are convention-dependent across
   the three frozen weightings, and the raw coarse DDoS reading (EMERGED)
   matches no sub-label's status. **C2 is unexcluded**: the two benign
   references are different populations (13.47M vs. 16.64M rows,
   byte-based reply rate 0.70 vs. 0.93) and cannot be capture-matched.
2. **Data quality.** Canonical SlowHTTPTest and FTP-BruteForce have
   exactly constant `A_bytes` (all rows 0, zero variance). Their canonical
   "confident positive" (0.7087) describes where the benign reference sits
   relative to 0, not the attack traffic. Case C is robust to excluding
   them (2 of 6 reversed; D would need at least 4). That check is POST-HOC
   and does not redefine the frozen denominator.
3. **Mechanism (POST-HOC, descriptive).** The canonical positive
   orientation of HOIC and Hulk is dominated by short, unidirectional,
   zero-payload flow records at `A_bytes = 0` (75.5% of HOIC rows, 94.1% of
   Hulk rows); the answered canonical flows already sit predominantly below
   benign, and these records are essentially absent under NF-v2. This
   implicates flow construction/segmentation. Byte-accounting convention is
   **directionally ruled out** for this reversal: header-inclusive counting
   of those records would make them more positive, not reverse them (they
   have zero backward bytes under either accounting convention, so
   `A_bytes` stays non-negative regardless -- exactly 0 payload-only,
   strictly positive header-inclusive). This is descriptive and POST-HOC;
   C2 and label-assignment differences prevent a causal attribution to
   segmentation or to the exporter alone.
4. **Candidate central thesis, across both phases.**

   > Signed directional orientation is a relational measurement, not an
   > intrinsic attack attribute. Its observed sign, and the confidence in
   > it, can depend on the benign reference population, reply composition,
   > dependence/weighting structure, and flow representation/construction.
   > Separability may remain strong even when signed orientation fails to
   > transport.

   Benign reference, reply composition and dependence/weighting come from
   Phase I (BoT-IoT via A1/A2; CICIDS reference convention via A3). Flow
   representation/construction comes from A4, found only as a
   representation-plus-benign-reference pair (C2 unexcluded, A4 cannot
   isolate "representation" from "its benign reference" as separate
   factors -- read the thesis's "flow representation/construction" clause
   as shorthand for that pair), for CICIDS HOIC and Hulk specifically, not
   for every mechanism (6 of 11 preserved,
   though 2 of those 6 -- SlowHTTPTest, FTP-BruteForce -- are constant-valued
   on the canonical side, see the data-quality row in `CLAIMS_LEDGER.md`) or
   dataset. **Not shown for UNSW-NB15**, whose H3 sign heterogeneity survived
   host-pair dependence and mostly persisted under reply-conditioning (8 of 9
   families persist; Analysis is the one collapse, 0.796→0.506, Generic
   persists but weakly on an unrepresentative 1.5%-answered slice -- see the
   UNSW rows in `CLAIMS_LEDGER.md`) -- the dependence/weighting and
   reply-composition clauses are findings specific to where each was
   actually tested (mainly BoT-IoT and CICIDS), not general across every
   dataset. The separability clause rests on A4 Q2 and the Phase I
   orientation-vs-separability point. Neither phase alone supports the
   whole sentence; together it is the best-supported single-sentence
   summary. It replaces the Phase I retraction candidate above and coexists
   with H3-env (`CLAIMS_LEDGER.md`).

A note on the Phase II decision section above: it framed A4 mainly as a
byte-semantics check. For the one reversal A4 found, byte semantics turned
out not to be the implicated factor; flow construction was. The general
point that byte accounting differs between exporters (A3, A4 §6) still
stands.

A4 does not bear on the BoT-IoT STRONG REPLICATION verdict or on UNSW-NB15
(different datasets and exporters). Row-level claims and allowed wording
are in `docs/methodology/CLAIMS_LEDGER.md` (A4 rows).

**A4 stopped after its report.** No NF-UNSW-NB15-v2, NF-BoT-IoT-v2,
CIC-UNSW-NB15, CIC-BoT-IoT or other variant was downloaded or run. Any such
extension is a separate, later decision for the user.

## Phase II status: closed

Phase II (A4) is closed, alongside Phase I, which was already closed.
Nothing in either phase is pending. What follows is manuscript work or a
new, separately frozen decision, and both are the user's.
