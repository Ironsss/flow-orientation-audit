# P2.5 -- Generator v2 model-based audit findings

**Status:** diagnostic, per `P2_GENERATOR_V2_DESIGN_FREEZE.md` SS15 ("to run
after implementation, never to shape it") -- these numbers do not feed back
into any tunable parameter, and none were changed after seeing them.

**Produced by:** `scripts/audit_generator_v2_p25.py`, run against the 30
Candidate v2 Validation runs (seeds 40001-40045, from
`P2_VALIDATION_FINDINGS.md` -- recomputed deterministically, no new
simulations). Train/test split by run (statistical unit, SS9), stratified per
severity_regime, ~70/30.

## Why this is the check that matters most

P1 (`docs/methodology/`, and the P1 blocker table in
`P2_GENERATOR_V2_DESIGN_FREEZE.md` SS2) found Generator v1's raw node/edge
count alone reached **C1 size-only AUC=1.0000** -- a classifier could tell
attack from benign windows perfectly using only `sz_nodes`/`sz_edges`,
independent of any traffic-asymmetry signal the project actually studies.
Validation's own AC1/AC2 (`P2_VALIDATION_FINDINGS.md`) only proxy for this
with an overlap coefficient and a threshold-split accuracy on the same raw
counts -- neither one fits an actual model. This script does.

## Results

| Arm | Features | ROC-AUC | PR-AUC | n_train / n_test |
|---|---|---|---|---|
| **C1 (size-only)** | `sz_nodes, sz_edges` | **0.5376** | 0.3715 | 1320 / 480 |
| **Flow baseline** | `fl_mean, fl_std, fl_p90, fl_frac_gt1` | **0.7913** | 0.7436 | 1320 / 480 |
| Topology baseline | `top_maxindeg_frac, top_indeg_gini, top_reciprocity, top_edges_per_node, top_fanout_max_frac` | 0.5941 | 0.4897 | 1320 / 480 |
| Combined (all of the above) | -- | 0.7762 | 0.7362 | 1320 / 480 |

Test set: 480 windows (332 benign, 148 attack), pooled across the held-out
run per regime.

**C1 (size-only) is near chance (0.5376)** -- the raw size/volume shortcut
that made Generator v1 unusable for H2 is not present in Generator v2 at
Candidate v2's tunable values. This is the single most important number
here: it is a direct, model-fitted answer to the question Validation's AC1/
AC2 could only proxy for.

**Flow baseline carries real signal (0.7913) without saturating.** For
comparison, the project's historical Phase 0 gate (`experiments/04_restriction.py`,
`CLAUDE.md`: "the binding one is that the per-flow baseline must not
saturate") used a `<=0.90` threshold on exactly this kind of per-flow
asymmetry baseline. 0.7913 clears that with real margin -- there is headroom
for a restriction treatment (H2's actual question) to move this number in
either direction, which a saturated baseline would foreclose.

**Topology baseline (0.5941) is real but currently much weaker than Flow.**
This is a full-information reading (rate=1, no restriction applied yet) --
H2 asks whether topology degrades *less* than per-flow asymmetry as
information is restricted, not whether topology wins at full information. A
weaker full-information topology signal is not itself evidence against or
for H2; it is simply where each representation starts.

**Combined is not the sum, or even the max, of its parts (0.7762 < Flow's
0.7913 alone).** Adding topology and size features to Flow's four features
slightly *hurt* ROC-AUC on this split. With 1320 training windows and a
combined 11-feature space, this reads as a real interaction effect worth
noting, not necessarily a robust one -- it comes from a single stratified
70/30 split (30 runs total to split, 4-5 per regime, 1 held out from Main
regimes each) rather than cross-validation across multiple splits, so it
should not be over-read.

## What this does and doesn't mean

This clears Generator v2 of the exact failure mode that ended Generator v1's
usefulness for H2. It does not by itself validate H2's eventual restriction
experiment -- that still needs Phase 0 revalidation (confirming the Flow
baseline doesn't saturate specifically under the restriction operators and
window/tau settings H2 actually uses) and the H2 experiment itself, both
still ahead per the roadmap (SS17).

## Recommendation

Per SS17's order, **Phase 0 revalidation** is next, before Final Freeze.
Given how comfortably both C1 and Flow baseline came in here, Phase 0
revalidation looks likely to pass too, but "looks likely" is exactly the kind
of unmeasured claim `CLAUDE.md` warns against (mistake #4: "declaring a
limitation is cheaper than measuring it") -- it should still be run, not
assumed. Final Freeze itself remains a decision gate (SS14): a human should
confirm before `N_final` and the Final Test seed lists are computed and
frozen.
