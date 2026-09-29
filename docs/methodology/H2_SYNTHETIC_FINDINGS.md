# H2 synthetic -- findings

**Status:** the pre-registered comparison
(`docs/metodologia/REPLANTEO-OPERACIONAL.md`), executed for the first time
against an instrument (Generator v2, Candidate v2) that passed Phase 0
(`P2_PHASE0_REVALIDATION_FINDINGS.md`) rather than saturating outright the
way Generator v1 did. This is the actual H2 verdict, not a diagnostic --
everything upstream of this document (P0-P2.5, Candidate Freeze, Validation,
Final Freeze) existed to make this comparison possible to run honestly.

**Produced by:** `scripts/run_h2_synthetic.py`, against the 49 frozen Final
Test runs (`P2_FINAL_FREEZE.md`: seeds 50001-50058, 21 Main + 28 Low-signal,
AC10 confirmed PASS by `scripts/audit_generator_v2_final_test.py`), split
by run ~70/30 (35 train / 14 test), scoped to the restriction levels Phase 0
revalidation cleared -- **1:1 and 1:10 sampling; 5s, 10s and 60s
truncation** -- per the recorded option (a) decision (1:100/1:1000 sampling
and 1s truncation are out of scope, structurally unmeasurable at Candidate
v2's tunables).

## H2

> Under information restriction, topology degrades LESS than per-flow
> directional asymmetry, and the gap widens with restriction.

## Results

| axis | level | topology | per-flow | combined | C1 size | n_attack/n_benign | delta (topo-flow) | 95% CI (bootstrap, N=2000) |
|---|---|---|---|---|---|---|---|---|
| sampling | 1:1 | 0.5707 | 0.7773 | 0.7751 | 0.5137 | 226/614 | **-0.2067** | [-0.2648, -0.1505] |
| sampling | 1:10 | 0.7146 | 0.7115 | 0.7441 | 0.7059 | 159/350 | +0.0030 | [-0.0528, +0.0586] |
| truncation | 5s | 0.7090 | 0.7052 | 0.7236 | 0.6513 | 162/311 | +0.0038 | [-0.0540, +0.0590] |
| truncation | 10s | 0.6150 | 0.7125 | 0.7246 | 0.5752 | 221/576 | -0.0975 | [-0.1543, -0.0434] |
| truncation | 60s | 0.5707 | 0.7773 | 0.7751 | 0.5137 | 226/614 | -0.2067 | [-0.2648, -0.1505] |

(1:1 sampling and 60s truncation are the same unrestricted data, listed
under both axes for direct comparability with the restricted levels of each
axis, matching `experiments/04_restriction.py`'s convention.)

## Verdict

**H2 REJECTED.** Per the pre-registered decision rule: `delta < 0.05` at
every in-scope level. The best level (5s truncation) reaches only
`delta=+0.0038`, with a 95% CI of `[-0.0540, +0.0590]` that includes 0 --
not distinguishable from no difference.

**Topology does not degrade less than per-flow asymmetry -- at full
information it is substantially worse** (delta=-0.2067, CI entirely below
0: per-flow's AUC of 0.7773 comfortably beats topology's 0.5707). As
restriction increases, the gap **narrows toward parity, not toward favoring
topology** -- at 1:10 sampling and 5s truncation the two arms are
statistically indistinguishable (CIs straddle 0), and at 10s truncation
per-flow is still clearly ahead (delta=-0.0975, CI entirely below 0). No
level shows topology pulling ahead, let alone by the pre-registered margin.

**Not confounded**: C1 (size-only) never approaches either arm's AUC at any
level (0.51-0.71, tracking well below per-flow throughout), so the C1-share
check in the decision rule never becomes the binding reason for rejection --
delta failing the threshold is.

## Exploratory: does combining topology with per-flow help beyond per-flow alone?

**Post-hoc, not part of the pre-registered H2 decision rule** (which is
topology-vs-per-flow, alone, only). The `combined` column above is
numerically above `per-flow` at 3 of 4 non-full-information levels (1:10
sampling, 5s and 10s truncation) -- a pattern worth checking properly rather
than either ignoring or declaring a finding from the point estimates alone.
Extended `scripts/run_h2_synthetic.py` with the same paired-bootstrap method
applied to `combined - per-flow`:

| axis | level | delta (combined-flow) | 95% CI (bootstrap, N=2000) |
|---|---|---|---|
| sampling | 1:1 | -0.0022 | [-0.0254, +0.0203] |
| sampling | 1:10 | +0.0326 | [-0.0018, +0.0664] |
| truncation | 5s | +0.0184 | [-0.0143, +0.0474] |
| truncation | 10s | +0.0121 | [-0.0217, +0.0453] |
| truncation | 60s | -0.0022 | [-0.0254, +0.0203] |

**The CI includes 0 at every level, including the closest case (1:10
sampling, lower bound -0.0018).** The positive point estimates at 1:10/5s/10s
are not distinguishable from noise at this sample size. This does not
support "combining topology and per-flow features helps under restriction"
as a finding -- it is the reason to run the bootstrap before reporting a
point-estimate pattern as anything more than numbers that happened to line
up. Recorded here, with its numbers, rather than silently dropped, per the
project's own rule that a documented negative is worth more than a
discarded one -- but not carried into the Verdict above, which the
pre-registered rule alone determines.

## What this does and doesn't mean

This is a result about Generator v2's synthetic traffic, at Candidate v2's
frozen tunables, using RandomForest on the feature sets defined in
`src.features.extractors`. It says topology (scale-invariant graph-shape
features: max in-degree fraction, in-degree Gini, reciprocity, edges/node,
fan-out) does not out-survive per-flow directional asymmetry as NetFlow-style
sampling or early-decision truncation is applied, on this instrument. It does
not by itself say anything about real CICIDS-2018 traffic -- that is
`docs/datos-reales/`'s domain and a separate, not-yet-repeated comparison
(the roadmap's "real-data validation" step, still ahead).

It is consistent with -- not contradicted by -- the project's own prior
real-data finding (`project_iag_symmetry` memory / `docs/datos-reales/`):
per-flow asymmetry already carried the signal there too, with topology never
clearly separating from the C1 size-only control. Two independently-built
instruments (synthetic Generator v2 and real CICIDS-2018 flows) now point
the same direction.

## Recommendation

Per `CLAUDE.md`'s own stated rule for exactly this outcome (`docs/metodologia/`,
H2's pre-registration): "If topology degrades equally or worse, the framing
does not get amended again -- the project concludes and the honest result is
per-flow only." This document records that H2, tested for the first time on
an instrument that passed its own Phase 0 gate, came back REJECTED. Whether
to still attempt real-data validation as a second, independent test of the
same now-REJECTED-on-synthetic hypothesis, or to conclude the topology line
here and write up per-flow asymmetry as the project's honest finding, is the
next human decision -- not something this document resolves.
