# Phase 0 revalidation -- findings

**Status:** diagnostic, per `P2_GENERATOR_V2_DESIGN_FREEZE.md` SS17 (the step
between P2.5 and Final Freeze). Answers the question `CLAUDE.md` frames as
"the instrument has blocked six measurements ... the binding [acceptance
criterion] is that the per-flow baseline must not saturate" -- for Generator
v2 (Candidate v2) specifically, since `experiments/04_restriction.py` (the
pre-registered H2 experiment) only knows how to run Generator v1 or real
data and was not touched here.

> **Correction (same session):** an earlier version of this document had the
> `n_pos`/`n_neg` columns read backwards -- it reported the coarse-restriction
> levels as losing ATTACK evidence, when the script's own `n_pos =
> int(test["y_gt"].sum())` / `n_neg = len(test) - n_pos` (attack is the
> positive class, `y_gt==1`) means the opposite: at severe restriction, the
> windows that disappear are BENIGN, not attack. This version corrects that
> and revises the recommendation, which the earlier (wrong) reading had
> gotten backwards -- **scoping severe sampling to the Main stratum was
> tried, verified with real runs, and does not work; see below.**

**Produced by:** `scripts/audit_generator_v2_restriction.py --axis sampling`
and `--axis truncation` (add `--stratum main` to reproduce the Main-only
check below), against the 30 Candidate v2 Validation runs (seeds
40001-40045) and the same 70/30 stratified train/test split as
`scripts/audit_generator_v2_p25.py`.

## Sampling axis, all four severity regimes pooled

| level | topology | per-flow | combined | C1 size | n_attack/n_benign (test) |
|---|---|---|---|---|---|
| 1:1 | 0.5941 | 0.7913 | 0.7912 | 0.5376 | 148/332 |
| 1:10 | 0.7169 | 0.7270 | 0.7514 | 0.7013 | 110/206 |
| 1:100 | nan | nan | nan | nan | **45/0** |
| 1:1000 | nan | nan | nan | nan | **43/0** |

**No saturation at 1:1 or 1:10** (per-flow tops out at 0.7913) -- confirms
`P2_5_FINDINGS.md` under an actual restriction operator.

**At 1:100 and 1:1000, every surviving window is attack -- zero benign
windows have `>=10` observed flows.** This is the opposite of what an
earlier version of this document claimed. Checked directly: a run's BENIGN
windows only ever contain background traffic (`src.simulator.v2.background`
never reads attack state), and background's per-window volume is governed
entirely by the Development-tuned `DEFAULT_ACTIVITY` rates
(`P2_DEVELOPMENT_FINDINGS.md`'s ~20x cut for AC8/AC9) -- which do **not**
depend on `severity_regime` at all. So benign-window volume is similarly
thin in every regime, while attack-window volume scales with
`severity_regime` (a medium/high flood adds tens of thousands of flows to
its window; low/low_signal's smaller floods add far fewer). At 1:100+
sampling, the uniformly-thin benign background drops below `min_flows=10`
everywhere, while some attack windows (mainly medium/high, whose floods are
large enough to survive even 1:1000) still clear the threshold.

**Tried scoping to Main stratum (`--stratum main`, excludes Low-signal) as a
candidate fix -- it does not work, on two counts, both verified by running
it:**

| level | topology | per-flow | combined | C1 size | n_attack/n_benign (test) |
|---|---|---|---|---|---|
| 1:1 | 0.6325 | **0.9563** | 0.9655 | 0.6226 | 68/112 |
| 1:10 | 0.8823 | **0.9256** | 0.9314 | 0.8622 | 61/70 |
| 1:100 | nan | nan | nan | nan | 45/0 |
| 1:1000 | nan | nan | nan | nan | 43/0 |

1. **It does not restore benign evidence at 1:100/1:1000** -- identical
   `45/0` and `43/0` to the all-regime run, because the missing evidence is
   benign windows, and benign volume does not depend on severity_regime
   (`low`, which stays in "Main", is exactly as thin as `low_signal`, which
   Main excludes). Excluding Low-signal removes a regime that was never
   contributing at these levels either way.
2. **It introduces NEW saturation at 1:1 and 1:10** (0.9563, 0.9256 -- both
   `>0.90`), which the all-regime run did not have. Low-signal's windows are
   evidently what keeps the full pooled comparison from saturating: they are
   deliberately low-intensity, near-`tau` examples, and removing them leaves
   only low/medium/high's more clearly-separable windows.

## Truncation axis, all four severity regimes pooled

| level | topology | per-flow | combined | C1 size | n_attack/n_benign (test) |
|---|---|---|---|---|---|
| 1s | 0.9833 | **0.9611** | 0.9667 | 0.9750 | 45/**4** |
| 5s | 0.7547 | 0.7389 | 0.7490 | 0.7130 | 97/166 |
| 10s | 0.6223 | 0.7027 | 0.7257 | 0.5704 | 143/312 |
| 60s | 0.5941 | 0.7913 | 0.7912 | 0.5376 | 148/332 |

**No saturation at 5s, 10s, or 60s.** **At 1s, per-flow reads 0.9611** on a
test set of 45 attack windows and only **4 benign windows** -- observing
just the first second of a 60s window, background's thin rate almost never
accumulates 10 flows that fast, while an active flood usually does. 49 total
windows (45+4) is a small test set and 4 in the minority class gives the AUC
estimate real variance; flagged, not dismissed, pending more runs.

Main-only truncation (`--stratum main`) makes this worse in the same way as
sampling: 1s reads **1.0000** (on 43 attack / 2 benign windows) and even 60s
now saturates (0.9563) -- the same Low-signal-removal effect as above.

## The power gate (MIN_WINDOWS_PER_CLASS=250) fails at every level regardless

Expected on 30 runs (`N_final`, SS11, is what closes this gap) -- separable
from the saturation/evidence questions above.

## What this means

1. **Core Phase 0 concern (saturation) clears at moderate restriction** (1:1,
   1:10 sampling; 5s-60s truncation), pooling all four regimes -- this is the
   configuration to keep, not the Main-only one.
2. **1:100/1:1000 sampling and 1s truncation cannot produce a two-class
   comparison at Candidate v2's tunables, for a structural reason that no
   stratum scoping fixes**: benign-window volume is set by the AC8/AC9-tuned
   background rate, which is uniform across `severity_regime` by
   construction, so no regime's benign windows survive that much
   restriction any better than another's.
3. **Scoping severe restriction to "Main" was tried and rejected** -- it
   doesn't restore the missing benign evidence and it saturates the levels
   that previously worked. Do not adopt it.

## Recommendation

Two real options remain, and the choice is a human one (not something to
default on): **(a)** report 1:100/1:1000 sampling and 1s truncation as "no
valid comparison possible at Candidate v2's tunables" -- a genuine,
reportable H2 finding (a realistic NetFlow-style sampler at 1:1000 may
simply erase this generator's benign signal, which is itself informative),
and scope H2's actual restriction axis to the levels that do work (1:1,
1:10, 5s-60s); or **(b)** attempt a further tuning round that raises benign
(background) volume enough to survive coarser restriction without
re-breaking AC8 (pair coverage) or AC9 (reciprocity heterogeneity), which
were the reason that volume was cut in the first place -- not guaranteed to
be possible, and would need its own Candidate v3 / re-Validation cycle.
Final Freeze (SS14) should wait on this decision, since `N_final`'s formula
depends on which levels are actually in scope.
