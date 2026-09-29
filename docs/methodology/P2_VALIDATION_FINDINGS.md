# P2 Validation -- findings

**Status:** Official PASS/FAIL per `P2_GENERATOR_V2_DESIGN_FREEZE.md` SS10,
declared against Candidate v2 (see `P2_CANDIDATE_FREEZE.md`). AC10 (sample
size) is out of scope here -- it is Final Test only (SS8).

**Produced by:** `scripts/audit_generator_v2_validation.py`. Every number
below came from actually running that script -- none of it is reasoned from
config alone, per `CLAUDE.md`'s "run the code" rule. AC4 additionally
recomputes the 20 Development runs (seeds 20001-20040, from
`P2_DEVELOPMENT_FINDINGS.md`) inside the same script run, since AC4's frozen
decision rule needs them; recomputing is deterministic given the seeds and
keeps the script independent of the gitignored Development JSON artifact.

## Attempt 1 -- Candidate v1, seeds 30001-30045 -- FAILED (AC4), seeds burned

| AC | Reading | Target | Verdict |
|---|---|---|---|
| AC1 | OVL(n_nodes)=0.8519, sep_run>=0.95: 0% | >=0.30, <=20% | PASS |
| AC2 | OVL(n_flows)=0.6306, eligible sep_run>=0.95: 0% | >=0.20, <=20% | PASS |
| AC3 | 22/30 distinct onsets, 100% of configured span | >=15, >=30% | PASS |
| **AC4** | **Acc_time_validation=0.7600** (majority-class alone: 0.7533) | **<=0.75** | **FAIL** |
| AC5 | 5/5/5/15 by construction | >=3 regimes x >=3 runs | PASS |
| AC6 | 66.7% of runs with >=2 intermediate windows | >=50% | PASS |
| AC7 | 13 near-zero, 18 near-tau runs | >=3, >=3 | PASS |
| AC8 | median pair_coverage_run=0.259 | <0.50 | PASS |
| AC9 | median std_recip_run=0.054 | >0.05 | PASS |
| AC11 | reproducible; median(LS)=0.0308 < Q1(Main)=0.2269 | -- | PASS |
| AC12 | 100% of runs have both classes | 100% | PASS |

AC4 checks that a decision rule frozen from Development's per-window-position
attack frequency (`p_dev(w)`, `yhat(w) = 1 if p_dev(w)>=0.5 else 0`) does NOT
generalize suspiciously well to Validation -- a positional/temporal shortcut
guard. It failed here not because of a detected shortcut per se, but because
majority-class accuracy alone (0.7533, i.e. ~75% of canonical windows were
benign) already exceeded the 0.75 target: with attack windows only ~24% of
the total, `AC4 <= 0.75` was close to structurally unattainable regardless of
whether `yhat(w)` encoded real timing information or none at all. Per SS14,
these 30 seeds are now burned -- permanently excluded from any future
Validation or Final Test seed set for this project.

## Fix -- iterated on Development seeds (reusable), not on burned seeds

Swept `attack_duration_range`'s lower bound against the 20 Development seeds
(safe to reuse; only Validation/Final Test seeds are burned by a failure):

| attack_duration_range | p(attack window) | majority-class acc | AC2b (eligible sep>=0.95) |
|---|---|---|---|
| (300, 1800) -- v1 | 0.240 | 0.760 | 0.0% |
| (450, 1800) | 0.257 | 0.743 | 0.0% |
| **(600, 1800) -- chosen** | **0.284** | **0.716** | **0.0%** |
| (750, 1800) | 0.298 | 0.702 | 7.1% |
| (900, 1800) | 0.314 | 0.686 | 7.1% |

`(600, 1800)` was chosen over `(750, 1800)`/`(900, 1800)` as the smallest
change that gives comfortable margin below 0.75 (rather than the narrowest
change that merely clears it) while keeping AC2b's separability at 0% instead
of the 7.1% the larger changes start to show -- a minimal-intervention choice,
not a tuned-to-the-target one. Re-ran the full 20-run Development audit after
applying it: AC1, AC2b, AC7, AC8, AC9 all still comfortably in range (see
`P2_CANDIDATE_FREEZE.md` for the exact change and reasoning).

## Attempt 2 -- Candidate v2, seeds 40001-40045 -- ALL PASS

| AC | Reading | Target | Verdict |
|---|---|---|---|
| AC1 | OVL(n_nodes)=0.8945, sep_run>=0.95: 0% | >=0.30, <=20% | PASS |
| AC2 | OVL(n_flows)=0.6673, eligible sep_run>=0.95: 0% | >=0.20, <=20% | PASS |
| AC3 | 16/30 distinct onsets, 93.9% of configured span | >=15, >=30% | PASS |
| **AC4** | **Acc_time_validation=0.7361** (majority-class alone: 0.7261) | **<=0.75** | **PASS** |
| AC5 | 5/5/5/15 by construction | >=3 regimes x >=3 runs | PASS |
| AC6 | 66.7% of runs with >=2 intermediate windows | >=50% | PASS |
| AC7 | 14 near-zero, 18 near-tau runs | >=3, >=3 | PASS |
| AC8 | median pair_coverage_run=0.258 | <0.50 | PASS |
| AC9 | median std_recip_run=0.052 | >0.05 | PASS |
| AC11 | reproducible; median(LS)=0.0293 < Q1(Main)=0.2206 | -- | PASS |
| AC12 | 100% of runs have both classes | 100% | PASS |

**Every criterion Validation is responsible for (AC1-AC9, AC11, AC12) PASSES**
against Candidate v2, on seeds never used in Development or in the burned
first Validation attempt.

## What this does and doesn't mean

Generator v2, at the Candidate v2 tunable values, is validated per SS10's own
criteria. This is not the same as saying it is a good instrument for H2 in
every sense: P2.5's model-based diagnostics (C1 size-only baseline, Flow
baseline, Topology baseline -- see `P2_GENERATOR_V2_DESIGN_FREEZE.md` SS15)
have not been run yet, and those are the ones that most directly mirror the
kind of shortcut (AUC=1.0000 from raw size/volume) that made Generator v1
unusable for H2 in the first place. AC1/AC2's overlap-coefficient and
separability checks are a structural proxy for "no trivial shortcut," not a
substitute for actually fitting a classifier and checking its AUC.

## Recommendation

Per the roadmap (SS17): Final Freeze is next, followed by P2.5's diagnostic
audit and Phase 0 revalidation, before H2 itself runs against Generator v2.
Final Freeze is a decision gate (SS14) -- a human should confirm the
Candidate v2 values above are what gets frozen before N_final and the Final
Test seed lists are computed (SS11).
