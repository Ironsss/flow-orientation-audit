# P2 -- Candidate Freeze

**Status:** CANDIDATE v2 FROZEN -- validated (see `P2_VALIDATION_FINDINGS.md`:
Validation seeds 40001-40045, ALL PASS on AC1-AC9/AC11/AC12).
**Candidate v1 baseline:** `80bd160` (as merged to `main` in PR #32, commit
`e1f262f`) -- FAILED Validation (AC4). Superseded, kept below as a record.
**Candidate v2 baseline:** adds one further change to `attack_duration_range`
on top of v1 (see "Candidate v2" below). This is what Validation seeds
40001-40045 actually tested and passed.

Per `P2_GENERATOR_V2_DESIGN_FREEZE.md` SS14 (Freeze protocol: Design Freeze ->
Implementation -> Development -> **Candidate Freeze** -> Validation -> Final
Freeze -> Final H2), this is the point between Development and Validation.
Its only job is to say, in one place, exactly which tunable values Validation
tests -- so that if Validation fails, "return to Development, new candidate"
(SS14) has a precise prior candidate to diff against, and so a later reader
never has to reconstruct "what config produced the Validation numbers" from
commit archaeology.

## Candidate v1 (commit `80bd160` / merged `e1f262f`) -- FAILED Validation

Every tunable value in `src/simulator/v2/config.py` as PR #32
(`P2_DEVELOPMENT_FINDINGS.md`) left it, after two rounds of Development-stage
tuning:

- `CommunityConfig`: `p_intra=0.30`, `p_inter=0.0`, `hub_preference=0.05`
- `DEFAULT_ACTIVITY`: `base_flows_per_min` per role (~20x below the original
  design-freeze starting point), `state_multiplier[IDLE]=0.08`
- `DEFAULT_SERVICES.response_probability`: web=0.98, dns=0.95, ssh=0.92,
  bulk=0.05, periodic=0.02, m2m=0.15
- `DEFAULT_SEVERITY[LOW].peak_rate_per_attacker_range=(0.0833, 0.25)`,
  `DEFAULT_SEVERITY[LOW_SIGNAL].peak_rate_per_attacker_range=(0.025, 0.05)`
- `attack_duration_range=(300.0, 1800.0)` (the design-freeze starting default,
  unchanged by Development)

Tested against Validation seeds 30001-30005, 30011-30015, 30021-30025,
30031-30045 (N=30). **Result: AC1, AC2, AC3, AC5, AC6, AC7, AC8, AC9, AC11,
AC12 all PASS -- AC4 FAILS** (`Acc_time_validation=0.7600` against a `<=0.75`
target; majority-class accuracy alone was already `0.7533`, i.e. only ~24% of
canonical windows were labeled attack, so the AC4 gate was structurally close
to unpassable at that class balance regardless of whether a genuine temporal
shortcut existed). Full numbers in `P2_VALIDATION_FINDINGS.md`. Per SS14
("Validation failure: record failure -> burn validation seeds -> return to
Development -> new candidate -> new Validation seeds"), **those 30 seeds are
burned** -- never to be reused as Validation or Final Test seeds, even though
only one of eleven checked criteria failed.

## Candidate v2 -- validated

One additional change, found by iterating on the (reusable) Development
seeds 20001-20040, never on the burned Validation seeds:

- `attack_duration_range`: `(300.0, 1800.0)` -> `(600.0, 1800.0)`. Raising the
  floor lifts the attack-window share from ~24% to ~28-29% (checked on
  Development seeds before spending new Validation seeds), without moving
  AC2b/AC7 (onset span is unaffected -- `onset_hi` was already bounded by
  `onset_fraction_range`'s 0.70 fraction, not by this floor, both before and
  after) or AC8/AC9 (background never reads attack state).

Tested against **new** Validation seeds 40001-40005, 40011-40015,
40021-40025, 40031-40045 (N=30, disjoint from both Development and the
burned 30000s block). **Result: ALL PASS**, including AC4
(`Acc_time_validation=0.7361`, majority-class accuracy `0.7261`). Full numbers
in `P2_VALIDATION_FINDINGS.md`.

## What "candidate" means

Per SS13: "tunable parameters may only be adjusted to satisfy the frozen
structural contract, never using detector AUC or H2 results." Nothing above
was adjusted using a detector AUC -- P2.5's model-based diagnostics (C1/Flow
baselines) have not been run yet against Generator v2 and remain out of scope
until after Validation, per the design freeze's own roadmap (SS17). Every
FROZEN structural constant (SS13 -- AC thresholds, `host_pool.size`, role
counts, `communities`, `duration_seconds`, `window_seconds`, the split
protocol, the `N_final` formula) is untouched in both candidates.
