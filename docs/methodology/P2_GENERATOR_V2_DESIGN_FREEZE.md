# P2 — Generator v2 Design Freeze

**Project:** IAG-Symmetry
**Status:** FROZEN
**Design baseline:** `7f53eb006853ac0e6b1f298f1cc96b09681bb55b`
**Generator v2 implemented at freeze time:** No
**Generator v2 simulations executed at freeze time:** No
**H2 executed at freeze time:** No

> Acceptance criteria were defined before Generator v2 implementation and before observing Generator v2 experimental results.

> Any later methodological change must be versioned and cannot be retroactively described as preregistered for previously observed results.

This document is a **Preregistered Design Contract for Generator v2**. It is self-contained: everything needed to implement, validate, and freeze Generator v2 without re-deriving the rationale from earlier conversation is here, with the P1 evidence that motivated each design choice.

---

## 1. Scientific scope

> What traffic representation survives real deployment information constraints, and how early / with how few observations does it provide a usable detection signal?

**P2 != H2 experiment.** P2 prepares the experimental substrate (a generator whose synthetic traces do not let benign/attack be told apart by construction alone). H2 — whether topology survives information restriction better than per-flow asymmetry — is executed later, against Generator v2 once frozen, and is out of scope here.

---

## 2. P1 evidence → P2 response

| P1 blocker | Executed evidence | P2 response |
|---|---|---|
| node-count shortcut | benign ~50 vs attack ~55; C1=1.0 | shared host pool |
| volume gap | ~12.95× | heterogeneous benign load + severity regimes |
| Flow saturation | AUC=1.0 | post-design diagnostic |
| temporal shortcut | same attack windows across seeds | randomized onset/duration |
| abrupt attack | ~0→~0.92 | ramp-up |
| no near-tau | positives ~0.92 | gradual + low-intensity generation |
| uniform background | 2450/2450 pairs, reciprocity≈1 | roles/communities/hubs/services |
| low sample size | ~20/class/run | multiple independent runs |
| stealth unavailable | NOT REPRODUCED | reproducible low-signal regime |

These are prior, executed results — not tuning objectives for Generator v2.

---

## 3. Frozen architecture

```text
simulation_seed
      │
      ├── Background generation
      └── Attack generation
              │
              ▼
          Full trace
              │
              ▼
   Canonical immutable GT
              │
              ▼
           Sampling
              │
              ▼
    Observed representation
```

Rule: `Full trace → canonical immutable GT → sampling`. Ground truth is never recomputed after sampling — this is the P0.5 canonical-windowing contract, and Generator v2 must keep producing a trace compatible with it unchanged.

---

## 4. Generator v1/v2 compatibility

```text
src/simulator/
├── agents.py      # Generator v1, unchanged
└── v2/            # future Generator v2
```

Coexistence, not replacement: v1 stays available to reproduce every historical result (P0/P0.5/P0.6/P1). `v2/` is not created in this task — this document freezes its design only.

---

## 5. Frozen background

```text
host_pool.size = 80
communities = 4
```

Roles:

```text
client              32
server              12
infra/shared hub     4
high-activity       12
low-activity        12
periodic-M2M         8
```

Activity types:

```text
web/interactive
dns-like
ssh/admin-like
bulk-transfer
periodic-service
background-M2M
```

Temporal states:

```text
idle
normal
burst
```

Community model: SBM-like, `p_intra >> p_inter`.

---

## 6. Strata and severity

| severity_regime | stratum |
|---|---|
| low_signal | Low-signal |
| low | Main |
| medium | Main |
| high | Main |

The only valid definition:

```text
Main = {low, medium, high}
Low-signal = {low_signal}
```

`severity_regime` is the internal generative subcategory (controls attacker_count/rate/ramp ranges). `stratum` is the scientific category used in AC10, `N_final`, and every future Main-vs-Low-signal comparison for H2.

---

## 7. Frozen temporal protocol

```text
duration_seconds = 3600
window_seconds = 60
canonical windows/run = 60
```

for Development, Validation, and Final Test. `duration_seconds` is **not tunable** — any deficit in windows/class is resolved exclusively via `N_final` (§15), never by changing duration. A different duration would be a separate, versioned experiment, not an adaptation of P2.

Onset, attack duration, and ramp keep a randomized mechanism, reproducible per seed.

---

## 8. Experimental split

### Development

```text
Main: 10
  4 low
  3 medium
  3 high

Low-signal: 10

Total: 20
```

May adjust permitted generative parameters (§17). Does not declare PASS of behavioral acceptance criteria.

### Validation

```text
Main: 15
  5 low
  5 medium
  5 high

Low-signal: 15

Total: 30
```

New seeds, never used in Development. AC1–AC9, AC11, AC12 are declared PASS/FAIL here.

### Final Test

```text
N_final_main
N_final_low_signal
```

Computed after Validation and frozen before Final Test executes (§15).

---

## 9. Statistical unit

> Primary statistical unit = simulation run / seed.

Windows within the same run are not independent replicates. No confidence interval or pooled-window count is to be read as N independent Bernoulli trials.

---

## 10. Final acceptance criteria

### AC1a — Node-count overlap (pooled)
Validation: `OVL(n_nodes) >= 0.30`.

### AC1b — Node-count, per run (bidirectional)
For each Validation run:
```text
sep_run(x) =
max over threshold and direction
Accuracy(
  attack iff x > t
  OR
  attack iff x < t
)
```
applied to `n_nodes`. PASS: `fraction of Validation runs with sep_run(n_nodes) >= 0.95 <= 20%`.

### AC2a — Volume overlap (pooled)
Validation: `OVL(n_flows) >= 0.20`.

### AC2b — Volume, per run (bidirectional)
Same `sep_run` definition applied to `n_flows`. Eligible runs: `severity_regime ∈ {low, low_signal}` — i.e. the low-intensity runs of stratum Main plus every Low-signal run. PASS: `fraction of eligible runs with sep_run(n_flows) >= 0.95 <= 20%`.

### AC3 — Randomized onset
Validation, N=30: `>=15 distinct attack_start_window_id` AND `observed onset span >= 30% of the configured onset range`.

### AC4 — Temporal non-determinism, out-of-sample
Development estimates `p_dev(w)` per window position and freezes `ŷ(w) = 1 if p_dev(w)>=0.5 else 0`. Validation evaluates `Acc_time_validation <= 0.75`. Majority-class accuracy is reported as a diagnostic only.

### AC5 — Severity diversity
Validation includes `5 low + 5 medium + 5 high + 15 low_signal`. PASS: `>=3 severity regimes with >=3 runs each`.

### AC6 — Gradual transitions
Validation. Ramp interval: `[attack_start, attack_start + ramp_seconds]`; runs with `ramp_seconds=0` excluded. Intermediate window: `0.02 < attack_ratio_gt < 0.90`. PASS: `>=50% of ramp>0 runs have >=2 intermediate windows`.

### AC7 — Near-tau availability (bilateral)
`tau = 0.01`. Validation: `>=3 runs with 0 < attack_ratio_gt < tau` AND `>=3 runs with tau <= attack_ratio_gt <= 5*tau`. Run sets may overlap.

### AC8 — Structured background, per run
`pair_coverage_run = n_unique_benign_ordered_pairs / n_possible_ordered_pairs`, computed per Validation run. PASS: `median < 0.50` AND `>=80% of runs < 0.50`.

### AC9 — Reciprocity heterogeneity, per run
`std_recip_run = std(reciprocity across benign windows)`, per Validation run. PASS: `median > 0.05` AND `>=70% of runs > 0.02` AND `>=2 services configured with reciprocity < 0.5`.

### AC10 — Sample size, no escape clause
Final Test, by stratum: `>=250 benign windows` AND `>=250 attack windows`. No "or maximum achievable" clause.

### AC11a — Low-signal reproducibility
Same seed + same frozen config, executed twice: exact trace equality.

### AC11b — Low-signal validity
All required, on Validation:
1. 100% of Low-signal runs have benign + attack windows.
2. `median positive attack_ratio_gt(Low-signal) < Q1 positive attack_ratio_gt(Main)`.
3. Low-signal attacker-count and peak-rate ranges are configured strictly below Main's.

No AUC target anywhere in this definition.

### AC12 — Same-run positives/negatives
Validation: `100% of runs contain benign + attack windows from the same trace`.

---

## 11. N_final freeze algorithm

After Validation PASS:

```text
Y25(s,c)   = p25(yield across Validation runs), per stratum s, class c
N_req(s,c) = ceil(250 / Y25(s,c))
N_req(s)   = max(N_req(s,benign), N_req(s,attack))
N_final(s) = ceil(1.20 * N_req(s))
```

Frozen before Final Test executes: `N_final_main`, `N_final_low_signal`, and the exact Final Test seed lists.

If Final Test still fails AC10 after execution: `AC10 = FAIL`, reported as a finding. No additional runs are appended post-hoc to the same Final Test.

---

## 12. Seed policy

- One exposed `simulation_seed` per run.
- Deterministic internal substreams derived from it (roles, communities, onset, ramp, ... — not independently supplied seeds).
- Development, Validation, and Final Test seed sets are disjoint.
- Validation seeds that contributed to a FAIL are permanently burned — never reused as Validation or promoted to Final Test.
- `sampling_seed` (P0.5) remains a separate concern, applied later, downstream of Generator v2.
- Final Test seeds are frozen before execution, per §11.

---

## 13. Frozen vs tunable

| Parameter/category | Frozen? | Tunable in Development? |
|---|---|---|
| AC thresholds | YES | NO |
| host_pool.size=80 | YES | NO |
| roles/proportions | YES | NO |
| communities=4 | YES | NO |
| activity/service types | YES | NO |
| strata hierarchy | YES | NO |
| duration_seconds=3600 | YES | NO |
| window_seconds=60 | YES | NO |
| split protocol | YES | NO |
| N_final formula | YES | NO |
| exact p_intra/p_inter | NO | YES |
| exact benign rates | NO | YES |
| exact attack rates | NO | YES |
| activity multipliers | NO | YES |
| reciprocity probabilities | NO | YES |
| exact onset/duration/ramp ranges | NO | YES |
| low-signal concept | YES | NO |
| exact low-signal rates | NO | YES |

> Tunable parameters may only be adjusted to satisfy the frozen structural contract, never using detector AUC or H2 results.

---

## 14. Freeze protocol

```text
1. Design Freeze
2. Implementation
3. Development
4. Candidate Freeze
5. Validation
6. Final Freeze
7. Final H2
```

Validation failure:

```text
record failure
→ burn validation seeds
→ return to Development
→ new candidate
→ new Validation seeds
```

After Final H2 starts, Generator v2 cannot change based on results — a negative outcome (Topology does not win, or C1/Flow remain saturated even under v2) is reported and kept, not used to trigger a silent redesign.

---

## 15. P2.5 diagnostics (post-design, not tuning objectives)

To run after implementation, never to shape it:

- P1-style descriptive audit;
- C1 size-only;
- Flow baseline;
- Topology baseline;
- temporal shortcut audit;
- attack-ratio distribution;
- sample-size audit;
- background audit;
- Low-signal reproducibility;
- full Phase 0 revalidation.

If C1 or Flow remain saturated after implementing the frozen contract, that is reported as a result — Generator v2 is not adjusted afterward to move those numbers.

---

## 16. Open decision (out of scope)

```text
OPEN DESIGN DECISION —
insufficient/no-evidence scoring policy
before restricted H2 evaluation.
```

Out of scope for Generator v2 and non-blocking for full-information implementation.

---

## 17. Roadmap

```text
P0                              ✅
P0.5                            ✅
P0.6                            ✅
P1                              ✅
P2 Design                       ✅ FROZEN
P2 Design Contract PR           ✅ (PR #30)
P2 Implementation               ✅ (PR #31)
P2 Development                  ✅ (PR #32 -- see P2_DEVELOPMENT_FINDINGS.md;
                                   AC8/AC9 retuned)
P2 Candidate Freeze              ✅ v1 failed Validation, v2 frozen -- see
                                   P2_CANDIDATE_FREEZE.md
P2 Validation                    ✅ ALL PASS (AC1-AC9,AC11,AC12) on Candidate
                                   v2, seeds 40001-40045 -- see
                                   P2_VALIDATION_FINDINGS.md (30001-30045
                                   burned, Candidate v1 failed AC4)
P2.5 Generator v2 Audit          ✅ C1 size-only AUC=0.5376 (chance -- the v1
                                   shortcut is gone), Flow baseline
                                   AUC=0.7913 (real signal, not saturated) --
                                   see P2_5_FINDINGS.md
Phase 0 revalidation              ✅ no saturation at 1:1/1:10 sampling or
                                   5s-60s truncation (all regimes pooled);
                                   1:100/1:1000 sampling + 1s truncation lose
                                   BENIGN evidence (uniform-across-regime
                                   background volume, not a Low-signal-only
                                   issue) -- scoping to Main stratum was
                                   tried and REJECTED (doesn't restore
                                   evidence, re-introduces saturation at
                                   levels that worked) -- see
                                   P2_PHASE0_REVALIDATION_FINDINGS.md
Final Freeze                      ✅ option (a) chosen: 1:100/1:1000 sampling
                                   + 1s truncation out of scope. N_final_main
                                   =21, N_final_low_signal=28, seeds
                                   50001-50058 -- see P2_FINAL_FREEZE.md.
                                   Final Test AC10: PASS (Main 868 benign/392
                                   attack, Low-signal 1275/405, both >=250)
H2 synthetic                      ✅ REJECTED -- delta<0.05 at every in-scope
                                   level (best: +0.0038 at 5s truncation, CI
                                   includes 0); at full information per-flow
                                   beats topology by a lot (delta=-0.2067,
                                   CI entirely below 0) -- see
                                   H2_SYNTHETIC_FINDINGS.md. Per CLAUDE.md's
                                   own pre-registered rule for this outcome,
                                   the framing is not amended again; whether
                                   to still run real-data validation as a
                                   second independent test, or conclude here,
                                   is the next human decision.
AUC(k)                             not run (contingent on H2 SUPPORTED in
                                   the original plan; human call above
                                   decides whether these still apply)
AUC(t)
combined restrictions
tuple-only
real-data validation
```

`P2 FINAL DESIGN FREEZE GATE: READY`

Generator v2 implementation may begin only after this PR is merged.
