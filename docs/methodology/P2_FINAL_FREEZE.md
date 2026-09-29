# P2 -- Final Freeze

**Status:** FROZEN.
**Decision recorded (option (a) from `P2_PHASE0_REVALIDATION_FINDINGS.md`):**
1:100/1:1000 sampling and 1s truncation are **out of scope** for H2 at
Candidate v2 -- they cannot produce a two-class comparison for a structural
reason (benign-window volume, set uniformly by the AC8/AC9-tuned background
rate, drops below `min_flows=10` at that much restriction regardless of run
count). H2's restriction axis is scoped to **1:1 and 1:10 sampling; 5s, 10s
and 60s truncation** -- the levels Phase 0 revalidation confirmed do not
saturate. This is a recorded finding (a real limit of Candidate v2), not a
gap smoothed over -- if it needs revisiting, that is a Candidate v3 /
re-Validation decision, out of scope here.

## N_final (SS11)

Computed from the 30 Candidate v2 Validation runs' RAW per-run window counts
by class, at full information (rate=1) -- "yield" is not qualified by
restriction level in SS11, and AC10 itself talks about window availability,
not a specific restriction level, so this reads it as the pre-restriction
count. This is stated explicitly because it is an interpretive choice, not
because SS11 spells it out.

| stratum | class | yield across 15 runs (sorted) | Y25 | N_req | N_final |
|---|---|---|---|---|---|
| Main | benign | 33,35,37,37,38,38,38,41,43,44,44,45,47,48,49 | 37.5 | ceil(250/37.5)=7 | -- |
| Main | attack | 11,12,13,15,16,16,17,19,22,22,22,23,23,25,27 | 15.5 | ceil(250/15.5)=17 | -- |
| Main | (both) | -- | -- | max(7,17)=**17** | ceil(1.20*17)=**21** |
| Low-signal | benign | 37,38,42,44,45,45,45,47,48,48,49,49,51,51,51 | 44.5 | ceil(250/44.5)=6 | -- |
| Low-signal | attack | 9,9,9,11,11,12,12,13,15,15,15,16,18,22,23 | 11.0 | ceil(250/11.0)=23 | -- |
| Low-signal | (both) | -- | -- | max(6,23)=**23** | ceil(1.20*23)=**28** |

**N_final_main = 21, N_final_low_signal = 28.** Attack yield is the binding
class in both strata (lower Y25 than benign in both -- consistent with
attack windows being a genuine minority class by design).

Main's 21 is split evenly across severity_regime (7 low + 7 medium + 7
high), mirroring Development/Validation's even-as-possible splits; SS8/SS11
do not mandate a specific sub-split, so this is a stated choice, not a
frozen requirement.

## Final Test seed lists (SS12: new, disjoint from every prior block)

- Development: 20001-20040 (reusable for iteration, not for Validation/Final Test)
- Validation v1 (FAILED, burned per SS14): 30001-30005, 30011-30015, 30021-30025, 30031-30045
- Validation v2 (PASSED, Candidate v2): 40001-40005, 40011-40015, 40021-40025, 40031-40045
- **Final Test (this freeze), base 50000:**
  - Main: low = 50001-50007 (7), medium = 50011-50017 (7), high = 50021-50027 (7)
  - Low-signal: 50031-50058 (28)

Total Final Test runs: 21 + 28 = **49**.

## What happens if AC10 still fails

Per SS11: "If Final Test still fails AC10 after execution: AC10 = FAIL,
reported as a finding. No additional runs are appended post-hoc to the same
Final Test." If that happens, it is reported with its numbers in
`P2_FINAL_TEST_FINDINGS.md`, not patched by adding more runs to this same
frozen set.
