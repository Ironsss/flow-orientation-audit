# P2 Development -- findings

**Status:** Development-stage reading, informational only. Per
`P2_GENERATOR_V2_DESIGN_FREEZE.md` SS8, this phase "does not declare PASS of
behavioral acceptance criteria" -- that is Validation's job, on its own
disjoint seed set. Nothing here is a gate; it exists so the tunable
adjustments below are recoverable and their justification doesn't have to be
re-derived from a PR thread.

**Produced by:** `scripts/audit_generator_v2_development.py`, PR #32
(`analysis/p2-development-runs`). Every number below came from actually
running that script (`.venv/Scripts/python.exe scripts/audit_generator_v2_development.py`)
against the 20-run Development split it builds (10 Main = 4 low + 3 medium +
3 high, 10 Low-signal; seeds 20001-20040, reserved and never to be reused for
Validation/Final Test per SS12) -- none of it is reasoned from the config
alone, per `CLAUDE.md`'s "run the code" rule.

## Round 0 -- first execution, starting tunable defaults

Generator v2 had been implemented (PR #31) but never actually run before this.
Reading the design freeze's tunable defaults (`src/simulator/v2/config.py` as
merged in PR #31) against AC1-AC12:

| AC | Reading | Target | Status |
|---|---|---|---|
| AC1a pooled OVL(n_nodes) | 0.9988 | >=0.30 | clear |
| AC1b sep_run(n_nodes)>=0.95 | 0% | <=20% | clear |
| AC2a pooled OVL(n_flows) | 0.5965 | >=0.20 | clear |
| AC2b sep_run(n_flows)>=0.95, eligible | 28.6% (4/14) | <=20% | **borderline over** |
| AC3 onset diversity | 15/20 distinct start windows, 81.8% of span | >=15/30, >=30% | clear |
| AC5 severity diversity | 4/3/3/10 by construction | >=3 regimes x >=3 runs | clear |
| AC7 near-tau | 4 near-zero, 7 near-tau runs | >=3, >=3 | clear |
| AC8 pair_coverage_run (median) | 0.838 | <0.50 | **fails clearly** |
| AC9 std_recip_run (median) | 0.011 | >0.05 | **fails clearly** |
| AC11a reproducibility | identical trace on repeat | exact | clear |
| AC11b Low-signal validity | median(LS)=0.074 < Q1(Main)=0.481 | condition holds | clear |

AC8/AC9's root cause, found by inspecting `src/simulator/v2/background.py`
and `population.py` before changing anything: `_select_destination` samples a
fresh, independent destination from its bucket on every single flow -- no
host has a persistent set of "usual contacts." At the original background
volume (~1.3e5 flows/hour across 80 hosts), even a small per-flow probability
of an inter-community or hub destination accumulates, over an hour, into
almost every possible host pair being touched at least once (explains AC8),
and enough flows land in every window that the benign-vs-attack service mix
converges to nearly the same average reciprocity every window, by the law of
large numbers (explains AC9). Changing that per-flow independence would be an
architecture change, not a tunable-value change (SS13 of the design freeze
lists parameter *values* as tunable, not the destination-selection
algorithm), so the fix stayed within the tunable menu: `CommunityConfig`,
`ActivityProfile`, `ServiceProfile.response_probability`,
`SeverityProfile.peak_rate_per_attacker_range`.

## Round 1 -- fix AC8/AC9

Changed in `src/simulator/v2/config.py`:

- `CommunityConfig.p_inter`: 0.03 -> 0.0. A hub host has no community
  (`community_of[hub] is None`), so its *only* non-hub-to-hub route was the
  "inter" bucket -- all 76 non-hub hosts. At the hub roles' high base rate,
  this was the single biggest driver of AC8's failure. `hub_preference`:
  0.15 -> 0.05, tightening how hard even regular hosts fan out toward the 4
  hub destinations.
- `DEFAULT_ACTIVITY.base_flows_per_min`: cut ~20x on every role.
  `state_multiplier[IDLE]`: 0.3 -> 0.08 (idle periods now close to silent).
  Lower volume reintroduces per-window sampling noise in both pair coverage
  and reciprocity, which the original high-volume defaults had smoothed away.
- `DEFAULT_SERVICES.response_probability`: spread widened -- web/dns/ssh
  raised toward 0.92-0.98, bulk/periodic/m2m lowered toward 0.02-0.15. A
  second, volume-independent lever on AC9: a wider gap between "very
  reciprocal" and "not reciprocal" services means a window's exact service
  mix matters more, adding variance even when the low-volume fix alone isn't
  enough.

Result: AC8 median pair_coverage_run 0.838 -> 0.261; AC9 median std_recip_run
0.011 -> 0.052. Both now clear.

**But this broke two other criteria.** LOW/LOW_SIGNAL's attack rates were
untouched, so against a ~20x-smaller background they now dominated almost
every window's flow count: AC2b (eligible sep_run(n_flows)>=0.95) went from
28.6% to **100%** (target <=20%), and AC7's near-tau/near-zero windows nearly
vanished (0 runs near-zero, 1 near-tau, target >=3 each) because a burst this
large relative to the new background jumps `attack_ratio_gt` straight past
the near-tau band. This is recorded rather than hidden, per the project's
standing rule that a documented dead end is worth more than a silently
discarded one -- round 1 alone is not an acceptable configuration.

## Round 2 -- restore AC2b/AC7 without touching AC8/AC9's fix

`src.simulator.v2.background` never reads attack state (checked in the module
docstring and confirmed by re-reading the code before relying on it), so
nothing about round 1 needed to be undone -- only the attack side needed to
shrink to match. Changed in `src/simulator/v2/config.py`:

- `DEFAULT_SEVERITY[SeverityRegime.LOW].peak_rate_per_attacker_range`:
  (5.0, 15.0) -> (0.0833, 0.25).
- `DEFAULT_SEVERITY[SeverityRegime.LOW_SIGNAL].peak_rate_per_attacker_range`:
  (2.0, 4.0) -> (0.025, 0.05).

Only `peak_rate_per_attacker_range` was scaled (not `attacker_count_range`,
which is a count, not a rate, and not MEDIUM/HIGH, which AC2b's eligibility
rule -- `severity_regime in {low, low_signal}` -- never evaluates anyway).
The two values were chosen jointly to keep satisfying
`SimulationConfigV2.__post_init__`'s ordering constraint (LOW_SIGNAL's
`peak_rate_per_attacker_range` upper bound must stay strictly below every
Main regime's minimum, i.e. below LOW's own new lower bound).

## Final reading (20/20 Development runs)

| AC | Reading | Target | Status |
|---|---|---|---|
| AC1a pooled OVL(n_nodes) | 0.853 | >=0.30 | clear |
| AC1b sep_run(n_nodes)>=0.95 | 0% | <=20% | clear |
| AC2a pooled OVL(n_flows) | 0.618 | >=0.20 | clear |
| AC2b sep_run(n_flows)>=0.95, eligible | 0% | <=20% | clear (was 100% after round 1) |
| AC3 onset diversity | 15/20 distinct start windows, 81.8% of span | >=15/30, >=30% | clear |
| AC5 severity diversity | 4/3/3/10 by construction | >=3 regimes x >=3 runs | clear |
| AC7 near-tau | 10/20 near-zero, 12/20 near-tau | >=3, >=3 | clear (was 0/1 after round 1) |
| AC8 pair_coverage_run (median) | 0.261 | <0.50 | clear |
| AC9 std_recip_run (median) | 0.051 | >0.05 | clear, narrow (2/20 runs individually at 0.039/0.047) |
| AC11a reproducibility | identical trace on repeat | exact | clear |
| AC11b Low-signal validity | median(LS)=0.026 < Q1(Main)=0.279 | condition holds | clear |

AC6 was read as an unconditional proxy over all 20 runs rather than the
official "ramp_seconds>0 runs only" denominator, since `run_simulation_v2`
does not expose `AttackTiming` to callers (SS1 of the design contract: only
`simulation_seed` is public) -- the proxy read 70% of runs with >=2
intermediate windows, which understates the true rate and was not a design
target for this round of tuning.

## What this does and doesn't mean

Every AC this script can read is inside target on a 20-run Development
sample. That is evidence the tunable defaults are in a reasonable place, not
a Validation PASS -- Validation (N=30, its own disjoint seeds, official
PASS/FAIL per SS10) hasn't run. AC9 in particular has little margin (0.051
against a 0.05 target, with individual runs below it) and is the one most
worth re-checking rather than assuming it will hold at N=30.

## Recommendation

Candidate Freeze is a reasonable next step, but it's a decision gate (SS14):
a human should confirm before generative parameters are declared candidate-
frozen and Validation seeds are drawn.
