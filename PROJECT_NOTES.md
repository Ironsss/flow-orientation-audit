> Originally named `CLAUDE.md`. Documents written during development refer to this file by that name.

# Working notes for this repository

Read `docs/metodologia/` before proposing or running anything. This file is the
short version of what that directory cost to learn.

## What the project is asking

**Which representation survives the information restrictions of a real
deployment, and how early does it give a usable signal?**

Not "which features score best on CICIDS". That question was answered — per-flow
directional asymmetry wins — and answering it turned out not to matter, because
CICIDS features presuppose full packet reconstruction that no router performs.

**H2** (`docs/metodologia/REPLANTEO-OPERACIONAL.md`): under information
restriction, topology degrades *less* than per-flow asymmetry. **REJECTED**, on
synthetic and real data. As pre-committed, the framing was not amended: the
honest result for that question is per-flow only.

**Current line: H3**, external validation of an observation from CICIDS that
the *sign* of per-flow asymmetry depends on the attack mechanism.
**Did not replicate on UNSW-NB15; replicated (STRONG) on BoT-IoT**, where the
environment reading from UNSW predicted 6/6 flood groups in advance. Both
datasets are now spent as confirmatory sets for H3. Status, always current: **`docs/ESTADO-ACTUAL.md`**. Read
it before anything else, and update it in the same PR as any change of state.

Two rules added by the H3 work:
- **A dataset used for a confirmatory test is spent** for that hypothesis.
  UNSW-NB15 cannot be re-mined for H3 variants.
- **Freeze → push → code → push → run once.** The script computes the
  verdict. Anything else is labeled POST-HOC.

## The rule that generated everything here

**Run the code. Do not reason about what it would do.**

Every claim in this repository was produced by execution. That discipline is why
the project found its own headline metric to be broken, its own default
threshold to be wrong, and its own diagnostic to be confounded. Reasoning
carefully produced three wrong answers that testing caught.

## Five mistakes already made. Do not remake them.

1. **A confound produced AUC 1.0000.** Positives came from one set of simulation
   runs and negatives from another; `n_nodes` was 51 in one class and 50 in the
   other with zero overlap. A size-only control arm caught it, and it was there
   by habit rather than design. → **Control C1 (size-only arm) in every
   comparison. Control C2 (same run) in every design.**

2. **A metric was published without being probed.** Five rounds of scrutiny went
   into a spectral component that was retired; `A_dir`, which survived and
   carried the whole narrative, was never subjected to the same test and turns
   out to be flat across 95% of its input domain. → **Apply the independence
   probe to what you intend to keep, not only to what you doubt.**

3. **A default was reasoned rather than measured.** The correlation threshold
   shipped at 0.95 because it "seemed conservative". Measured, damage is already
   severe at 0.85. → **`src/audit/` defaults now carry the curve that justifies
   them.**

4. **A limitation was declared instead of measured.** "The threshold is a
   choice, not a derived value" sat in the docs as an acknowledged caveat.
   Measuring it took twenty minutes and proved the value wrong. → **Declaring a
   limitation is cheaper than measuring it and worth much less.**

5. **Generality was claimed on one case.** An audit protocol developed here was
   argued to transfer to fraud and medical diagnosis on the strength of
   synthetic data plus one case study. → **Scope claims to what was run.**

## The simulator has blocked six measurements

PR-AUC ceiling; no negative class in infiltration; AUC 1.0000 across all three
feature sets on brute force; the size confound; saturation in both
information-restriction experiments. `experiments/04_restriction.py` now refuses
to report a verdict when its gate fails, and the gate fails today.

**The instrument is the blocker, not the dataset and not the method.** A
baseline scoring 1.0000 with one second of observation leaves no headroom for
any treatment to win in. Acceptance criteria are in `docs/metodologia/`; the
binding one is that the per-flow baseline must not saturate.

*Since then:* Generator v2 passed Phase 0 for a scoped set of levels
(`docs/methodology/P2_PHASE0_REVALIDATION_FINDINGS.md`), which made the H2
verdict possible. The lesson stands for any new instrument: check for
saturation first.

## Repository layout, by role

| Path | Role |
|---|---|
| `src/features/` | Extractors organized by `InfoTier` — the thesis, as code |
| `src/restriction/` | Operators that withdraw information — the independent variable |
| `src/audit/` | Attribution protocol — the **instrument**, not the contribution |
| `src/iag/` | The retired index. Kept as an audited baseline, not a proposal |
| `src/graphs/`, `src/ingest/`, `src/models/`, `src/simulator/`, `src/viz/` | Pipeline, reused unchanged |
| `experiments/04_restriction.py` | The pre-registered experiment. Gated |
| `experiments/01–03` | Built for the superseded framing. Legacy |
| `scripts/preflight_data.py` | Run on ONE real file before downloading more |
| `scripts/validate_claims.py` | Re-derives the documented numbers locally |
| `scripts/analyze_real_data.py` | Statistics + column audit on real files, real vs. simulator contrast |
| `scripts/explore_real_data_structure.py` | Real interaction graph + unsupervised clustering on real data |
| `scripts/benchmark_real_data.py` | First supervised benchmark on real data, flow-level, no windows needed |
| `scripts/run_h2_real.py` | H2 on real data, canonical windowing. Verdict: REJECTED |
| `src/ingest/unsw_nb15.py` | UNSW-NB15 → canonical flow schema |
| `scripts/run_unsw_external_validation.py` | H3 on UNSW-NB15, frozen plan, script-computed verdict: NO REPLICATION |
| `docs/ESTADO-ACTUAL.md` | **Current project status. Single source of truth** |
| `docs/methodology/` | Freezes and findings in order (P2, H2, H3/UNSW, H3/BoT-IoT). Index in its README |
| `docs/datos-reales/` | First real-data statistical analysis. Real per-flow AUC vs. documented |
| `docs/comprension-datos/` | Data-understanding guide for CICIDS-2018 — pedagogical, not a finding |
| `paper/` | Superseded manuscript. Do not extend it |
| `manuscript/` | **Current manuscript** (v2 draft, includes BoT-IoT). Every table cites its source file in a comment; figures are regenerated by `manuscript/figures/make_figures.py` |

## Conventions that are not negotiable

- **Branch → PR → review → merge.** Never commit to `main`. GitHub blocks
  self-approval, so self-reviews use `event: "COMMENT"` (`CONTRIBUTING.md`).
- **`pytest` and `ruff check .` clean before every commit.** Run the suite more
  than once when touching anything stochastic.
- **Numbers in docs come from execution**, with the command that produced them
  recoverable.
- **Negative results are kept with their numbers.** Five spectral formulations,
  three failed hypotheses, six blocked measurements — all preserved. A
  documented dead end is worth more than a silently discarded one.
- **`data/raw/` is gitignored.** Never commit dataset files.

## Before proposing anything new

Ask, in this order:

1. Does `docs/metodologia/` already state the question this would answer?
2. Can the current instrument measure it? (Six times: no.)
3. What control rules out the obvious alternative explanation?
4. What result would make me abandon this?

If step 4 has no answer, it is not an experiment.
