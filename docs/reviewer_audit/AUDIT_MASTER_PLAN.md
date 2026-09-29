# Reviewer Robustness Audit — Master Plan

**Started:** 2026-09-27
**Status:** Phase I complete on all fronts (closed by `AUDIT_SYNTHESIS.md`, including A1 at 60/300/600s); Phase II (A4, same-traffic alternative-flow-representation sensitivity) awaiting the user's go/no-go

## Master rule

The preregistered H2 and H3 analyses (docs/methodology/, results/unsw/,
results/botiot/, results/dependence/, results/multiplicity/) are closed.
No preregistered hypothesis, feature, threshold, decision rule, seed, or
confirmatory result is modified by this sprint.

Everything produced from 2026-09-27 onward under docs/reviewer_audit/ and
results/audit/ is a POST-HOC ROBUSTNESS ANALYSIS, reported as such, never
relabeled as confirmatory.

## The four audits

- **A1 — BoT-IoT dependence.** Does the STRONG REPLICATION verdict survive
  when flows are no longer treated as independent resampling units?
  `docs/reviewer_audit/A1_BOT_DEPENDENCE.md`.
- **A2 — reply-conditional decomposition.** Is directional asymmetry doing
  work beyond "did the destination reply at all"?
  `docs/reviewer_audit/A2_REPLY_CONDITIONAL.md`.
- **A3 — feature semantics + CICIDS per-label.** Does CICIDS's label
  granularity actually let HOIC/LOIC-HTTP/LOIC-UDP/Hulk be told apart, and
  what do Argus/CICFlowMeter actually mean by "bytes"?
  `docs/reviewer_audit/A3_EXPORTER_AND_LABEL_SEMANTICS.md`.
- **A4 — common-exporter control (NF-CSE-CIC-IDS2018-v2).** Out of scope
  for this plan. Gated on the Gate 1 synthesis below; requires downloading
  a new external dataset, which is a separate decision.

## Phase I -> Gate 1 -> Phase II

Phase I (A1, A2, A3) uses only data already on disk. It ends with
`docs/reviewer_audit/AUDIT_SYNTHESIS.md`, which classifies every affected
manuscript claim as SURVIVES / SURVIVES WITH QUALIFICATION / WEAKENED /
RETRACT. Phase II (A4) is a separate, later decision and is not started by
this plan.

## Pre-committed interpretation matrix

| A1 dependence | A2 answered-only | Interpretation |
|---|---|---|
| survives | survives | Evidence for directional semantics strengthens |
| survives | collapses | Asymmetry is largely a proxy for reply structure |
| weakens | survives | Phenomenon exists; original CI overstated precision |
| weakens | collapses | Benchmark interaction/reply-structure artifact |

No result is chosen after the fact to preserve the current narrative. The
`STRONG REPLICATION` verdict in `results/botiot/verdict.json` remains
documented as a historical script output regardless of what this sprint
finds.
