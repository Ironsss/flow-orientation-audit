# A2 — Reply-conditional decomposition (frozen 2026-09-27)

## Question

When `bwd_bytes == 0` (no reply), `A_bytes = log1p(fwd_bytes) - log1p(0) > 0`
for any nonzero forward traffic, by construction. "Unanswered flows produce
positive A_bytes" can therefore be partly definitional rather than a
directional-asymmetry finding. This audit checks how much of the observed
AUC survives once reply presence is held fixed.

## What this does NOT touch

`results/unsw/`, `results/botiot/`, any confirmatory verdict.

## New analysis (frozen before execution), per dataset (UNSW, BoT-IoT,
CICIDS) and per attack group/label

1. `P(bwd_bytes == 0 | attack)`, `P(bwd_bytes == 0 | benign)`,
   `P(bwd_packets == 0 | attack)`, `P(bwd_packets == 0 | benign)`.
2. `AUCsigned(A_bytes)` on: all flows; answered-only (`bwd_bytes > 0` on
   both attack and benign rows); unanswered-only.
3. `AUCsigned(A_packets)` on: all flows; `bwd_packets > 0`-only.
4. Report `n_attack` and `n_benign` alongside every AUC — an AUC on a
   near-empty answered-only slice (e.g. UNSW Generic, ~2% answered) is not
   informative regardless of its point value.

## Frozen interpretation

- **Answered-only AUC stays close to the all-flows AUC** (e.g. within the
  all-flows 95% CI) for a group -> directional magnitude carries
  information beyond reply presence for that group.
- **Answered-only AUC collapses toward 0.5** -> that group's observed
  asymmetry is substantially a proxy for reply presence, not magnitude.
- **Answered-only AUC's sign flips** -> report as its own finding; do not
  discard.
- No group's answered-only result is used to "rescue" or discard another
  group's all-flows result — each group is reported independently.
