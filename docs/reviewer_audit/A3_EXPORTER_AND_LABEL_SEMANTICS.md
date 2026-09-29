# A3 — Feature semantics + CICIDS per-label re-analysis (frozen 2026-09-27)

## Question

Two sub-claims need checking against primary sources / the actual files:
(a) does CICIDS-2018's `Label` column actually separate HOIC from
LOIC-HTTP from LOIC-UDP from Hulk, contradicting any manuscript language
that treats a capture as an unresolvable mix; (b) do Argus (UNSW/BoT-IoT)
and CICFlowMeter (CICIDS) mean the same thing by "bytes" in a flow record.

## What this does NOT touch

The CICIDS discovery numbers already reported (docs/datos-reales/,
ESTADO-ACTUAL.md) as exploratory findings — those stand. This audit
re-derives the same kind of numbers directly and independently from
`data/raw/*.csv`'s raw `Label` column, and separately documents feature
semantics; it does not edit the existing exploratory write-up.

## New analysis (frozen before execution)

1. `scripts/audit_a3_cicids_labels.py`: for each of the 10 files in
   `data/raw/`, `df["label"].value_counts()` after stripping whitespace,
   then per distinct non-benign label: `n`, `auc_signed(A_bytes)`,
   `auc_sep(A_bytes)`, `auc_signed(A_packets)`, reply rate
   (`totlen_bwd_pkts == 0`), median `A_bytes` for attack vs. benign in the
   same file. `A_bytes = log1p(totlen_fwd_pkts) - log1p(totlen_bwd_pkts)`,
   `A_packets = log1p(tot_fwd_pkts) - log1p(tot_bwd_pkts)` (CICFlowMeter's
   raw byte/packet-count columns, matching the canonical `fwd_bytes`/
   `bwd_bytes` definition used for UNSW/BoT-IoT).
2. `docs/reviewer_audit/A3_FEATURE_SEMANTICS_TABLE.md`: a documentation-only
   comparison table (CICFlowMeter vs. Argus-UNSW vs. Argus-BoT-IoT) for:
   forward/backward direction definition, byte accounting (transaction
   bytes vs. application bytes — Argus documents `sbytes`/`dbytes` as
   transaction bytes and separate `sappbytes`/`dappbytes` fields for
   application bytes; whether CICFlowMeter's `TotLen Fwd/Bwd Pkts` includes
   headers needs checking against the exact CICFlowMeter version's source,
   not assumed), packet-count fields, IP availability. Filled from the
   UNSW-NB15 description PDF already on disk
   (`C:\Users\DavidG\Downloads\UNSW-NB15\The UNSW-NB15 description.pdf`)
   and `src/ingest/bot_iot.py`'s `NAMES_FILE`/`column_names()`; cells that
   cannot be verified from a primary source on disk are marked
   `UNVERIFIED`, not guessed.

## Frozen interpretation

- **HOIC/LOIC-HTTP/LOIC-UDP/Hulk separate cleanly in the raw labels and
  show different signs/magnitudes** -> correct any manuscript language
  that describes CICIDS floods as an unresolvable mix; report the
  per-label numbers.
- **Labels don't actually separate the mechanisms** (e.g. because the
  file conflates capture windows) -> the existing "mixed capture" caveat
  stands, now with the value_counts evidence attached.
- **Byte semantics differ meaningfully between Argus and CICFlowMeter**
  (e.g. transaction vs. application bytes) -> flag as a limitation on
  any exporter-independence claim in the manuscript; this becomes the
  main input to the A4 go/no-go decision, not resolved here.
