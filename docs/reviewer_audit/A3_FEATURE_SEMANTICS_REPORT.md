# A3 — CICIDS per-label breakdown + feature semantics: report (2026-09-27)

## Question

(a) Does CICIDS-2018's raw `Label` column actually separate `HOIC` from
`LOIC-HTTP` from `LOIC-UDP` from `Hulk` etc., contradicting any manuscript
language that treats a capture as an unresolvable mix? (b) Do Argus
(UNSW/BoT-IoT) and CICFlowMeter (CICIDS) mean the same thing by "bytes" in
a flow record?

## Frozen interpretation

`docs/reviewer_audit/A3_EXPORTER_AND_LABEL_SEMANTICS.md`, frozen
2026-09-27, before this task's code ran:

- Labels separate cleanly with different signs/magnitudes -> correct
  manuscript language.
- Labels don't actually separate -> existing "mixed capture" caveat
  stands.
- Byte semantics differ meaningfully -> flag for A4, not resolved here.

## What this does NOT touch

Re-derives independently from `data/raw/*.csv`'s raw `Label` column; does
not edit `docs/datos-reales/`'s existing exploratory write-up.

## Data used

All 10 CICIDS-2018 CSVs (`Friday-02-03-2018` ... `Wednesday-28-02-2018`),
via `src.ingest.loader.load_csv` per file. Run command:

```
python scripts/audit_a3_cicids_labels.py --data-dir "<repo>/data/raw"
```

Note on path: this task ran in a git worktree
(`.claude/worktrees/reviewer-audit-phase1`); `data/raw/` is gitignored and
was empty in the worktree (only `.gitkeep` — gitignored files are not
copied when a worktree is created). The 10 real CSVs live in the main
checkout at `C:\Users\DavidG\iag-symmetry\data\raw`; `--data-dir` was
pointed there for the real run. Output written to
`results/audit/a3_cicids_labels.csv` (21 rows). Runtime: well under a
minute, as expected for the smallest of the three datasets.

## Results: per-label AUC breakdown

| file | label | n | auc_signed(A_bytes) | auc_sep(A_bytes) | auc_signed(A_packets) | reply_rate |
|---|---|---|---|---|---|---|
| Friday-02-03 | Bot | 282,310 | 0.8384 | 0.8384 | 0.4616 | 0.5061 |
| Friday-16-02 | DoS attacks-Hulk | 434,873 | 0.0234 | 0.9766 | 0.9419 | 0.0587 |
| Friday-16-02 | DoS attacks-SlowHTTPTest | 19,462 | 0.0248 | 0.9752 | 0.0678 | 0.0 |
| Friday-23-02 | Brute Force -Web | 362 | 0.8168 | 0.8168 | 0.7894 | 0.3481 |
| Friday-23-02 | Brute Force -XSS | 151 | 0.4543 | 0.5457 | 0.7921 | 0.4901 |
| Friday-23-02 | SQL Injection | 53 | 0.5360 | 0.5360 | 0.5886 | 0.5094 |
| Thuesday-20-02 | DDoS attacks-LOIC-HTTP | 576,191 | 0.3813 | 0.6187 | 0.4580 | 0.5021 |
| Thursday-01-03 | Infilteration | 93,040 | 0.5371 | 0.5371 | 0.4596 | 0.5132 |
| Thursday-15-02 | DoS attacks-GoldenEye | 41,455 | 0.5099 | 0.5099 | 0.6123 | 0.6467 |
| Thursday-15-02 | DoS attacks-Slowloris | 10,285 | 0.9120 | 0.9120 | 0.7822 | 0.0138 |
| Thursday-22-02 | Brute Force -Web | 249 | 0.7082 | 0.7082 | 0.6637 | 0.5703 |
| Thursday-22-02 | Brute Force -XSS | 79 | 0.4467 | 0.5533 | 0.7983 | 0.4937 |
| Thursday-22-02 | SQL Injection | 34 | 0.5134 | 0.5134 | 0.6164 | 0.6176 |
| Wednesday-14-02 | FTP-BruteForce | 39,352 | 0.7605 | 0.7605 | 0.3138 | 0.0 |
| Wednesday-14-02 | SSH-Bruteforce | 117,322 | 0.5879 | 0.5879 | 0.4020 | 0.7997 |
| Wednesday-21-02 | DDOS attack-HOIC | 668,461 | 0.0005 | 0.9995 | 0.7509 | 0.2450 |
| Wednesday-21-02 | DDOS attack-LOIC-UDP | 1,730 | 1.0000 | 1.0000 | 1.0000 | 0.0 |
| Wednesday-28-02 | Infilteration | 68,857 | 0.4938 | 0.5062 | 0.5015 | 0.6275 |

(Full numbers, including `median_a_bytes_attack`/`median_a_bytes_benign`,
in `results/audit/a3_cicids_labels.csv`.)

Three additional rows, one per file (`Friday-16-02`, `Thursday-01-03`,
`Wednesday-28-02`), have `label == "Label"`, `n == 1`,
`median_a_bytes_attack == NaN`. **This is not a fifteenth attack type.**
`src/ingest/loader.py`'s own docstring documents that CICIDS-2018 CSVs
embed repeated CICFlowMeter export header rows mid-file; one such header
row per affected file survives ingestion as a single malformed data row
whose numeric fields fail to parse (null, not caught by `_clean_data`'s
inf/NaN cleaning, which only fires on actual NaN/inf, not null) and whose
`Label` field literally contains the string `"Label"`. Its `A_bytes` is
`NaN` (hence `auc_signed`/`auc_sep` == 1.0 for it, an artifact of how
`counting_auc`'s `np.unique` orders a lone `NaN`, not a real separation).
Excluded from the analysis below.

## Sub-question (a): do the raw labels separate cleanly?

**Yes.** 14 distinct real attack-label strings appear across the 10
files, and they match the reviewer-quoted list exactly: `HOIC`,
`LOIC-HTTP`, `LOIC-UDP`, `Hulk`, `SlowHTTPTest`, `GoldenEye`, `Slowloris`,
plus `Bot`, `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`,
`Infilteration` (x2 files), `FTP-BruteForce`, `SSH-Bruteforce`. Nothing
merges two mechanistically distinct attack types under one label, and
nothing that looks like a real attack type collapses into `Benign`.

The `auc_signed(A_bytes)` values span almost the entire `[0, 1]` range
across these labels — `0.0005` (`HOIC`) to `1.0000` (`LOIC-UDP`), with
`Hulk` at `0.0234`, `LOIC-HTTP` at `0.3813`, `Slowloris` at `0.9120` — i.e.
different floods sit on opposite sides of neutral (`0.5`) and at very
different distances from it. This is different signs and different
magnitudes, on large samples (`n` from 10,285 to 668,461 for these four),
not noise.

**Classification against the frozen buckets: bucket 1 applies** — "labels
separate cleanly... with different signs/magnitudes" — for the labels with
non-degenerate reply rates (`HOIC` reply_rate 0.245, `LOIC-HTTP` 0.502,
`GoldenEye` 0.647, `Slowloris` 0.014 but not exactly 0). Manuscript
language that describes a CICIDS capture's flood labels as one
unresolvable mix is not supported by this data and should be corrected.

**Caveat carried over from A2, not re-litigated here**: three of these
labels — `LOIC-UDP` (`reply_rate = 0.0` here, matching A2's finding
exactly), `SlowHTTPTest` (`reply_rate = 0.0`), and `FTP-BruteForce`
(`reply_rate = 0.0`) — are 100% unanswered. Per
`docs/reviewer_audit/A2_REPLY_CONDITIONAL_REPORT.md`, for these three
labels `A_bytes` is definitionally a reply-presence indicator (constant
forward-only traffic against a fixed benign distribution), not measured
magnitude asymmetry. Their `auc_signed(A_bytes)` here (`1.0000`, `0.0248`,
`0.7605` respectively) is real and correctly computed, but should not be
cited as evidence of *magnitude* separation — only `HOIC`, `LOIC-HTTP`,
`Hulk` (partially — `reply_rate = 0.0587`, mostly but not 100% unanswered),
`GoldenEye`, and `Slowloris` give AUCs where the reply-presence confound
does not fully explain the number. Any manuscript sentence citing "clean
separation across floods" should name which labels the claim is safe for
under this same caveat, rather than citing the full spread uniformly.

**Observation on the A2 "duplicate AUC" coincidence** (context handed to
this task, not independently re-derived): A2 found `FTP-BruteForce` and
`DoS attacks-SlowHTTPTest` sharing an identical pooled `A_packets` AUC
(`0.360`) despite different `n`, attributed there to both labels having
`reply_packets = 1.0` against the same dataset-wide pooled benign
population. **This does not reproduce in the per-file breakdown here**:
`FTP-BruteForce`'s `auc_signed(A_packets)` is `0.3138` (Wednesday-14-02)
and `SlowHTTPTest`'s is `0.0678` (Friday-16-02) — different files, and
this script computes AUC against each file's *own* benign population
rather than a pooled dataset-wide one. That the coincidence depends on
pooling benign flows across files, and disappears once each label is
scored against only its own capture's benign flows, is consistent with
A2's own explanation (a shared benign population, not a shared mechanism)
and is noted here per the task's instruction, not further investigated.

**Reference-dependence (added in the Phase I fix wave, from committed
numbers only):** the same pooled-vs-per-file difference reverses the
orientation of three labels' all-flows `A_bytes` AUC. Per file (this
table): HOIC 0.0005, Hulk 0.023, SlowHTTPTest 0.025. Against A2's pooled
dataset-wide benign reference (`results/audit/a2_reply/auc_by_slice.csv`,
slice `all`): HOIC 0.577, Hulk 0.681, SlowHTTPTest 0.709. The two affected
capture files (Wednesday-21-02, Friday-16-02) are the ones whose own benign
median `A_bytes` is strongly positive (1.105, 0.975) rather than between
-0.34 and -0.30 like the other files. A CICIDS label's apparent sign depends on
which benign reference it is scored against. See `AUDIT_SYNTHESIS.md`.

**Resolved: which convention the discovery numbers use (Phase I close-out).**
Confirmed: the CICIDS discovery numbers are per-capture-file AUCs that pool
every attack label in the file against that file's own benign rows.
`docs/datos-reales/ANALISIS-DATOS-REALES.tex` (table at line ~841) has one row
per file (`Archivo`) with a plural label column (`Etiqueta(s) real(es)`), and
`manuscript/main.tex` (line 195: "for attack versus benign flows in each of
the ten CICIDS-2018 captures"; Limitations: "The CICIDS values are per
capture, and a capture may mix attacks") states the same convention. Because
both labels in a file share one benign set, the pooled AUC is the
attack-count-weighted mean of the per-label AUCs in
`results/audit/a3_cicids_labels.csv`. Computing that mean (excluding the n=1
`"Label"` header-artifact rows) reproduces all ten discovery figures to three
decimals — 0.838, 0.023, 0.694, 0.381, 0.537, 0.590, 0.633, 0.631, 0.003,
0.494. For Wednesday-21-02:
(668,461 × 0.000515 + 1,730 × 1.0000) / 670,191 = **0.0031**. So the published
"HOIC/LOIC-UDP 0.003" is HOIC (99.7% of that file's attack rows) with a small
LOIC-UDP contribution, not a separate number. It is consistent with A3's
per-label values, and the per-label split (HOIC 0.0005, LOIC-UDP 1.0000)
shows that the two floods in that capture point in opposite directions. The
manuscript's own line 315 already says CICIDS alone cannot tell which of the
two drives the inversion. Per label, HOIC does.
Command: `python -c "import polars as pl; d=pl.read_csv('results/audit/a3_cicids_labels.csv').filter(pl.col('label')!='Label'); print(d.group_by('capture_file').agg(((pl.col('n')*pl.col('auc_signed_bytes')).sum()/pl.col('n').sum()).alias('pooled')))"`.

## Sub-question (b): do Argus and CICFlowMeter mean the same thing by "bytes"?

Full comparison in `docs/reviewer_audit/A3_FEATURE_SEMANTICS_TABLE.md`.
Summary:

- **Verified, and different in kind**: CICFlowMeter's `TotLen Fwd/Bwd
  Pkts` is payload bytes only (confirmed by reading `BasicFlow.java`
  directly — headers are a separate field). Argus's `sbytes`/`dbytes` are
  documented as "transaction bytes" in UNSW-NB15's own official feature
  list — a different, Argus-specific term whose exact byte scope
  (header-inclusive or not) is **not** resolved by that document.
- **Verified, both datasets**: neither UNSW-NB15 nor BoT-IoT's actual
  exported feature sets include Argus's optional `sappbytes`/`dappbytes`
  (application-byte) fields — checked directly against both datasets' own
  column lists, not assumed from Argus's general capabilities.
- **UNVERIFIED, and flagged rather than guessed**: whether Argus's
  "transaction bytes" include L2/L3/L4 headers (no Argus manual/source on
  disk); whether "transaction bytes" is the right description for
  BoT-IoT's `sbytes`/`dbytes` specifically, since BoT-IoT's own feature
  file carries no text descriptions at all (name-only header) and this is
  inferred by analogy to UNSW-NB15, not independently confirmed.

**Classification: bucket 3 partially applies.** The two tools are
confirmed to define "bytes" differently in kind (payload-only vs.
Argus's undefined "transaction bytes" label) and there is no `sappbytes`
subtlety to worry about in either canonical adapter (both stick to plain
`sbytes`/`dbytes`, so this repo's `fwd_bytes`/`bwd_bytes` naming is at
least internally consistent). But whether the *magnitude* of the
CICFlowMeter/Argus difference matters for the manuscript's
exporter-independence claim cannot be settled without knowing whether
Argus's transaction bytes include headers — that specific gap is real,
unresolved by any source available on disk, and is exactly what should go
to A4 as an open question rather than being asserted either way.

## Files

- `scripts/audit_a3_cicids_labels.py`, `tests/test_audit_a3_cicids_labels.py`
- `results/audit/a3_cicids_labels.csv`
- `docs/reviewer_audit/A3_FEATURE_SEMANTICS_TABLE.md`, this report

## Bug found and fixed in the brief's test fixture

The brief's `Step 2` test built its 20/10/5/8-row synthetic CSV out of
*exact-duplicate* rows per label (same port, timestamp, packet/byte
counts). `src.ingest.loader.load_csv`'s `_clean_data()` calls
`lf.unique()` across all columns before labels are even inspected —
confirmed by running the brief's fixture verbatim through `load_csv`,
which collapsed it from 43 rows to 4 (one per distinct full row). The
fixed test (`tests/test_audit_a3_cicids_labels.py`) varies `Dst Port` per
repeated row so rows are distinct on their non-label columns, matching
real CICIDS-2018 data (no two real flows share every field), while still
testing exactly the thing A3 exists to test: that a whitespace-variant
label (`" DoS attacks-Hulk"`) is merged into its stripped counterpart
(`n == 15`, not double-counted or dropped).
