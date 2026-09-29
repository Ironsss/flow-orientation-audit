# A4 — Data preflight (Step 0, structural only)

**Status:** POST-HOC REVIEWER ROBUSTNESS AUDIT, pre-freeze inventory.
**No outcome was computed.** No AUC, sign, `A_bytes`/`A_packets` value or
distribution, and no feature-by-label relationship was computed for this
document. Label counts are structural preflight, as the A4 task allows.

**Two NF inputs are inventoried here.**

1. **Standalone `NF-CSE-CIC-IDS2018-v2.csv`** (added 2026-09-27, next
   section). It carries the 14 fine CIC labels and is the **PRIMARY A4 NF
   input** from the fine-grained re-freeze onward.
2. **Merged `NF-UQ-NIDS-v2.csv`** (the original Step 0, from "Provenance
   (merged file)" down). It is **RETAINED** with its provenance as recorded,
   but it is **no longer the primary A4 dataset**. It may later serve one
   purpose: a cross-check that aggregating the standalone file's fine labels
   into coarse categories reproduces the merged file's own category-level
   row counts. That check belongs to a later task and was **not** run here.

## Standalone NF-CSE-CIC-IDS2018-v2 (PRIMARY A4 NF input)

### Gate (run first; would have stopped everything on mismatch)

The UQ RDM page for this dataset
(`https://rdm.uq.edu.au/files/ce5161d0-ef9c-11ed-827d-e762de186848`)
publishes 18,893,708 rows, 16,635,567 benign and 2,258,141 attack. The
script checks the file against these before hashing or inventorying anything,
and exits non-zero on any mismatch.

| | required | found |
|---|---|---|
| rows | 18,893,708 | **18,893,708** |
| benign (`Label == 0`) | 16,635,567 | **16,635,567** |
| attack (`Label == 1`) | 2,258,141 | **2,258,141** |

**Gate passed exactly.**

### Provenance

| Item | Value |
|---|---|
| Source directory (BagIt bag, not copied into the repo) | `C:\Users\DavidG\Downloads\b3427ed8ad063a09_MOHANAD_A4706\b3427ed8ad063a09_MOHANAD_A4706` |
| Bag metadata (`bag-info.txt`) | University of Queensland (UQRDM), External-Identifier `b3427ed8ad063a09_MOHANAD_A4706`, Bagging-Date 2023-05-11, contact Mohanad Sarhan. `FurtherInformation.txt` points to `https://espace.library.uq.edu.au/view/UQ:e9636b7` (not fetched) |
| Command | `.venv/Scripts/python.exe scripts/audit_a4_finegrained_preflight.py` |
| Output | `results/audit/a4_representation/preflight_inventory_finegrained.json`. Two rows upserted into `data_manifest.csv`, with the merged-file rows kept unchanged |
| Preflight run (UTC) | 2026-09-27T22:49:24Z to 2026-09-27T22:49:47Z (the gate query ran just before, in the same invocation) |
| Git HEAD at run | `fb814d14595e3f825bc926e39b2596980b82c5ff` |
| Environment | Python 3.11.16 (MSC v.1944, 64-bit), polars 1.44.1, Windows 10 |
| Integrity | SHA1 of both data files matches the bag's `manifest-sha1.txt` (`sha1_matches_bag_manifest: true`; data file SHA1 `80ff7fd07e2bc31164197f07fe9d9606ee565f9a`) |
| `NetFlow_v2_Features.csv` | **Byte-identical** to the merged bag's copy (same 2,115 bytes, same SHA256 `f20e86a9…e939`). Both bags document the same schema family |

| filename | size bytes | SHA256 | rows | columns |
|---|---|---|---|---|
| `NF-CSE-CIC-IDS2018-v2.csv` | 3,221,378,977 | `16a545a3e139b2e85d08b1b7d9d40328c3689a49d0deaafce6dcf8d7b63e1257` | 18,893,708 | 45 = the 43 documented fields + `Label`, `Attack` (no `Dataset` column) |
| `NetFlow_v2_Features.csv` | 2,115 | `f20e86a939f9eb53b06ace15de4cc977ed61c02e538c6465efe72b635448e939` | 43 | `Feature`, `Description` |

### Schema

Same 43 feature columns, in the same order, as the merged file, followed by
`Label`, `Attack`. There is no `Dataset` column. All 45 columns have
**0 nulls and 0 empty strings**. All 42 numeric columns parse to Float64 with
**0 failures** over the full file. The types polars infers from the first 100k
rows are the same as the merged file's, with one difference: `FTP_COMMAND_RET_CODE`
is inferred as Int64 here and as Float64 there. Inference only looks at the
first 100k rows, and those came from other datasets in the merged file. A4
does not use this field.

| Question | Answer |
|---|---|
| Label / category columns | `Label` (0/1). `Attack` (**fine** CIC label string) |
| Source / destination IP | Yes: `IPV4_SRC_ADDR` (224,568 distinct), `IPV4_DST_ADDR` (33,614 distinct), plus ports. These are the same distinct counts as the merged file's CIC subset |
| Timestamp / capture identifier | **None.** No timestamp, date, capture-day or source-file column. Capture-matched benign stays impossible on the NF side (see the freeze) |
| Candidate directional byte fields | `IN_BYTES`, `OUT_BYTES` |
| Candidate directional packet fields | `IN_PKTS`, `OUT_PKTS` |

### Label vocabulary (`Label`, `Attack`, rows)

Every one of the 14 NF `Attack` strings is **byte-for-byte identical** to a
canonical CICFlowMeter label string in `results/audit/a3_cicids_labels.csv`,
including CIC's own spellings (`Infilteration`, `SSH-Bruteforce` vs.
`FTP-BruteForce`, `DDOS attack-` vs. `DDoS attacks-`). There are no NF-only
labels and no canonical-only labels. No pooling is needed.

| Label | `Attack` (= canonical label) | NF rows | canonical rows |
|---|---|---|---|
| 0 | Benign | 16,635,567 | 13,467,970 |
| 1 | DDOS attack-HOIC | 1,080,858 | 668,461 |
| 1 | DDOS attack-LOIC-UDP | 2,112 | 1,730 |
| 1 | DDoS attacks-LOIC-HTTP | 307,300 | 576,191 |
| 1 | DoS attacks-Hulk | 432,648 | 434,873 |
| 1 | DoS attacks-SlowHTTPTest | 14,116 | 19,462 |
| 1 | DoS attacks-GoldenEye | 27,723 | 41,455 |
| 1 | DoS attacks-Slowloris | 9,512 | 10,285 |
| 1 | Bot | 143,097 | 282,310 |
| 1 | FTP-BruteForce | 25,933 | 39,352 |
| 1 | SSH-Bruteforce | 94,979 | 117,322 |
| 1 | Infilteration | 116,361 | 161,897 |
| 1 | Brute Force -Web | 2,143 | 611 |
| 1 | Brute Force -XSS | 927 | 230 |
| 1 | SQL Injection | 432 | 87 |

`Label == 0` occurs only with `Attack == "Benign"`, and `Label == 1` never
does. Canonical rows come from the canonical table further down
(`a3_cicids_labels.csv`, summed over capture files). Every label's row count
differs between the two sides, some by a factor of 2 or more (HOIC ×1.62,
LOIC-HTTP ×0.53, Bot ×0.51, Brute Force -Web ×3.5). So the fine labels are
not a row-for-row re-export either.

### Duplicates and label-blind invariants

- **Exact full-row duplicates: 0** of 18,893,708 (same 64-bit row-hash method
  as below, over all 45 columns). The merged file's CIC subset had 72 over
  its 46 columns. One possible explanation is that rows identical in every
  feature but carrying different fine labels became identical once the merge
  coarsened the labels. This is **UNVERIFIED** and was not checked, because
  checking it means relating feature values to labels.
- **Feature-only duplicates: 2,988 rows.** Hashing over the 43 feature
  columns alone (excluding `Label` and `Attack`) gives 18,890,720 distinct
  rows out of 18,893,708. Since full-row duplicates are 0, these 2,988 rows
  are feature-identical to another row but carry a different fine `Attack`
  label. They share the binary `Label`, so they are attack-vs-attack label
  conflicts, not attack-vs-benign. This is a label-blind structural count
  (row hashing only, no label-conditioned outcome), done by the A4 freeze
  reviewer after `0b705ad` and recorded here. It is consistent with the
  merge-coarsening explanation above but does not verify it (the merged
  file was not re-checked). Which labels are involved was not computed. The
  A4 tertiary pair contrast must report its tie share because of it
  (`A4_REPRESENTATION_SENSITIVITY.md`).
- **Label-blind invariants:** every count is identical to the merged CIC
  subset's (table below). There are 0 violations of every retransmission,
  bytes⇔packets, 20-byte-floor and min/max-packet-length relation, and
  1,122,754 rows (5.9%) where the size bins do not sum to total packets.

### Disclosure

To read the header, the first ~1,500 bytes of the standalone file were
printed (`head -c 1500`). That showed four complete data rows (one
SSH-Bruteforce, three Benign) and part of a fifth. It exposed their raw field
values, and so their `IN_/OUT_BYTES`. Nothing was computed from them. Four
rows out of 18.9M cannot inform any per-label AUC, and they are disclosed here
for completeness.

---

# Merged NF-UQ-NIDS-v2 (original Step 0; RETAINED, no longer primary)

## Provenance (merged file)

| Item | Value |
|---|---|
| Source directory (BagIt bag, not copied into the repo) | `C:\Users\DavidG\Downloads\9810e03bba4983da_MOHANAD_A4706\9810e03bba4983da_MOHANAD_A4706` |
| Bag metadata (`bag-info.txt`) | University of Queensland (UQRDM), External-Identifier `9810e03bba4983da_MOHANAD_A4706`, Bagging-Date 2023-05-11, contact Mohanad Sarhan; `FurtherInformation.txt` points to `https://espace.library.uq.edu.au/view/UQ:631a24a` (not fetched) |
| Command | `.venv/Scripts/python.exe scripts/audit_a4_preflight.py` |
| Output | `results/audit/a4_representation/preflight_inventory.json`, `results/audit/a4_representation/data_manifest.csv` |
| Preflight run (UTC) | 2026-09-27T21:59:39Z to 2026-09-27T22:01:36Z |
| Git HEAD at run | `bdc07f75b10a5fb7e3302758bb111d2073ffc93c` |
| Environment | Python 3.11.16 (MSC v.1944, 64-bit), polars 1.44.1, Windows 10 |
| Integrity | SHA1 of both data files matches the bag's own `manifest-sha1.txt` (`sha1_matches_bag_manifest: true`). No corruption detected. A later review pass independently recomputed the SHA256 of both files and found it matches the values below and in `data_manifest.csv` (reported by the reviewer, not re-run for this amendment) |

The raw data was **not** copied into `data/external/` and is not committed.

## Files

| filename | ext | size bytes | SHA256 | rows | columns |
|---|---|---|---|---|---|
| `NetFlow_v2_Features.csv` | .csv | 2,115 | `f20e86a939f9eb53b06ace15de4cc977ed61c02e538c6465efe72b635448e939` | 43 | `Feature`, `Description` (documentation of 43 fields) |
| `NF-UQ-NIDS-v2.csv` | .csv | 13,729,330,230 | `7e55364a20d98b9517097de77bbff168d1d0b047b8bb50bf4bb16287804920c8` | 75,987,976 | 46 = the 43 documented fields + `Label`, `Attack`, `Dataset` |

Bag files outside `data/` (`bag-info.txt`, `bagit.txt`, `FurtherInformation.txt`,
`manifest-sha1.txt`, `tagmanifest-sha1.txt`) are packaging metadata. They were
read, but they contain no schema information.

## The downloaded file is not NF-CSE-CIC-IDS2018-v2. It contains it as a subset

`NF-UQ-NIDS-v2.csv` is a merged file. Its `Dataset` column has exactly four
values:

| `Dataset` | rows | exact duplicate rows | distinct src IPs | distinct dst IPs |
|---|---|---|---|---|
| NF-BoT-IoT-v2 | 37,763,497 | 120,210 | 20 | 291 |
| **NF-CSE-CIC-IDS2018-v2** | **18,893,708** | **72** | 224,568 | 33,614 |
| NF-ToN-IoT-v2 | 16,940,496 | 0 | 23,079 | 6,868 |
| NF-UNSW-NB15-v2 | 2,390,275 | 0 | 40 | 40 |

**A4 uses only the rows with `Dataset == "NF-CSE-CIC-IDS2018-v2"`.** The
identification comes from the file's own `Dataset` column, not from
row order or position. The NF-BoT-IoT-v2 and NF-UNSW-NB15-v2 rows are out of
scope. The A4 task prohibits running UNSW or BoT alternative representations,
and both datasets are spent for H3.

## Schema

All 46 columns have **0 nulls, 0 empty strings**, and all 42 numeric columns
parse to Float64 with **0 failures** over the full file. Types were inferred by
polars from the first 100k rows:

- String: `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `Attack`, `Dataset`
- Float64: `L7_PROTO`, `SRC_TO_DST_SECOND_BYTES`, `DST_TO_SRC_SECOND_BYTES`, `FTP_COMMAND_RET_CODE`
- Int64: all other columns, including `Label`

Full column list, in file order: `IPV4_SRC_ADDR, L4_SRC_PORT, IPV4_DST_ADDR,
L4_DST_PORT, PROTOCOL, L7_PROTO, IN_BYTES, IN_PKTS, OUT_BYTES, OUT_PKTS,
TCP_FLAGS, CLIENT_TCP_FLAGS, SERVER_TCP_FLAGS, FLOW_DURATION_MILLISECONDS,
DURATION_IN, DURATION_OUT, MIN_TTL, MAX_TTL, LONGEST_FLOW_PKT,
SHORTEST_FLOW_PKT, MIN_IP_PKT_LEN, MAX_IP_PKT_LEN, SRC_TO_DST_SECOND_BYTES,
DST_TO_SRC_SECOND_BYTES, RETRANSMITTED_IN_BYTES, RETRANSMITTED_IN_PKTS,
RETRANSMITTED_OUT_BYTES, RETRANSMITTED_OUT_PKTS, SRC_TO_DST_AVG_THROUGHPUT,
DST_TO_SRC_AVG_THROUGHPUT, NUM_PKTS_UP_TO_128_BYTES, NUM_PKTS_128_TO_256_BYTES,
NUM_PKTS_256_TO_512_BYTES, NUM_PKTS_512_TO_1024_BYTES,
NUM_PKTS_1024_TO_1514_BYTES, TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT, ICMP_TYPE,
ICMP_IPV4_TYPE, DNS_QUERY_ID, DNS_QUERY_TYPE, DNS_TTL_ANSWER,
FTP_COMMAND_RET_CODE, Label, Attack, Dataset`.

| Question | Answer |
|---|---|
| Label / category columns | `Label` (0/1). `Attack` (category string). `Dataset` (source benchmark) |
| Source / destination IP | Yes: `IPV4_SRC_ADDR`, `IPV4_DST_ADDR` (plus `L4_SRC_PORT`, `L4_DST_PORT`) |
| Timestamp | **None.** No timestamp, date, capture-day or source-file column exists |
| Candidate directional byte fields | `IN_BYTES`, `OUT_BYTES` (see `A4_FEATURE_MAPPING.md` for semantics) |
| Candidate directional packet fields | `IN_PKTS`, `OUT_PKTS` |
| Other directional fields | `RETRANSMITTED_{IN,OUT}_{BYTES,PKTS}`, `SRC_TO_DST_/DST_TO_SRC_SECOND_BYTES`, `SRC_TO_DST_/DST_TO_SRC_AVG_THROUGHPUT`, `TCP_WIN_MAX_{IN,OUT}`, `DURATION_{IN,OUT}`, `CLIENT_/SERVER_TCP_FLAGS` |

## Label vocabulary

### NF-CSE-CIC-IDS2018-v2 subset (`Label`, `Attack`, rows)

| Label | Attack | rows |
|---|---|---|
| 0 | Benign | 16,635,567 |
| 1 | Bot | 143,097 |
| 1 | Brute Force | 123,982 |
| 1 | DDoS | 1,390,270 |
| 1 | DoS | 483,999 |
| 1 | Infilteration | 116,361 |
| 1 | injection | 432 |

`Label == 0` occurs only with `Attack == "Benign"`, and `Label == 1` never
does. The two columns are consistent. **The merged file carries only coarse
attack categories.** None of CICFlowMeter's fine labels (HOIC, LOIC-UDP,
LOIC-HTTP, Hulk, SlowHTTPTest, GoldenEye, Slowloris, FTP-/SSH-Bruteforce,
Brute Force -Web/-XSS, SQL Injection) appears in this file.

### Other subsets (inventory only, not used)

- NF-BoT-IoT-v2: Benign 135,037; DDoS 18,331,847; DoS 16,673,183;
  Reconnaissance 2,620,999; Theft 2,431.
- NF-ToN-IoT-v2: Benign 6,099,469; Backdoor 16,809; DDoS 2,026,234;
  DoS 712,609; injection 684,465; mitm 7,723; password 1,153,323;
  ransomware 3,425; scanning 3,781,419; xss 2,455,020.
- NF-UNSW-NB15-v2: Benign 2,295,222; Analysis 2,299; Backdoor 2,169; DoS 5,794;
  Exploits 31,551; Fuzzers 22,310; Generic 16,560; Reconnaissance 12,779;
  Shellcode 1,427; Worms 164.

### Canonical CICFlowMeter side (already in repo, for comparison)

These are the attack rows per label after `src/ingest/loader.py` dedup
(`results/audit/a3_cicids_labels.csv`, column `n`, summed over capture files).
The pooled benign count is 13,467,970 (`A2_REPLY_CONDITIONAL_REPORT.md`):

| canonical label | rows | capture file(s) |
|---|---|---|
| DDOS attack-HOIC | 668,461 | Wednesday-21-02 |
| DDOS attack-LOIC-UDP | 1,730 | Wednesday-21-02 |
| DDoS attacks-LOIC-HTTP | 576,191 | Thuesday-20-02 |
| DoS attacks-Hulk | 434,873 | Friday-16-02 |
| DoS attacks-SlowHTTPTest | 19,462 | Friday-16-02 |
| DoS attacks-GoldenEye | 41,455 | Thursday-15-02 |
| DoS attacks-Slowloris | 10,285 | Thursday-15-02 |
| Bot | 282,310 | Friday-02-03 |
| FTP-BruteForce | 39,352 | Wednesday-14-02 |
| SSH-Bruteforce | 117,322 | Wednesday-14-02 |
| Brute Force -Web | 611 | Friday-23-02 (362), Thursday-22-02 (249) |
| Brute Force -XSS | 230 | Friday-23-02 (151), Thursday-22-02 (79) |
| SQL Injection | 87 | Friday-23-02 (53), Thursday-22-02 (34) |
| Infilteration | 161,897 | Wednesday-28-02 (68,857), Thursday-01-03 (93,040) |

The three `"Label"` header-artifact rows (n=1 each) are excluded, as in A2/A3.

Per-category row counts differ between the representations: Bot has 282,310
rows canonically and 143,097 in NF, Infilteration 161,897 and 116,361, DDoS
1,246,382 and 1,390,270. So NF-v2 flows are **not a row-for-row re-export** of
the CICFlowMeter flows. Flow segmentation and/or labelling differ, and no
row-level pairing between the two representations is possible.

## Duplicates: method

Exact full-row duplicates were counted over **all** rows, not a sample. Each
row's 46 string fields were concatenated with a unit separator, hashed to
64 bits (`polars` `hash`), and the distinct hashes were counted per `Dataset`.
The collision probability is about n²/2⁶⁵ ≈ 10⁻⁵ for the 18.9M CIC rows, which
is negligible. The CIC subset has 72 duplicate rows (0.0004%).

## Label-blind field invariants (CIC subset, 18,893,708 rows)

These checks are counts of rows that violate a structural relation between
paired fields. `Label` and `Attack` are not read. They inform the semantic
mapping and are not outcomes.

| invariant (violations counted) | violations |
|---|---|
| `RETRANSMITTED_IN_BYTES > IN_BYTES` | 0 |
| `RETRANSMITTED_OUT_BYTES > OUT_BYTES` | 0 |
| `RETRANSMITTED_IN_PKTS > IN_PKTS` | 0 |
| `RETRANSMITTED_OUT_PKTS > OUT_PKTS` | 0 |
| `IN_PKTS == 0` but `IN_BYTES > 0`, or `IN_PKTS > 0` but `IN_BYTES == 0` | 0, 0 |
| `OUT_PKTS == 0` but `OUT_BYTES > 0`, or `OUT_PKTS > 0` but `OUT_BYTES == 0` | 0, 0 |
| `IN_BYTES < 20 × IN_PKTS` (IN_PKTS > 0) | 0 |
| `OUT_BYTES < 20 × OUT_PKTS` (OUT_PKTS > 0) | 0 |
| `IN_BYTES + OUT_BYTES < SHORTEST_FLOW_PKT × (IN_PKTS + OUT_PKTS)` | 0 |
| `IN_BYTES + OUT_BYTES > LONGEST_FLOW_PKT × (IN_PKTS + OUT_PKTS)` | 0 |
| rows with `IN_PKTS + OUT_PKTS == 0` | 0 |
| packet-size bins (`NUM_PKTS_*`) do not sum to `IN_PKTS + OUT_PKTS` | 1,122,754 (5.9%) |

The last row is a data-quality note on fields A4 does not use. One untested
possibility is that the bins stop at 1514 bytes and larger packets go
uncounted. It does not affect `IN_/OUT_BYTES` or `IN_/OUT_PKTS`.

## Disclosure

Before this inventory, the first ~1,500 bytes of the file were printed to
read the header (`head -c 1500`). That showed four complete data rows. All
four belong to NF-BoT-IoT-v2 or NF-ToN-IoT-v2, not the CIC subset. No CIC-subset
feature value was viewed.

## Step-0 conclusion

- **Not a stop condition.** NF-CSE-CIC-IDS2018-v2 is an identifiable subset
  (`Dataset` column). Hashes match the bag manifest, and the file has no
  missing or unparseable values.
- **Structural limits carried into the freeze:**
  1. The merged file's NF labels are coarse (6 attack categories).
     **Resolved (2026-09-27):** the standalone NF-CSE-CIC-IDS2018-v2 file
     carries all 14 fine labels (top of this document), and A4 is re-frozen at
     fine-label granularity.
  2. There is no timestamp and no capture/day identifier, so capture-matched
     benign cannot be reconstructed on the NF side. This holds for the
     standalone file too.
  3. There is no row-level correspondence between the representations.
