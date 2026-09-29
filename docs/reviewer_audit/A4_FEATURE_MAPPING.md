# A4 — Feature mapping: canonical CICFlowMeter vs. NF-CSE-CIC-IDS2018-v2 (Step 1)

**Status:** POST-HOC REVIEWER ROBUSTNESS AUDIT, pre-freeze. Documentation plus
label-blind structural checks only. No outcome was computed.

## Primary sources used (nothing else)

| Source | What it establishes |
|---|---|
| `NetFlow_v2_Features.csv` (shipped in the bag, SHA256 `f20e86a9…e939`) | One-line description per NF-v2 field, 43 fields |
| `results/audit/a4_representation/preflight_inventory.json` | Schema, label vocabulary, and label-blind invariant counts (`A4_DATA_PREFLIGHT.md`) |
| `results/audit/a4_representation/preflight_inventory_finegrained.json` (**added 2026-09-27**) | Fine label vocabulary of the standalone NF-CSE-CIC-IDS2018-v2 file. Its label-blind invariant counts are identical to the merged CIC subset's, so every structural argument below holds for it unchanged. Its `NetFlow_v2_Features.csv` is byte-identical to the merged bag's |
| `docs/reviewer_audit/A3_FEATURE_SEMANTICS_TABLE.md` / `A3_FEATURE_SEMANTICS_REPORT.md` | Canonical CICFlowMeter semantics, verified from `BasicFlow.java` in Phase I |
| `src/ingest/loader.py` | Canonical CICIDS column names |
| arXiv:2101.11315v2 (NF-v2 paper). **Added in the 2026-09-27 amendment**, and used only for the label mapping | Class tables and the label-merging procedure (see "Amendment", below) |

General NetFlow/nProbe knowledge was **not** used to fill any cell. Where
neither source above settles a point, the cell says UNVERIFIED.

## Key documentary evidence for NF direction

`NetFlow_v2_Features.csv` does not define `IN_BYTES` directionally. It says
only "Incoming number of bytes" and "Outgoing number of bytes". The same
document does, however, define the `IN`/`OUT` suffix explicitly for three
other field pairs:

- `RETRANSMITTED_IN_BYTES` / `_PKTS`: "(src->dst)". `RETRANSMITTED_OUT_BYTES` / `_PKTS`: "(dst->src)".
- `TCP_WIN_MAX_IN`: "(src->dst)". `TCP_WIN_MAX_OUT`: "(dst->src)".
- `DURATION_IN`: "Client to Server stream duration". (`DURATION_OUT` carries
  the same text, an evident copy error in the source document.)

The label-blind invariants agree with that convention. Over all 18,893,708 CIC
rows there are 0 violations of `RETRANSMITTED_IN_* ≤ IN_*` and 0 of
`RETRANSMITTED_OUT_* ≤ OUT_*`. This is consistency, not proof, because
retransmissions are zero on many rows.

## Key structural evidence for NF byte accounting

Over all CIC rows, label-blind (`A4_DATA_PREFLIGHT.md`):

- `IN_PKTS > 0` ⇔ `IN_BYTES > 0`, and `OUT_PKTS > 0` ⇔ `OUT_BYTES > 0`, with 0 exceptions.
- Every packet contributes at least 20 bytes: 0 rows with `X_BYTES < 20 × X_PKTS`.
- Total bytes always lie within [`SHORTEST_FLOW_PKT`, `LONGEST_FLOW_PKT`] × total packets, with 0 exceptions.

Payload-only accounting could not satisfy these relations. A header-only
packet, such as a bare ACK, would add a packet and zero bytes. **NF-v2 bytes
therefore count whole packets including at least the IP header.** Whether L2
framing is included is UNVERIFIED. (The 20-byte floor bounds the IP header only.)
Canonical CICFlowMeter bytes are **payload only** (A3, verified from
`BasicFlow.java`). The two byte fields therefore mean different things.

One consequence is fixed by construction and matters for Q3. In NF-v2, "reply
by bytes" and "reply by packets" are the same event (`OUT_BYTES > 0` ⇔
`OUT_PKTS > 0`). In canonical CICFlowMeter they differ for 10 of 14 labels
(A2).

## Mapping table

| Concept | Canonical CICFlowMeter | NF-CSE-CIC-IDS2018-v2 | Comparability |
|---|---|---|---|
| source endpoint | `Src IP`/`Src Port`. Source = sender of the first observed packet (`BasicFlow.firstPacket()`, A3). Canonical files do not all carry `Src IP` (`loader.py` `IP_COLUMNS`) | `IPV4_SRC_ADDR`/`L4_SRC_PORT` ("IPv4 source address"). The rule that picks which endpoint is "source" is not documented. The document equates the `IN` direction with both "src->dst" and "Client to Server", which implies src = client. How "client" is chosen is not documented | **UNVERIFIED** that NF "src" = CICFlowMeter's first-packet sender |
| destination endpoint | `Dst IP`/`Dst Port` | `IPV4_DST_ADDR`/`L4_DST_PORT` | same caveat, **UNVERIFIED** |
| forward direction | first-packet sender → receiver | src → dst (= `IN`, by the document's own suffix convention, above) | **APPROXIMATELY COMPARABLE**. Both are "record source → record destination". Whether the two tools pick the same endpoint as source is UNVERIFIED |
| backward direction | receiver → first-packet sender | dst → src (= `OUT`) | as above |
| forward bytes | `TotLen Fwd Pkts` → `totlen_fwd_pkts` | `IN_BYTES` | **DIFFERENT SEMANTICS** (byte accounting, next rows), same intended direction |
| backward bytes | `TotLen Bwd Pkts` → `totlen_bwd_pkts` | `OUT_BYTES` | **DIFFERENT SEMANTICS**, same intended direction |
| forward packets | `Tot Fwd Pkts` → `tot_fwd_pkts` (one per packet, A3) | `IN_PKTS` ("Incoming number of packets") | **APPROXIMATELY COMPARABLE**. Both are packet counts per direction. Flow boundaries differ (row counts differ per category), so per-flow values are not paired |
| backward packets | `Tot Bwd Pkts` → `tot_bwd_pkts` | `OUT_PKTS` | **APPROXIMATELY COMPARABLE** |
| byte accounting semantics | payload bytes only. Headers are separate (`Fwd/Bwd Header Len`). Verified in A3 | whole-packet bytes including at least the IP header (label-blind invariants, above). L2 inclusion UNVERIFIED | **DIFFERENT SEMANTICS**, verified |
| packet accounting semantics | every packet counted, including header-only ones | every packet counted (bytes > 0 ⇔ packets > 0) | **APPROXIMATELY COMPARABLE**. Flow timeout and segmentation rules for NF are UNVERIFIED |
| label | `Label` free text, 14 fine labels + `Benign` | Standalone file (primary): `Label` 0/1 plus `Attack`, the **same 14 fine label strings** + `Benign`. Merged file (retained, diagnostic only): 6 coarse categories + `Benign` | **SAME STRINGS, one to one** for the standalone file. Label *assignment* is the NF authors' own, on re-exported flows |
| attack category | none shipped. Derived below by frozen mapping | Merged file: `Attack` ∈ {Bot, Brute Force, DDoS, DoS, Infilteration, injection}. Standalone file: derived from the fine labels by the same frozen mapping | Used only for the secondary and diagnostic comparisons |
| source IP | `Src IP` (some files) | `IPV4_SRC_ADDR` (all rows) | **SAME SEMANTICS** as a field. Not used by A4 |
| destination IP | `Dst IP` | `IPV4_DST_ADDR` | **SAME SEMANTICS** as a field. Not used by A4 |
| timestamp | `Timestamp` (per flow). The capture file identifies the day | **absent** | **NOT AVAILABLE in NF**, so capture matching is impossible on the NF side |
| flow duration | `Flow Duration` (unit not re-verified in this audit) | `FLOW_DURATION_MILLISECONDS` (ms, per doc) | **UNVERIFIED** unit equivalence. Not used by A4 |

## Fine label mapping (canonical → standalone NF `Attack`). PRIMARY

Added 2026-09-27, before execution. Source:
`results/audit/a4_representation/preflight_inventory_finegrained.json`
(label counts only). The standalone NF-CSE-CIC-IDS2018-v2 file
(SHA256 `16a545a3…1257`) carries fine labels. **Every one of its 14 attack
strings is byte-identical to a canonical label string**, so the mapping is
the identity. There is no judgement in it and no pooling.

| canonical label = NF `Attack` | canonical rows | NF rows | well-supported (n ≥ 1,000 both sides) | coarse category (secondary/diagnostic only) |
|---|---|---|---|---|
| DDOS attack-HOIC | 668,461 | 1,080,858 | yes | DDoS |
| DDOS attack-LOIC-UDP | 1,730 | 2,112 | yes | DDoS |
| DDoS attacks-LOIC-HTTP | 576,191 | 307,300 | yes | DDoS |
| DoS attacks-Hulk | 434,873 | 432,648 | yes | DoS |
| DoS attacks-SlowHTTPTest | 19,462 | 14,116 | yes | DoS |
| DoS attacks-GoldenEye | 41,455 | 27,723 | yes | DoS |
| DoS attacks-Slowloris | 10,285 | 9,512 | yes | DoS |
| Bot | 282,310 | 143,097 | yes | Bot |
| Infilteration | 161,897 | 116,361 | yes | Infilteration |
| FTP-BruteForce | 39,352 | 25,933 | yes | Brute Force |
| SSH-Bruteforce | 117,322 | 94,979 | yes | Brute Force |
| Brute Force -Web | 611 | 2,143 | **no** (canonical 611) | Brute Force |
| Brute Force -XSS | 230 | 927 | **no** | Brute Force |
| SQL Injection | 87 | 432 | **no** | injection (excluded) |

Identical strings do not make identical rows. Every label's row count
differs, some by a factor of 2 or more, so flow segmentation and/or label
assignment differ per mechanism. Fine-label matching controls *which
mechanism* is compared. It does not pair flows, and it does not control the
benign reference (C2 in the freeze).

## Coarse label mapping (canonical → merged NF `Attack`). Superseded as primary; used for secondary and diagnostic only

The documents on disk do **not** state how NF-UQ-NIDS-v2 collapsed the
original CIC labels. The mapping below was first built from label-string
lineage. The NF-v2 paper, consulted in the amendment below, has since
confirmed it:

| NF `Attack` | canonical labels pooled into it | basis | status |
|---|---|---|---|
| DDoS | DDOS attack-HOIC, DDOS attack-LOIC-UDP, DDoS attacks-LOIC-HTTP | exactly the 3 canonical labels whose category token is DDoS/DDOS | APPROXIMATELY COMPARABLE (name-derived) |
| DoS | DoS attacks-Hulk, DoS attacks-SlowHTTPTest, DoS attacks-GoldenEye, DoS attacks-Slowloris | exactly the 4 canonical labels with prefix "DoS attacks-" | APPROXIMATELY COMPARABLE (name-derived) |
| Bot | Bot | identical string | APPROXIMATELY COMPARABLE |
| Infilteration | Infilteration | identical string, including CIC's own misspelling, which is strong evidence of direct derivation | APPROXIMATELY COMPARABLE |
| Brute Force | FTP-BruteForce, SSH-Bruteforce, Brute Force -Web, Brute Force -XSS | every canonical label carrying the "Brute Force"/"BruteForce"/"Bruteforce" token. The NF-v2 paper confirms this grouping (next section) | APPROXIMATELY COMPARABLE. Compositions differ (next section) |
| injection | SQL Injection (87 rows) | the NF-v2 paper states SQL Injection went into injection. The NF count (432) is about 5 times the canonical count | Excluded from comparison (see freeze) |

### Amendment 2026-09-27 (before execution): what the NF-v2 paper says

Source: Sarhan, Layeghy, Portmann, "Towards a Standard Feature Set for
Network Intrusion Detection System Datasets", arXiv:2101.11315v2
(15 May 2021), §3.2, Tables 6, 7 and 12. The PDF was read on 2026-09-27. The
same class table appears on `https://staff.itee.uq.edu.au/marius/NIDS_datasets/`.

- **§3.2, verbatim:** in NF-UQ-NIDS-v2, "Attacks named
  FTP-BruteForce, SSH-Bruteforce, Brute Force -Web and Brute Force -XSS have
  been combined as a brute-force category. Finally, SQL Injection attacks
  have been included in the injection attacks category." The DoS and DDoS
  renamings match the freeze's mapping. This settles the former UNVERIFIED
  Brute Force -XSS assignment and the injection composition, at the level of
  the authors' stated procedure.
- **Table 6 (NF-CSE-CIC-IDS2018-v2, standalone):** Benign 16,635,567;
  BruteForce 120,912; Bot 143,097; DoS 483,999; DDoS 1,390,270; Infiltration
  116,361; Web Attacks 3,502. The total is 18,893,708, which equals this
  repo's CIC-subset count exactly. Bot, DoS, DDoS and Infilteration also match
  the preflight exactly.
- **Table 7 (NF-UQ-NIDS-v2, merged):** Brute Force 123,982, matching the
  preflight. Injection 684,897 = NF-ToN-IoT-v2 injection 684,465 + **432**.
- **Arithmetic:** 120,912 + 3,502 = 124,414 = 123,982 + 432. The merge
  therefore moved 3,502 − 432 = **3,070** "Web Attacks" rows into Brute
  Force and 432 into injection. By §3.2 these are Brute Force -Web/-XSS and
  SQL Injection rows respectively. This is inferred from published counts
  and the stated procedure. It was not checked row by row.

**Web-attack share of the Brute Force pool, both sides:**

| side | web-attack rows in Brute Force | pool | share |
|---|---|---|---|
| canonical | 841 (Brute Force -Web 611 + -XSS 230) | 157,515 | 0.53% |
| NF (inferred, above) | 3,070 | 123,982 | **≈ 2.48%** |

The earlier "at most 0.15%" figure described the canonical side only, and
only Brute Force -XSS. It does not describe NF. NF's Brute Force carries
about 4.6 times canonical's web-attack share. That is a real compositional
asymmetry. The canonical AUCs of these two sub-labels (0.7598 and 0.4414,
`A_bytes`) lie inside the Brute Force envelope, so the freeze's envelope rule
already covers it. NF's SSH vs. FTP split inside the remaining 120,912 rows
is **not** published and remains unknown.

**Standalone, possibly finer-grained file.** NF-CSE-CIC-IDS2018-v2 is
published as its own file (Table 2: 2.80 GB CSV), separate from the merged
NF-UQ-NIDS-v2 that was downloaded. The download is at
`https://rdm.uq.edu.au/files/ce5161d0-ef9c-11ed-827d-e762de186848`. Its
published class table is coarse (7 classes). However, **Table 12 of the same
paper reports NF-CSE-CIC-IDS2018-v2 multi-class results for all 14 fine CIC
labels**, from DDoS attack-HOIC to SQL Injection. §3.2 also describes the
renaming as part of building the merged file. It is therefore plausible that
the standalone file, or some version of it, carries fine labels. This is
**UNVERIFIED**: the file was not downloaded, and the RDM page returned no
readable content. The freeze makes checking it a pre-execution gate
(`A4_REPRESENTATION_SENSITIVITY.md`, "Pre-execution gate"). If fine labels
are present, the coarse taxonomy is superseded before any outcome is
computed.

**Resolved 2026-09-27 (fine-grained re-freeze):** the standalone file was
downloaded. It passes the published row-count gate exactly and carries all 14
fine labels (see "Fine label mapping", above). The coarse taxonomy is
superseded as the primary comparison. The web-attack share figures above
remain the basis of the *diagnostic* raw coarse comparison only.

Row counts differ between the two sides for every category
(`A4_DATA_PREFLIGHT.md`). The NF labels are the NF authors' labels on
re-exported flows. They are not CICFlowMeter's labels transferred row by row.

## Critical question: is `A_bytes_NF` defensible?

**Yes, as a computable directional feature, with qualifications that the
freeze must carry:**

`A_bytes_NF = log1p(IN_BYTES) − log1p(OUT_BYTES)` and
`A_packets_NF = log1p(IN_PKTS) − log1p(OUT_PKTS)`.

- The directional fields exist. The dataset's own documentation, through its
  explicit IN = src→dst / OUT = dst→src convention on three sibling field
  pairs, orients them relative to the record's source and destination, and
  the label-blind invariants are consistent with that orientation. This is
  not a stop condition.
- **Byte accounting differs** from canonical: whole packets including headers,
  where canonical counts payload only. This is verified, not assumed, and it is
  part of what A4 measures. It is not a reason to stop.
- **Source-endpoint selection is UNVERIFIED.** If NF chooses "src" by a rule
  other than first packet, the forward direction itself can differ between
  the two representations. A4 therefore measures the effect of the
  representation *as a whole*: direction rule, byte accounting, flow
  segmentation and relabelling together. It cannot attribute a difference to
  any one of them.
- `A_packets_NF` is supported on the same basis. In NF, reply by packets and
  reply by bytes coincide exactly.

No substitute feature was introduced.
