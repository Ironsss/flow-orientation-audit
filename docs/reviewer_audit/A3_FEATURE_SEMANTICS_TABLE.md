# A3 — Feature semantics comparison: CICFlowMeter vs. Argus-UNSW vs. Argus-BoT-IoT

Documentation only. No code. Frozen question:
`docs/reviewer_audit/A3_EXPORTER_AND_LABEL_SEMANTICS.md`.

Every cell is either backed by a primary source actually opened for this
table, or marked `UNVERIFIED`. No cell is filled from general/remembered
knowledge of these tools.

## Primary sources actually used

| Source | What it is | Where |
|---|---|---|
| `NUSW-NB15_features.csv` | Official 49-feature description for UNSW-NB15, `No.,Name,Type,Description` | `docs/methodology/unsw/NUSW-NB15_features.csv` (repo), matches copy in `C:\Users\DavidG\Downloads\UNSW-NB15\` |
| `UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv` | BoT-IoT's own column-name header (names only, no descriptions) | `C:\Users\DavidG\Downloads\OneDrive_2026-09-23\Entire Dataset\` |
| `src/ingest/bot_iot.py` | This repo's BoT-IoT ingest adapter — `column_names()`, `to_canonical()` | repo |
| `src/ingest/unsw_nb15.py`, `src/ingest/loader.py` | This repo's UNSW / CICIDS ingest adapters | repo |
| `BasicFlow.java`, `ahlashkari/CICFlowMeter`, `master` branch | CICFlowMeter's own byte/packet accounting logic, downloaded and grepped directly (not summarized) | `https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java` |
| `The UNSW-NB15 description.pdf` | One-page dataset overview | `C:\Users\DavidG\Downloads\UNSW-NB15\` — checked, contains no field-level definitions (those live in `NUSW-NB15_features.csv` instead, used above) |

The task brief pointed at the description PDF for the `sbytes`/`dbytes` vs.
`sappbytes`/`dappbytes` distinction; that PDF turned out to be a one-page
dataset summary with no per-field text at all. The actual field
descriptions are in `NUSW-NB15_features.csv`, which is on disk in both the
downloads folder and the repo (`docs/methodology/unsw/`), and is what this
table actually cites.

## Comparison table

| Dimension | CICFlowMeter (CICIDS-2018) | Argus (UNSW-NB15) | Argus (BoT-IoT) |
|---|---|---|---|
| Forward/backward direction | Direction of the **first packet observed** for the flow (`BasicFlow.firstPacket()` sets the initial fwd/bwd assignment; confirmed by reading `BasicFlow.java` directly). | `src`/`dst` = the two endpoints as Argus's flow-record fields `srcip`/`dstip`; `sbytes`/`Spkts` = source-to-destination, `dbytes`/`Dpkts` = destination-to-source (`NUSW-NB15_features.csv` rows 1-4, 8-9, 17-18). Which endpoint Argus calls "source" for a given flow (first-packet vs. port-heuristic) is **UNVERIFIED** — not stated in `NUSW-NB15_features.csv` and no Argus manual is on disk. | Same field semantics as UNSW (`saddr`/`daddr`, `sbytes`/`dbytes`, `spkts`/`dpkts` — `src/ingest/bot_iot.py` `to_canonical()`). Same UNVERIFIED caveat on the source-selection rule; no BoT-IoT-specific text description exists (`Feature_Names.csv` has names only, no `Description` column). |
| Byte accounting: what does "bytes" include | **Payload bytes only.** `BasicFlow.java`: `forwardBytes`/`backwardBytes` accumulate `packet.getPayloadBytes()` on every packet (`firstPacket()`, `addPacket()`); L2/L3/L4 header bytes are accumulated **separately** into `fHeaderBytes`/`bHeaderBytes`, dumped as their own `Fwd Header Len`/`Bwd Header Len` columns. `TotLen Fwd/Bwd Pkts` = `fwdPktStats.getSum()`/`bwdPktStats.getSum()`, i.e. the sum of those same per-packet payload-byte values — confirmed by line-level source reading, not inferred. Caveat: this is the current `master` branch of the actively-maintained `ahlashkari/CICFlowMeter` fork; whether it is byte-for-byte the exact tool version that produced the 2018 CICIDS export is not independently confirmed, though payload/header separation is a structural design choice unlikely to differ across versions. | `sbytes`/`dbytes` = **"Source to destination transaction bytes"** / **"Destination to source transaction bytes"** (`NUSW-NB15_features.csv` rows 8-9, verbatim). "Transaction bytes" is Argus's own term for the field; whether it includes L2/L3/L4 headers or payload only is **UNVERIFIED** — the features CSV gives the field name and a one-line label, not a byte-accounting definition, and no Argus source/manual is on disk to check further. | Same field name (`sbytes`/`dbytes`), same tool (Argus), inherited by analogy from the UNSW description — but BoT-IoT's own `Feature_Names.csv` supplies no description text at all, so even the "transaction bytes" label is not independently confirmed for BoT-IoT specifically, only for UNSW-NB15. Marked **UNVERIFIED** for BoT-IoT on that basis. |
| Application-layer bytes (`sappbytes`/`dappbytes`) present? | **N/A — no such distinction exists in CICFlowMeter's output at all.** There is exactly one byte-total per direction (`TotLen Fwd/Bwd Pkts`); headers are the only thing split out separately, not payload vs. application data. | **No.** `sappbytes`/`dappbytes` do **not** appear anywhere in the official 49-field list (`NUSW-NB15_features.csv`, all 49 rows read) or in `src/ingest/unsw_nb15.py`'s `RAW_COLUMNS`. Argus generically supports such fields in other configurations, but UNSW-NB15's actual export does not carry them — checked directly, not assumed. | **No.** BoT-IoT's `UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv` (34 columns, read directly off disk) has no `sappbytes`/`dappbytes` field either — only `sbytes`/`dbytes`. `src/ingest/bot_iot.py::column_names()` returns exactly that 34-column list, confirming the adapter isn't silently dropping a field the raw file has. |
| Packet-count fields | `Tot Fwd Pkts`/`Tot Bwd Pkts` = per-direction packet counts (`fwdPktStats.getN()`/`bwdPktStats.getN()`, one increment per packet regardless of payload size). | `Spkts`/`Dpkts` = "Source to destination packet count" / "Destination to source packet count" (`NUSW-NB15_features.csv` rows 17-18). | `spkts`/`dpkts`, same Argus convention, no separate text description on disk for BoT-IoT (name-only header). |
| Source/destination IP available | Present in some CICIDS-2018 CSV variants only (`Src IP`/`Dst IP` in `src/ingest/loader.py`'s `IP_COLUMNS`, commented as not present in every file) — **not guaranteed per file.** | Yes, always: `srcip`/`dstip` (`RAW_COLUMNS` position 1, 3; `NUSW-NB15_features.csv` rows 1, 3). | Yes, always: `saddr`/`daddr` (`Feature_Names.csv`; `to_canonical()`). |
| Label granularity in the raw export | Single free-text `Label` column, one string per flow (e.g. `DoS attacks-Hulk`, `DDOS attack-HOIC`) — see `A3_FEATURE_SEMANTICS_REPORT.md` for the per-label breakdown. | Two-level: `attack_cat` (9 families) is the only category column in the 49-field export; there is no finer per-technique field in `NUSW-NB15_features.csv`. | Two-level: `category`/`subcategory` raw strings, collapsed by this repo into the frozen `GROUP_MAP` in `src/ingest/bot_iot.py` (e.g. `("DDoS","TCP")` -> `"DDoS/TCP"`). |

## UNVERIFIED cells, summarized

1. Argus's source/destination assignment rule (first-packet vs. some other
   heuristic) for both UNSW-NB15 and BoT-IoT.
2. Whether Argus's "transaction bytes" (`sbytes`/`dbytes`) include L2/L3/L4
   headers — no Argus manual/source was available on disk to check.
3. Whether "transaction bytes" is the correct label for BoT-IoT's `sbytes`/
   `dbytes` specifically (verified for UNSW-NB15 via its own features CSV;
   inferred, not confirmed, for BoT-IoT, which ships no field descriptions
   at all).

None of these are guessed in the table above — each is stated as
UNVERIFIED with the reason no primary source on disk resolved it.
