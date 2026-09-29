# BoT-IoT external validation of H3 -- pre-data freeze

**Status: FROZEN BEFORE THE DATA EXISTS ON THIS MACHINE.** No BoT-IoT file
has been downloaded, opened, or summarized by this project. Every fact below
comes from first-party documentation:

- the official page (research.unsw.edu.au/projects/bot-iot-dataset);
- the dataset paper: Koroniotis, Moustafa, Sitnikova, Turnbull, "Towards the
  Development of Realistic Botnet Dataset in the Internet of Things for
  Network Forensic Analytics: Bot-IoT Dataset", FGCS 100 (2019) 779-796,
  arXiv:1811.00701v1. The PDF read has SHA256
  `d6e448ed19da48c6852d1d9c01af8e99d418be93d591a9efd196cb21c69dc079`.

This is a stronger position than the UNSW freeze, which was written after a
blind preflight of files already on disk. Phase 0 (SS9) will be appended
after download. It may only add structural facts and map observed label
strings onto the groups fixed here. It may not change SS3-SS8.

**Date:** 2026-09-22. **Commit at freeze time:** parent `960d70f`.

## 1. Why BoT-IoT, and what is already known

- CICIDS-2018 (discovery): the sign of per-flow asymmetry appeared to depend
  on the attack mechanism. HTTP floods were strongly inverted (Hulk 0.023,
  HOIC/LOIC-UDP 0.003, LOIC-HTTP 0.381), while Bot (0.838) and Brute
  Force (0.63-0.69) were positive.
- UNSW-NB15 (first confirmatory test, `docs/methodology/UNSW_H3_FINDINGS.md`):
  **NO REPLICATION.** All nine families were positive (0.68-0.89). A POST-HOC
  look found that most UNSW attack flows receive no reply (`dbytes == 0`),
  and that UNSW labels only attacker-initiated flows.
- BoT-IoT is the second independent test. It was proposed as a *mechanism
  stress test* (flooding vs. scanning vs. theft). It is also the first
  unseen dataset on which the UNSW-derived environment reading (SS6.2) can
  be tested prospectively.

**H3 is not amended after the UNSW failure** (protocol SS17). It is re-tested
verbatim, with the same features, metric, thresholds, and decision rule. A
BoT-IoT pass would not undo the UNSW failure. Both results are reported.

## 2. Dataset facts from documentation (to be verified in Phase 0)

**Column semantics (paper Table 2):**
- `saddr`/`daddr`: source/destination IP address. `sport`/`dport`: ports.
- `sbytes`: "Source-to-destination byte count". `dbytes`:
  "Destination-to-source byte count".
- `spkts`: "Source-to-destination packet count". `dpkts`:
  "Destination-to-source packet count".
- `attack`: "0 for Normal traffic, 1 for Attack Traffic". `category`,
  `subcategory`: traffic category and subcategory.
- The flow exporter is Argus, as in UNSW-NB15. Source is the endpoint that
  sent the flow's first observed packet.

**Hosts (paper Fig. 1, §3.2):**
- Attackers: Bot Kali_1..4 = 192.168.100.150, .149, .148, .147.
- Targets: Ubuntu Server 192.168.100.3, Ubuntu Mobile .5, Windows 7 .6,
  Metasploitable .7.
- Tap: .4. Gateway/pfSense: .1.

**Labeling (paper §4.1-4.2):** "update queries to modify the values based on
saddr and daddr values". Labels were assigned by attacker/victim **host
pair**, not by which side initiated the flow. The paper adds that "between
the two groups, only attacking traffic would be transferred". Consequence:
unlike UNSW, attack-labeled flows may have the victim as source (the data
theft scenario uses a *reverse* meterpreter connection, §5.2). The role
check (SS5) is therefore substantive here.

**Composition (paper Tables 4-5, full dataset):**

| Group | Tool | Records |
|---|---|--:|
| Normal | Ostinato + Node-red MQTT | 9,543 |
| Reconnaissance / Service scanning | nmap, hping3 | 1,463,364 |
| Reconnaissance / OS fingerprinting | nmap, xprobe2 | 358,275 |
| DDoS / TCP | hping3 `--syn --flood` | 19,547,603 |
| DDoS / UDP | hping3 `--flood` | 18,965,106 |
| DDoS / HTTP | GoldenEye | 19,771 |
| DoS / TCP | hping3 `--syn --flood` | 12,315,997 |
| DoS / UDP | hping3 `--flood` | 20,659,491 |
| DoS / HTTP | GoldenEye | 29,706 |
| Theft / Keylogging | Metasploit, Hydra | 1,469 |
| Theft / Data theft | Metasploit (reverse meterpreter) | 118 |

Normal and attack traffic were generated concurrently in the same captures
(§4.1: attacks ran "while simultaneously normal traffic was generated in the
background"). This satisfies control C2 (same run) by design. Phase 0
checks it structurally (SS9).

**Known limitation, recorded before seeing data:** Normal is 9,543 flows,
0.013% of the dataset. It is packet-generator traffic, 76% UDP by the
paper's Table 4. Every AUC here is "attack group vs. a small synthetic
background", not vs. realistic benign traffic. CIs will be dominated by
Normal sampling variance.

## 3. Hypotheses (verbatim from the UNSW freeze)

**H3 -- mechanism-dependent directional asymmetry.** Directional flow
asymmetry is not universally oriented across malicious traffic; its sign and
discriminative magnitude vary by attack mechanism.

**H3b -- separability independent of orientation.**
`AUC_sep = max(AUC_signed, 1 - AUC_signed)`.

## 4. Data handling

- **Population: the full CSV release** ("Entire Dataset", ~16.7 GB, 72M+
  records), not the 5% extract (reportedly ~477 Normal rows; unverified). Fallback
  only if the full release cannot be obtained: the 5% extract, with every
  output labeled `population=5pct_extract`. The verdict stands, with the
  reduced power stated.
- Only the needed columns are read: `saddr, daddr, sbytes, dbytes, spkts,
  dpkts, attack, category, subcategory`, plus `stime` for the C2 check.
- Benign = `attack == 0`. Attack group = `attack == 1` with the
  (category, subcategory) pair mapped to the ten groups of SS2. Label strings
  are trimmed. The Phase 0 mapping must be one-to-one onto those ten groups.
  Any unmapped attack string is reported and excluded, never merged by
  judgment.
- **Primary: all rows as released.** Pre-registered sensitivity: exact
  duplicates removed across all raw columns except `pkSeqID` (a row
  counter, unique by construction). The verdict comes from the primary.
- No other filtering, no subsampling of the analyzed population.

## 5. Analysis (identical to UNSW FREEZE SS7 unless stated)

- **Features:** `A_bytes = log(1+sbytes) - log(1+dbytes)` (primary),
  `A_packets = log(1+spkts) - log(1+dpkts)` (secondary). No sign flip
  conditioned on results.
- **Control C1 (size-only arm), new here** (`CLAUDE.md` mistake #1; it was
  missing from the UNSW run): `S_bytes = log(1+sbytes+dbytes)`, with AUC and
  CI per group. It is reported beside `A_bytes` so that direction can be
  told apart from volume. It does not enter the verdict.
- **Groups (primary unit): the ten (category, subcategory) groups of SS2**,
  in that fixed order. These are the mechanism-level units the dataset
  itself defines (tool and protocol differ between them). Category-level
  AUCs (DDoS, DoS, Reconnaissance, Theft) and all-attacks vs. Normal are
  reported, labeled descriptive.
- **Metric:** `AUC_signed` (attack = positive class, ties count 1/2,
  identical to `roc_auc_score`), `AUC_sep`, `Delta = AUC_signed - 0.5`.
  Median, IQR, p10/p25/p75/p90 per group and benign. Bootstrap CI of the
  median difference.
- **Bootstrap:** stratified 95% percentile, **B = 2000, seed = 20260922**.
  Resampling with replacement may be implemented as a multinomial draw over
  each class's distinct-value counts. That is distributionally identical,
  and it is required at 73M rows.
- **Role check:** attacker set = {192.168.100.147, .148, .149, .150} (paper
  Fig. 1). Per group, report `src_is_attacker`, `dst_is_attacker`, and
  `resolved`. `A_bytes_attack_oriented` uses `A_raw` if the source is an
  attacker, `-A_raw` if only the destination is, and excludes the row
  otherwise. Benign rows keep `A_raw`. It is computed for a group only if
  >= 90% of its rows resolve.
- **Orientation labels:** `positive` if `Delta >= 0.05`, `negative` if
  `Delta <= -0.05`, `near-neutral` otherwise. **Confidently oriented** means
  labeled positive or negative AND the 95% CI lies entirely on that side of
  0.5.
- **Code reuse, to guarantee an identical rule:** `orientation`,
  `confident`, `criterion`, and `auc_lookup`/`auc_from_codes` are imported
  unchanged from `scripts/run_unsw_external_validation.py` at `960d70f`.
  The new work is a BoT-IoT adapter (`src/ingest/bot_iot.py`) and a runner
  (`scripts/run_botiot_h3.py`). The UNSW script is not modified.

## 6. Decision rules

### 6.1 H3 verdict (identical rule to UNSW SS7.6, over the ten groups)

- **H3 consistent** (on `A_bytes`, primary) iff there exist a confidently
  positive group and a confidently negative group that both have
  `src_is_attacker >= 0.90`.
  - Opposite confident orientations exist but no pair meets the role
    condition: **INCONCLUSIVE (ROLE)**.
- **STRONG REPLICATION:** consistent on `A_bytes` AND on `A_packets`.
  **PARTIAL:** `A_bytes` only. **NO REPLICATION:** the `A_bytes` criterion
  is not met.
- The dedup run is reported beside the primary; disagreement is reported,
  not resolved.

### 6.2 Secondary directional predictions (not part of the verdict)

The two readings disagree on hping3 floods, which make up most of BoT-IoT.
That disagreement is what this dataset can discriminate.

| Group | H3-dir (CICIDS mechanism reading) | H3-env (UNSW post-hoc environment reading) |
|---|---|---|
| DDoS/HTTP, DoS/HTTP (GoldenEye) | **negative** (request flood; the server answers, as with Hulk/HOIC) | **negative** (the server answers) |
| DDoS/TCP, DoS/TCP, DDoS/UDP, DoS/UDP (hping3 `--flood`) | **negative** (floods invert) | **positive** (fire-and-forget; no reply awaited) |
| Theft/Keylogging | **positive** (active credential attack, like Brute Force/Bot) | no prediction |
| Reconnaissance, Theft/Data theft | no prediction | no prediction |

Each prediction is scored per group from its orientation label and whether
it is confident. H3-env was generated from UNSW-NB15 after that dataset's
verdict. This is its first prospective test. If it fails here, it is
dropped, not re-derived.

## 7. What would make us abandon each claim

- **H3:** NO REPLICATION here, after UNSW's, means the mechanism-dependent
  sign has failed on both independent datasets. The paper then reports it
  as a CICIDS-specific observation, and H3 is closed.
- **H3-env:** hping3 floods confidently negative.
- **H3-dir:** GoldenEye HTTP floods confidently positive.
- **The instrument:** Phase 0 cannot map groups one-to-one, or the role
  check shows attacker IPs absent from attack-labeled rows. Either one means
  a structural blocker, reported as such, with no verdict.

## 8. Outputs

`results/botiot/{preflight.json, asymmetry_by_attack.csv,
asymmetry_bootstrap.csv, asymmetry_distributions.csv, verdict.json,
run_metadata.json}` and `results/figures/botiot_{signed_auc,
separability_auc, asymmetry_distributions}.pdf`. Anything not listed in
SS4-SS6 is labeled **POST-HOC / EXPLORATORY**.

## 9. Phase 0 -- blind preflight (appended 2026-09-23)

Allowed: file names, sizes, SHA256, row counts, header/feature-name file,
column types, nulls, duplicates, distinct `category`/`subcategory` strings
and their counts, the string-to-group mapping, the attacker-IP presence
check, and the `stime` range per group (C2).

Prohibited: any statistic of `sbytes/dbytes/spkts/dpkts` or of anything
derived from them, split by label.

Download from the official page (SharePoint): the full CSV folder, the
feature-names file shipped with it, and, if present, any ground-truth or
readme files. Place them at `C:\Users\DavidG\Downloads\BoT-IoT`, outside the
repository.

### 9.1 Results (`scripts/botiot_preflight.py`, pushed at `7c52913` before its run; output `results/botiot/preflight.json`)

Everything below is structural. No statistic of any directional counter, or
of the totals and rates derived from them, was computed split by label.

**Files.** Downloaded 2026-09-22 from the official SharePoint folder "Entire
Dataset". Location: `C:\Users\DavidG\Downloads\OneDrive_2026-09-23\Entire Dataset`
(deviation from the path in SS9: operational only). The folder holds 74 data
files `UNSW_2018_IoT_Botnet_Dataset_{1..74}.csv`, 16,707,644,164 bytes, plus
`UNSW_2018_IoT_Botnet_Dataset_Feature_Names.csv` (SHA256
`0c7516e0fb425ba0d245d4420e2b2e7adf381caa94de304f940d64d952b359aa`). No
ground-truth or readme file is included. Per-file SHA256 values are in
`preflight.json`. Manifest hash (SHA256 of the 74 per-file hashes
concatenated in file-number order):
`7cbdad77548d146d550f0ddd172606ed73152fb914743055cfe5c70c297733a7`.

**Format.** The files have no header and 35 fields per row, named by the
feature-names file. String fields are double-quoted. The paper's Table 2
lists 32 features; the release adds `smac, dmac, soui, doui, sco, dco`,
which are **empty in all 73,370,443 rows**. They are irrelevant to H3.

**Rows.** 73,370,443 in total (1,000,000 per file; file 74 has 370,443).
That is **9,543 Normal + 73,360,900 attack, exactly matching the paper's
Tables 4-5.** `pkSeqID` is unique across all rows.

**Label vocabulary and mapping to the SS2 groups (one-to-one, nothing
unmapped).** `attack == 0` occurs exactly for `Normal/Normal`, and
`attack == 1` for everything else.

| `category` / `subcategory` (raw) | SS2 group | rows |
|---|---|--:|
| `Normal` / `Normal` | Normal | 9,543 |
| `Reconnaissance` / `Service_Scan` | Reconnaissance / Service scanning | 1,463,364 |
| `Reconnaissance` / `OS_Fingerprint` | Reconnaissance / OS fingerprinting | 358,275 |
| `DDoS` / `TCP` | DDoS / TCP | 19,547,603 |
| `DDoS` / `UDP` | DDoS / UDP | 18,965,106 |
| `DDoS` / `HTTP` | DDoS / HTTP | 19,771 |
| `DoS` / `TCP` | DoS / TCP | 12,315,997 |
| `DoS` / `UDP` | DoS / UDP | 20,659,491 |
| `DoS` / `HTTP` | DoS / HTTP | 29,706 |
| `Theft` / `Keylogging` | Theft / Keylogging | 1,469 |
| `Theft` / `Data_Exfiltration` | Theft / Data theft | 118 |

Every count equals the paper's Table 5.

**Column semantics, structurally confirmed (all rows, label-free).**
`spkts + dpkts == pkts` and `sbytes + dbytes == bytes` hold in
73,370,443 / 73,370,443 rows. The s/d columns are therefore an exact
directional split of the flow totals. Which side is "source" rests on the
paper's Table 2 and on Argus convention; it cannot be verified further
without PCAPs.

**Types and nulls.** Every numeric column casts cleanly, with 0
non-numeric values, including all four directional counters. `sport` and
`dport` are empty in 2,833 rows (ARP) and non-decimal in about 32.3k rows
(`0x` hex and `xinetd`). Ports are not used by H3.

**Duplicates: 0** exact duplicates across all columns except `pkSeqID`
(64-bit row hash; 73,370,443 distinct). **Consequence: the SS4 dedup
sensitivity population is identical to the primary.** It will still be
run and reported as such, not skipped.

**Attacker-IP presence (instrument check, SS7).** 73,360,900 of 73,360,900
attack rows (100%) have `saddr` or `daddr` in {192.168.100.147-.150}. No
blocker. Per-group `src_is_attacker` is **not** computed here: it is part
of the SS6.1 verdict rule and is left to the run.

**C2 (concurrency).** Normal rows occur on every day that has attacks
(2018-05-15: 1,142; 05-21: 2,736; 05-22: 2,804; 06-04: 2,673; 06-18: 24;
06-19: 164). Each attack group's time window contains concurrent Normal
rows:

| group | window | Normal rows inside window |
|---|--:|--:|
| DDoS / HTTP | 21.0 min | 27 |
| DDoS / TCP | 38.6 min | 624 |
| DDoS / UDP | 42.0 min | 607 |
| DoS / HTTP | 25.9 min | 39 |
| DoS / TCP | 42.3 min | 586 |
| DoS / UDP | 42.0 min | 671 |
| Recon / OS fingerprinting | 1,788.5 min | 5,477 |
| Recon / Service scanning | 10,389.0 min | 5,707 |
| Theft / Data theft | 18.3 min | 16 |
| Theft / Keylogging | 18.2 min | 157 |

C2 is satisfied at the capture level. As frozen in SS5, each group is
compared against **all** 9,543 Normal rows, not only the concurrent ones.
The within-window Normal counts (16-671 for the short attacks) would be
too small for a within-window comparison. This is recorded as a
limitation, not turned into an additional analysis.

**Gate: PASS.** Groups map one-to-one, the attacker hosts are present, and
the column semantics are structurally consistent. SS3-SS8 are unchanged.
Next: `src/ingest/bot_iot.py` + `scripts/run_botiot_h3.py`, pushed before
their first run.
