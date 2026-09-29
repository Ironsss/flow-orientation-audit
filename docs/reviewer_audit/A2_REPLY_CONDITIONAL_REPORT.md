# A2 — Reply-conditional decomposition: report (2026-09-27)

## Question

`A_bytes = log1p(fwd_bytes) - log1p(bwd_bytes)`. When `bwd_bytes == 0`
(no reply), `A_bytes = log1p(fwd_bytes) > 0` for any nonzero forward
traffic, by construction. "Attack flows tend to have positive `A_bytes`"
can therefore be partly definitional (a proxy for "attack flows tend not
to get a reply") rather than a real directional-magnitude finding. This
audit computes, per dataset and per attack group/label: the reply rate,
and the counting-AUC of `A_bytes`/`A_packets` split into all-flows /
answered-only / unanswered-only slices, to see how much of the observed
AUC survives once reply presence is held fixed.

## Threat to validity

A per-flow directional-asymmetry feature that is mechanically determined
by a binary "did the other side ever respond" indicator would overstate
the case for *magnitude* asymmetry as a mechanism signature — the paper's
central claim depends on magnitude, not just presence/absence of a reply.

## Analysis frozen before execution

`docs/reviewer_audit/A2_REPLY_CONDITIONAL.md`, frozen 2026-09-27, before
this task's code was written or run. Its frozen interpretation buckets
(persists / collapses / flips, defined per group against the group's own
all-flows AUC) are used below, not amended after seeing the numbers.

`docs/reviewer_audit/AUDIT_MASTER_PLAN.md`'s pre-committed A1 x A2
interpretation matrix is also applied to BoT-IoT, where A1
(`docs/reviewer_audit/A1_BOT_DEPENDENCE_REPORT.md`) already classified
dependence-robustness per group.

## Data used

- UNSW-NB15: `C:\Users\DavidG\Downloads\UNSW-NB15`, via
  `src/ingest/unsw_nb15.py:load_unsw(dedup=False)` — same population as the
  confirmatory H3 UNSW run.
- BoT-IoT: full "Entire Dataset" release (74 CSVs, ~73M rows) via
  `src/ingest/bot_iot.py:load_botiot`, from
  `C:\Users\DavidG\Downloads\OneDrive_2026-09-23\Entire Dataset` — same
  canonical frame the confirmatory H3 BoT-IoT run and A1 used.
- CICIDS-2018: the 10 CSVs in `data/raw/` (repo-root `data/raw`, gitignored;
  this task's worktree copy of `data/raw` was empty, so the run pointed
  `--data-dir` directly at `C:\Users\DavidG\iag-symmetry\data\raw` in the
  main checkout — no files were copied or downloaded), via
  `src/ingest/loader.py:load_directory`.

No new data was downloaded. No file under `results/unsw/` or
`results/botiot/` was read for its confirmatory numbers except the
already-published `A_bytes` AUCs used below only as a cross-check that this
task's own "all-flows" numbers reproduce them (see Method, step 3).

## Code commit

Task 1 (freeze) push: `22a325a7e1b4b5c33315a40765a9379a925b53e6` — "Freeze
reviewer robustness audit A1-A3 plans before writing analysis code."

This task's own code (`scripts/audit_a2_reply_conditional.py`,
`tests/test_audit_a2_reply_conditional.py`) is committed separately, see
the commit that accompanies this report.

## Method

1. For each dataset, load the canonical frame (UNSW/BoT-IoT) or the raw
   CICFlowMeter frame (CICIDS) and compute `A_bytes = log1p(fwd_bytes) -
   log1p(bwd_bytes)`, `A_packets = log1p(fwd_packets) - log1p(bwd_packets)`,
   `reply_bytes = bwd_bytes > 0`, `reply_packets = bwd_packets > 0`.
2. For each attack group (UNSW `attack_category`, BoT-IoT frozen
   `attack_category` group, CICIDS raw stripped `label`), compute the four
   reply rates (`P(reply | attack)`, `P(reply | benign)`, separately for
   bytes and packets) and, for each feature, the counting-AUC
   (`scripts/audit_a2_reply_conditional.py:counting_auc`, which reuses
   `run_unsw_external_validation.py`'s `auc_lookup`/`auc_from_codes` —
   the same engine used everywhere else in this repo, asserted equal to
   `sklearn.roc_auc_score` in
   `tests/test_audit_a2_reply_conditional.py::test_counting_auc_matches_sklearn`)
   on three slices: all flows, answered-only (`reply` true on both the
   attack and benign side), unanswered-only.
3. **Reproduction cross-check (informal, not part of the frozen output):**
   this task's own "all-flows A_bytes" numbers for BoT-IoT match the
   already-published `flow_auc_signed` column in
   `results/audit/a1_bot_dependence/comparison.csv` / the
   `A1_BOT_DEPENDENCE_REPORT.md` table to 3 decimal places for every one of
   the 8 verifiable groups (e.g. DDoS/TCP 0.703, DDoS/UDP 0.785, DoS/UDP
   0.789) — confirming the independently-written loading/feature code in
   this task's script agrees with the existing confirmatory pipeline before
   trusting its answered/unanswered breakdown.
4. Write `results/audit/a2_reply/{reply_rates,auc_by_slice}.csv`, one run
   per `--dataset`, each run replacing only its own dataset's rows via
   `pl.concat([existing.filter(dataset != this), new])` — verified across
   three sequential runs (unsw -> botiot -> cicids): row counts grew
   9 -> 19 -> 34 (`reply_rates.csv`) and 54 -> 114 -> 204
   (`auc_by_slice.csv`), with every earlier dataset's rows still present
   and unchanged after each subsequent run.

No transcription bugs were found in the brief's code for this task (unlike
Task 2, which found two). The one implementation detail worth flagging:
`np.ones_like(benign)` on a boolean array returns an all-`True` boolean
array (not integer `1`), which is what the "all" slice selector needs —
confirmed directly rather than assumed, since it is easy to misread.

### Diagnostic follow-up (not in the original frozen plan, done to explain
an otherwise-alarming pattern in the raw output)

Several unrelated CICIDS attack labels (`DDOS attack-HOIC`, `DoS
attacks-Hulk`, `DoS attacks-SlowHTTPTest`, `FTP-BruteForce`, `SQL
Injection`, `SSH-Bruteforce`) show the *exact same* `unanswered`-slice
`A_bytes` AUC value (`0.382705618912485`) despite wildly different `n`
(from 39 to 668,461). Before reporting this as a finding, a small ad hoc
diagnostic (not committed, not part of the audit's frozen output) checked
whether this was a script bug: for all six labels, 100% of unanswered
attack rows have `fwd_bytes == totlen_fwd_pkts == 0` as well as
`bwd_bytes == 0`, so `A_bytes` is the exact constant `0` on the attack side
for every one of those rows. A counting-AUC of a single repeated attack
value against a *shared* benign-unanswered population (4,076,376 rows,
identical across every CICIDS group since it's defined dataset-wide) is a
deterministic function of where that one value falls in the benign
distribution — hence the identical AUC regardless of which label or how
many attack rows share it. This is a genuine, confirmed data
characteristic (many CICFlowMeter-recorded attack flows in these
categories carry zero bytes in *either* direction), not a bug in
`counting_auc` or in the group/slice indexing. It is reported below as a
finding, not silently discarded.

## Results

Classification below reuses this repo's own existing near-neutral
convention (`run_unsw_external_validation.py`'s `NEUTRAL = 0.05`,
`orientation()`): "positive" if `AUC - 0.5 >= 0.05`, "negative" if
`<= -0.05`, "near-neutral" otherwise. **No bootstrap CI was computed for
this task** (the frozen A2 plan asks for point AUCs on three slices, not
a resampling CI) — see Limitations. "Persists" = answered-only AUC stays
on the same side of 0.5, outside the near-neutral band. "Collapses" =
answered-only AUC falls into the near-neutral band. "Flips" = answered-
only AUC crosses to the opposite side, outside the band. A fourth pattern shows up in the data that the frozen plan does not
name: an all-flows AUC already inside the near-neutral band whose
answered-only AUC moves outside it. Labeled "emerges" below and reported
as its own finding, the same way the frozen plan explicitly allows a sign
flip to be reported as its own finding rather than forced into a bucket.
Every AUC is
reported with its own `n_attack`/`n_benign`; a slice with a small or zero
`n_attack` is flagged explicitly rather than classified as if it were
reliable, per the frozen plan's own instruction (the UNSW Generic
~2%-answered example it names, and several BoT-IoT/CICIDS analogues found
here).

### UNSW-NB15 (9 attack categories; `n_benign` = 2,218,764 throughout)

| group | reply rate (attack, bytes) | AUC all (bytes) | AUC answered (bytes) [n_attack] | class (bytes) | AUC answered (packets) [n_attack] | class (packets) |
|---|---|---|---|---|---|---|
| Analysis | 0.235 | 0.796 | 0.506 [630] | **collapses** | 0.842 [630] | persists |
| Backdoors | 0.166 | 0.865 | 0.729 [386] | persists | 0.819 [386] | persists |
| DoS | 0.223 | 0.841 | 0.678 [3,646] | persists | 0.798 [3,646] | persists |
| Exploits | 0.631 | 0.679 | 0.608 [28,102] | persists | 0.686 [28,102] | persists |
| Fuzzers | 0.639 | 0.843 | 0.883 [15,503] | persists (strengthens) | 0.935 [15,503] | persists |
| **Generic** | **0.015** | 0.891 | 0.561 [3,247] | **persists** (weak: near-empty, 1.5% of 215,481 attack rows -- not treated as confident) | 0.614 [3,247] | weak/borderline (near-empty) |
| Reconnaissance | 0.502 | 0.829 | 0.848 [7,017] | persists | 0.916 [7,017] | persists |
| Shellcode | 0.496 | 0.878 | 0.909 [750] | persists | 0.949 [750] | persists |
| Worms | 0.879 | 0.709 | 0.754 [153] | persists | 0.776 [153] | persists |

**One of nine UNSW categories collapses for `A_bytes`: Analysis.**
Generic drops sharply (0.891 -> 0.561) but its answered-only AUC stays
just outside the frozen ±0.05 near-neutral band (0.561, 0.061 from 0.5) --
by the frozen "collapses toward 0.5" bucket's operational definition used
throughout this audit (falls inside the band), Generic **persists**, it
does not collapse. It should still not be treated as a confident, robust
positive result given how unrepresentative that 1.5% slice is of the
group's 215,481 flows (~2% answered, `n_attack` = 3,247 of 215,481,
exactly the case the frozen plan names by name) -- that is a separate,
sample-composition caveat on the persist classification, not grounds to
reclassify the point estimate as a collapse. Analysis collapses on a larger relative
answered fraction (23.5%, n=630) and its answered AUC (0.506) is
essentially exactly chance — a clean collapse, not a small-sample
artifact. The other seven groups persist for `A_bytes`, several (Fuzzers,
Shellcode, Reconnaissance) *strengthening* on the answered-only slice.
`A_packets` persists for every group including Analysis (0.842) — the two
features disagree specifically for Analysis: its `A_bytes` collapse does
not extend to `A_packets`.

### BoT-IoT (10 attack groups; `n_benign` = 9,543 throughout)

| group | reply rate (attack, bytes) | AUC all (bytes) | AUC answered (bytes) [n_attack] | class (bytes) | AUC answered (packets) [n_attack] | class (packets) |
|---|---|---|---|---|---|---|
| DDoS/HTTP | 0.9999 | 0.320 | 0.676 [19,769] | **flips** | 0.966 [19,769] | emerges (all-packets 0.460 is near-neutral) |
| DDoS/TCP | 0.261 | 0.703 | 0.953 [5,103,403] | persists (strengthens) | 0.985 [5,103,403] | persists |
| DDoS/UDP | **0.0000214** | 0.785 | 0.780 [406] (answered slice unusable: 0.002% of 18,965,106 attack rows) | **persists, weakened** — tested on the unanswered-only slice: 0.592 [18,964,700 attack / 5,029 benign] | unanswered-only 0.640 [18,964,700] | persists, weakened (all 0.810) |
| DoS/HTTP | 0.9999 | 0.340 | 0.719 [29,704] | **flips** | 0.957 [29,704] | emerges (all-packets 0.456 is near-neutral) |
| DoS/TCP | 0.500 | 0.628 | 0.938 [6,152,453] | persists (strengthens) | 0.992 [6,152,453] | persists |
| DoS/UDP | **0.0000260** | 0.789 | 0.775 [537] (answered slice unusable: 0.0026% of 20,659,491 attack rows) | **persists, weakened** — tested on the unanswered-only slice: 0.600 [20,658,954 attack / 5,029 benign] | unanswered-only 0.639 [20,658,954] | persists, weakened (all 0.810) |
| Recon/OS fingerprint | 0.965 | 0.355 | 0.738 [345,635] | **flips** | 0.497 [345,635] | collapses (near-exact 0.5) |
| Recon/Service scan | 0.942 | 0.360 | 0.745 [1,378,580] | **flips** | 0.499 [1,378,580] | collapses (near-exact 0.5) |
| Theft/Data theft | 1.000 | 0.283 | 0.585 [118] | flips (benign-reference mechanism, see below) | 0.171 [118] | persists (negative) |
| Theft/Keylogging | 1.000 | 0.411 | 0.869 [1,469] | flips (benign-reference mechanism, see below) | 0.473 [1,469] | collapses |

For the two UDP rows, the table's "AUC answered" column is shown for
completeness but the classification uses the unanswered-only slice (both
attack and benign restricted to their own unanswered rows — a slice the
frozen A2 plan includes), because that slice holds >99.99% of each
group's attack rows.

This is the largest and most consequential result of the audit. **Where
the BoT-IoT numbers move, it is the benign reference population that
moves, not the attack population.** BoT-IoT's benign reference is 9,543
synthetic Normal flows, only 47.3% of which get a reply (4,514 answered,
5,029 unanswered); `docs/ESTADO-ACTUAL.md` already records that this
Normal traffic is heavily source-dominated (median `A_bytes` +4.49). Eight
of the ten attack groups, by contrast, are either almost entirely answered
(reply rate 0.94-1.00: HTTP, Recon, Theft) or almost entirely unanswered
(UDP, ~0.00002), so for them conditioning on reply presence barely changes
the attack side and mostly changes which benign rows are in the reference.
Only DDoS/TCP (0.261) and DoS/TCP (0.500) are genuinely mixed.
Stated precisely: **the sign of the HTTP, Recon and Theft groups, and most of the UDP
magnitude change, is set by which benign rows are in the reference
population when reply-presence is held fixed** — not by removing rare or
unusual attack rows.

**DDoS/TCP and DoS/TCP** are the two groups with a large reliable sample in
*both* slices (attack reply rates 0.261 and 0.500): answered-only `A_bytes`
strengthens (0.953, 0.938) and unanswered-only stays positive (0.605,
0.643). On the answered slice both features agree (`A_packets` 0.985,
0.992).

**DDoS/UDP and DoS/UDP** get essentially no replies (0.002% and 0.0026% of
attack rows), so the answered-only slice (406 / 537 rows) is unusable —
but the reply-conditional test *can* be run on the unanswered-only slice,
which the frozen plan includes and which holds >99.99% of each group's
attack rows. There, `A_bytes` is 0.592 (DDoS/UDP) and 0.600 (DoS/UDP)
against 5,029 unanswered benign rows: still outside the ±0.05
near-neutral band, so by this report's convention **persists, weakened**
(from 0.785, 0.789); `A_packets` likewise persists, weakened (0.640, 0.639
from 0.810, 0.810). The attack side is effectively unchanged between `all`
and `unanswered` (18,965,106 -> 18,964,700 and 20,659,491 -> 20,658,954
rows); the drop in AUC comes from restricting the *benign* side from 9,543
rows to its 5,029 unanswered rows (which, having no reply, have
positive `A_bytes` by construction), not from removing the extremely rare
answered attack rows.

**DDoS/HTTP, DoS/HTTP, Recon/OS fingerprint, and Recon/Service scan flip
sign for `A_bytes`** — from negative (`all`, 0.32-0.36) to clearly positive
(`answered`, 0.68-0.75). The attack side barely changes: DDoS/HTTP 19,771
-> 19,769 rows, DoS/HTTP 29,706 -> 29,704, Recon/OS fingerprint 358,275 ->
345,635 (96.5% kept), Recon/Service scan 1,463,364 -> 1,378,580 (94.2%
kept). The benign side drops from 9,543 to 4,514. So the negative all-flows
orientation of these groups is produced by scoring almost-always-answered
attack flows against a benign reference that is about half unanswered
(unanswered benign flows have positive `A_bytes` by construction); against answered
benign flows only, the same attack flows sit on the positive side.
`A_packets` tells a related but not identical story for the two Recon
groups: it collapses to almost exactly 0.5 (0.497, 0.499) on answered-only
rather than flipping. For the two HTTP groups the unanswered-only slice has
`n_attack` = 2 and is not interpretable; for the two Recon groups the
unanswered-only slice (12,640 and 84,784 attack rows, 3.5% and 5.8% of the
group) is strongly negative (`A_bytes` 0.067, 0.020) — within the
unanswered stratum, those minority Recon rows carry less forward traffic
than unanswered benign flows.

These four groups are **four of the five** groups A1 marks
`sign_stable = false`; the fifth, **DoS/TCP**, behaves oppositely under A2
(it persists and strengthens, see above). So A1's weakened set and A2's
flip set overlap but are not the same set.

**Theft/Data theft and Theft/Keylogging flip by the same mechanism as
DDoS/HTTP and DoS/HTTP.** Their attack-side reply rate is 1.0, so
`n_attack` in the `answered` slice equals `n_attack` in `all` exactly (118
and 1,469 rows); the flip comes entirely from restricting the benign
reference to its 4,514 answered rows. That is the same benign-reference
mechanism as the HTTP groups (where 2 attack rows are dropped) and nearly
the same as the Recon groups (where 3.5-5.8% are dropped) — not a distinct
mechanism. It is not evidence that the attack population's own signal
changed; Theft has no unanswered subpopulation to compare against.

### CICIDS-2018 (14 real attack labels + 1 excluded artifact; `n_benign` = 13,467,970 throughout)

One group, `"Label"` (`n_attack` = 3), is excluded from classification: it
is a known ingestion artifact, not an attack category. `src/ingest/loader.py`
documents that some CICIDS-2018 files embed repeated CICFlowMeter export
headers mid-file; those 3 rows are literal header lines whose `Label`
column value is the string `"Label"`, misparsed as a distinct attack
label with `AUC = 1.0` on `n = 3`. This is a real, reportable ingestion
quirk (consistent with the exact failure mode `_numeric_schema_overrides`'s
docstring already describes) but not a finding about attack traffic.

| group | reply rate (attack, bytes) | AUC all (bytes) | AUC answered (bytes) [n_attack] | class (bytes) | AUC answered (packets) [n_attack] | class (packets) |
|---|---|---|---|---|---|---|
| Bot | 0.506 | 0.779 | 0.893 [142,865] | persists (strengthens) | 0.083 [143,014] | emerges (all-packets 0.465 is near-neutral) |
| Brute Force -Web | 0.439 | 0.760 | 0.829 [268] | persists | 0.714 [272] | persists |
| Brute Force -XSS | 0.491 | 0.441 | 0.221 [113] | persists (negative, stronger) | 0.898 [114] | persists (strengthens) |
| DDOS attack-HOIC | 0.245 | 0.577 | 0.242 [163,750] | **flips** | 0.057 [163,750] | **flips** |
| **DDOS attack-LOIC-UDP** | **0.000** | 1.000 | undefined [0] | **untestable — 100% unanswered by construction** | undefined [0] | untestable |
| DDoS attacks-LOIC-HTTP | 0.502 | 0.357 | 0.010 [289,289] | persists (negative, much stronger) | 0.057 [289,289] | emerges (all-packets 0.458 is near-neutral) |
| DoS attacks-GoldenEye | 0.647 | 0.467 | 0.450 [26,807] | near-neutral throughout (no signal to lose) | 0.567 [27,772] | persists (weakly positive) |
| DoS attacks-Hulk | 0.059 | 0.681 | 0.329 [25,548] | **flips** | 0.157 [25,548] | **flips** |
| **DoS attacks-SlowHTTPTest** | **0.000** | 0.709 | undefined [0] | **untestable — 100% unanswered by construction, and the constant-0-`A_bytes` case (see Diagnostic)** | 0.360 [19,462] | persists (packets reply differently, see below) |
| DoS attacks-Slowloris | 0.014 | 0.904 | 0.284 [142] | flips (small sample, n=142 — directionally suggestive, not conclusive) | 0.765 [7,947] | persists |
| **FTP-BruteForce** | **0.000** | 0.709 | undefined [0] | **untestable — 100% unanswered by construction, and the constant-0-`A_bytes` case (see Diagnostic)** | 0.360 [39,352] | persists (packets reply differently, see below) |
| Infilteration | 0.562 | 0.511 | 0.436 [90,956] | emerges (negative; all-bytes 0.511 is near-neutral) | 0.428 [136,750] | persists (weakly negative, ~unchanged) |
| SQL Injection | 0.552 | 0.508 | 0.418 [48] | emerges (negative), small sample (n=87 total), low confidence | 0.650 [58] | persists (positive), small sample |
| SSH-Bruteforce | 0.800 | 0.528 | 0.692 [93,818] | **emerges (signal appears on answered-only; all-flows 0.528 was itself near-neutral)** | 0.463 [117,317] | collapses (all-packets 0.370 was negative) |

CICIDS has the widest spread of patterns and the clearest confirmation of
the audit's exact concern. **`DDOS attack-LOIC-UDP` is the purest case of
the effect A2 was designed to detect**: 100% of its flows are unanswered
(`reply_rate = 0.0`); there is no answered subpopulation to test against;
its all-flows `A_bytes` AUC of 0.99999... cannot be attributed to
magnitude at all versus reply-absence, because the two are perfectly
confounded for this label — no analysis of this dataset can separate them.
**`DoS attacks-SlowHTTPTest` and `FTP-BruteForce` are the same construction
for `A_bytes`** (100% unanswered, `AUC = 0.7087` untestable) **but not for
`A_packets`**: both labels have `reply_packets = 1.0` (every flow gets at
least one backward packet — e.g. a TCP handshake ACK — even though zero
backward *bytes* are ever sent). So `A_bytes` is completely untestable for
these two labels while `A_packets` is fully testable and persists
(0.288 -> 0.360, same negative side) — the two features are conditioning on
genuinely different information for these flows, a real and useful
finding in its own right, not an inconsistency to average away. It also
means these two labels' "100% unanswered" status is a property of
CICFlowMeter's byte accounting (payload-only, per A3), not a
packet-level fact: a flow whose backward direction carries only header
packets counts as "unanswered" by bytes. For UNSW and BoT-IoT (Argus),
`reply_rate_attack_bytes` equals `reply_rate_attack_packets` for every
group in `reply_rates.csv` (and the benign rates match too); for CICIDS
they differ for 10 of the 14 real labels (equal only for HOIC, LOIC-UDP,
LOIC-HTTP, Hulk) and for benign (0.697 by bytes vs. 0.800 by packets). This is POST-HOC and suggestive, not proof, of the exporters
defining bytes differently (A3's open header-inclusion question); see
`AUDIT_SYNTHESIS.md`, Phase II.

`DDOS attack-HOIC` and `DoS attacks-Hulk` both flip from weakly/moderately
positive all-flows to clearly negative answered-only, on large reliable
samples (163,750 and 25,548 attack rows respectively), and **both features
agree** for these two labels — `A_packets` flips the same way `A_bytes`
does. **Caveat (reference dependence):** the positive all-flows side of
this "flip" exists only against the pooled benign reference used here.
Scored against their own capture file's benign rows (A3), HOIC's and
Hulk's all-flows `A_bytes` AUCs are 0.0005 and 0.023, already negative. The
answered-only negative result agrees with the per-file sign; what flips
between conventions is the all-flows number.
`DDoS attacks-LOIC-HTTP` persists on the negative side for `A_bytes` and
becomes much stronger, but its `A_packets` all-flows AUC (0.458) is itself
near-neutral, so for that feature the answered-only negative result
(0.057) is better described as signal *emerging* under conditioning than
as "persisting." `SSH-Bruteforce` shows the same emerges/collapses split
in reverse: `A_bytes` emerges (all-flows 0.528 near-neutral -> answered
0.692 clearly positive) while `A_packets` collapses (all-flows 0.370
negative -> answered 0.463 near-neutral) — the two features disagree not
just in degree but in which of the four patterns applies. Reported as its
own finding per the frozen plan's explicit allowance, not forced into
"persists."

## What changed

`results/audit/a2_reply/reply_rates.csv` and
`results/audit/a2_reply/auc_by_slice.csv` are new.

## What did not change

`results/unsw/`, `results/botiot/`, `results/dependence/`, and
`results/multiplicity/` were only read (for the informal reproduction
cross-check in Method step 3), never written. No preregistered hypothesis,
feature definition, threshold, seed, or confirmatory verdict was touched.

## Impact on manuscript claims

Per `docs/reviewer_audit/AUDIT_MASTER_PLAN.md`'s pre-committed A1 x A2
matrix, applied per BoT-IoT group (the only dataset with an existing A1
dependence classification to cross with):

- **DDoS/TCP, DoS/TCP** — A1: survives (DDoS/TCP `sign_stable=true`;
  DoS/TCP's flow-level CI was confident, but `sign_stable=false` under
  cluster methods — see A1 report). A2: persists (strengthens) on a large
  reliable answered sample. For DDoS/TCP specifically (both `sign_stable`
  and A2-persists), the matrix's top row applies: **evidence for
  directional semantics strengthens**. For DoS/TCP, A1 "weakens" + A2
  "survives" -> **phenomenon exists; original CI overstated precision**
  (matrix row 3).
- **DDoS/UDP, DoS/UDP** — A1: `sign_stable=true` under host-pair
  (two-stage matches; time-block not computable at 300s). A2: persists,
  weakened, on the unanswered-only slice (0.592, 0.600 vs. all-flows
  0.785, 0.789; answered-only unusable). Nominally the matrix's
  survives/survives row, but the orientation that survives is much weaker
  than the headline all-flows number, and the attenuation comes from the
  benign side of the comparison (see Results).
- **DDoS/HTTP, DoS/HTTP, Recon/OS fingerprint, Recon/Service scan** — A1:
  weakens (`sign_stable=false`: host-pair and two-stage CIs straddle 0.5;
  for the two Recon groups, time-block at 300s is instead confidently
  negative, so the A1 methods disagree). A2: flips (`A_bytes`) or
  collapses to ~0.5 (`A_packets`, Recon only) on large samples. Matrix row
  4 applies: **benchmark interaction / reply-structure artifact**. These
  four groups' negative all-flows orientation should not be read as a
  stable magnitude signature. A1 and A2 are **not independent** here: both
  run on the same BoT-IoT rows against the same 9,543-row benign
  reference. A2 shows the negative sign is set by that reference's reply
  mix, and A1's cluster weighting changes the effective composition of
  the same reference (347 benign host-pairs reweighted equally). Their
  agreement is structurally expected, not two separate lines of evidence.
- **Theft/Data theft, Theft/Keylogging** — not part of A1's verifiable set
  (fewer than 10 host-pairs; "not computed" in the A1 comparison). A2:
  flips via the same benign-reference mechanism as the HTTP groups. No
  A1 x A2 cell applies; reported standalone.

**What this means for the manuscript's BoT-IoT claims.** The sign pattern
A2 finds — attack groups whose flows are almost always answered look
negative against a half-unanswered benign reference, groups whose flows go
unanswered look positive — is *consistent with* the manuscript's
target-response reading (H3-env: the sign tracks whether the target
replies), not evidence against it. What it weakens is any reading that
BoT-IoT's directional-asymmetry *magnitude* carries mechanism information
beyond reply presence: with reply presence held fixed, every BoT-IoT group
is positive on the answered-only `A_bytes` slice (0.585-0.953), so the
confidently opposite orientations that make up the "sign heterogeneity"
largely disappear. See `AUDIT_SYNTHESIS.md` for the combined A1+A2
statement and its exceptions.

For **UNSW**, no A1-equivalent dependence audit exists to cross with, so
only A2's own classification stands: 8 of 9 categories persist (several
strengthen), 1 (Analysis) collapses. **Erratum**: an earlier version of
this report and of `AUDIT_SYNTHESIS.md` called Generic's result a
"collapse" too. Under the frozen point-estimate/band rule (collapse =
answered-only AUC falls inside `|AUC-0.5|<0.05`), Generic's 0.561 is
0.061 from 0.5 -- outside the band -- so it PERSISTS, not collapses; the
numeric result (0.891 -> 0.561) is unchanged, only which frozen bucket it
belongs to. Generic's persistence should still be weighted lightly given
how unrepresentative its 1.5%-answered slice is (`n_attack`=3,247 of
215,481) -- that is a separate, sample-composition caveat, not grounds to
reclassify the point estimate. Analysis's collapse is on a larger, more
representative slice (23.5% answered, n=630) and is the unambiguous case.

For **CICIDS**, which has no A1 equivalent either: the manuscript's
existing framing of CICIDS floods (`docs/reviewer_audit/A3_EXPORTER_AND_LABEL_SEMANTICS.md`
already raises label-semantics questions for this dataset) should note
that at least three labels (`DDOS attack-LOIC-UDP`, `DoS
attacks-SlowHTTPTest`, `FTP-BruteForce`) have all-flows `A_bytes` AUCs
that are **entirely** a function of reply-absence/constant-zero
forward-byte flows, not measured magnitude asymmetry — any manuscript
table that lists a high `A_bytes` AUC for these three labels without this
caveat overstates what was measured. `DDOS attack-HOIC` and `DoS
attacks-Hulk` "flip" here only relative to a *pooled*-reference all-flows
AUC (0.577, 0.681) that itself has the opposite orientation from the
per-capture-file AUC (A3: 0.0005, 0.023; the same per-file convention as
the discovery numbers in `docs/datos-reales/`, e.g. Hulk 0.023). Their
answered-only negative orientation agrees with the per-file sign. Before
drawing any manuscript conclusion from these two "flips," check which
benign reference convention the manuscript's CICIDS numbers use (see
`AUDIT_SYNTHESIS.md`, reference-dependence finding).

## Limitations

- **No bootstrap CI was computed for this task.** Classification
  ("persists"/"collapses"/"flips") is based on point AUCs against the
  existing `NEUTRAL = 0.05` convention, not against a confidence interval
  as the frozen plan's prose literally describes ("within the all-flows
  95% CI"). This is a real gap between the plan's stated interpretation
  rule and what was actually computed; a future audit could add CIs to
  make several of the borderline calls above (Generic's 0.561, HOIC's
  0.577, SSH-Bruteforce's 0.528) less ambiguous.
- **The zero-`A_bytes` degenerate case** (six CICIDS labels'
  unanswered-slice attack rows, `DDOS attack-LOIC-UDP`, `DoS
  attacks-SlowHTTPTest`, `FTP-BruteForce` entirely) means several
  "AUC" numbers reported above are mechanical functions of a fixed
  benign distribution against a constant attack value, not a measured
  separation with any variance on the attack side. These are flagged
  inline but the underlying script has no code-level guard against
  reporting a zero-variance AUC as if it carried the same evidentiary
  weight as a non-degenerate one — a human reader must apply that
  caveat, the script does not apply it automatically.
- **BoT-IoT's DDoS/UDP and DoS/UDP answered-only samples (406 and 537
  rows out of 18.9M/20.7M)** are technically non-empty but too
  unrepresentative to classify on; these two groups are classified on the
  unanswered-only slice instead (persists, weakened). An earlier version
  of this report called them "not reliably classifiable" and said the
  test "cannot be run"; that was wrong, since the frozen plan's
  unanswered-only slice tests them directly.
- **Benign reference population.** Every AUC here is against one pooled
  benign population per dataset (for CICIDS: all 13,467,970 benign rows
  across the 10 capture files). A3 scores CICIDS labels against each
  capture file's own benign rows instead, and for three labels the two
  conventions give opposite orientations (see the CICIDS section and
  `AUDIT_SYNTHESIS.md`). The CICIDS all-flows numbers in this report are
  therefore not the same quantity as the per-file discovery numbers in
  `docs/datos-reales/`.
- **The `"Label"` CICIDS artifact (n=3)** was excluded from the results
  table by hand; the script itself does not filter it, so
  `results/audit/a2_reply/*.csv` still contains those 3 rows verbatim.
- No group's answered-only result was used to rescue or discard another
  group's all-flows result, per the frozen plan; each group above is
  reported independently.

## Output hashes

```
sha256(results/audit/a2_reply/reply_rates.csv) =
de38e2ecbb725f579a7521afcb6cab6dd3d63efc27cc6bfb3bba196d1d7f1e7e
sha256(results/audit/a2_reply/auc_by_slice.csv) =
ca1a301ea9ecbf558973e1c9793f4e470f36808ef7f62c781588595a2be921e8
```
