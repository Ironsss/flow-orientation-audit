# BoT-IoT external validation of H3 -- findings

**Verdict (script-evaluated, FREEZE SS6.1): STRONG REPLICATION.** The
deduplicated sensitivity run gives the same verdict; its population is
identical to the primary, since Phase 0 found 0 duplicates.

On BoT-IoT, per-flow directional asymmetry takes **opposite, confident
orientations across mechanism groups**, on both pre-registered features.
Every opposite-sign pair used by the rule has the attacker as source in
≥ 96% of its rows.

**Secondary predictions (SS6.2).** They were set up to discriminate between
the two readings, and they did:
- **H3-env** (the environment reading, generated post-hoc on UNSW-NB15;
  this was its first prospective test): **6/6 held, all confident.**
- **H3-dir** (the mechanism reading from CICIDS-2018): **2/7 held.** It
  failed on all four hping3 floods and on Keylogging.

Neither SS7 abandonment condition fired: no hping3 flood is confidently
negative, and no GoldenEye flood is confidently positive.

- Freeze: `docs/methodology/BOTIOT_H3_FREEZE.md`, commit `2fad302`
  (2026-09-22), written with no data on disk. Phase 0: SS9.1, PR #43.
- Code: `4554139` (adapter + runner), pushed before its only run on real
  data. `run_metadata.json` records `git_dirty: false`.
- Command: `python scripts/run_botiot_h3.py --data-dir "<...>/Entire Dataset"`
  (~4 min). Outputs: `results/botiot/`, `results/figures/botiot_*.pdf`.
- The counting AUC was asserted equal to `roc_auc_score` on all ten groups
  at run time.

## Primary result (all 73,370,443 rows; n_benign = 9,543; B=2000, seed 20260922)

| Group | n attack | AUC_signed A_bytes | 95% CI | AUC_signed A_packets | C1 size AUC | src=attacker | Orientation | H3-dir | H3-env |
|---|--:|--:|--|--:|--:|--:|--|--|--|
| Recon/Service scan | 1,463,364 | 0.3599 | [0.3513, 0.3688] | 0.2524 | 0.1049 | 0.978 | negative | – | – |
| Recon/OS fingerprint | 358,275 | 0.3548 | [0.3461, 0.3635] | 0.2454 | 0.0908 | 0.993 | negative | – | – |
| DDoS/TCP (hping3) | 19,547,603 | 0.7029 | [0.6962, 0.7102] | 0.7135 | 0.5834 | 0.998 | positive | ✗ | ✓ |
| DDoS/UDP (hping3) | 18,965,106 | 0.7851 | [0.7780, 0.7925] | 0.8102 | 0.5371 | 1.000 | positive | ✗ | ✓ |
| DDoS/HTTP (GoldenEye) | 19,771 | 0.3197 | [0.3116, 0.3281] | 0.4602 | 0.7128 | 0.971 | negative | ✓ | ✓ |
| DoS/TCP (hping3) | 12,315,997 | 0.6278 | [0.6206, 0.6355] | 0.6462 | 0.6214 | 0.999 | positive | ✗ | ✓ |
| DoS/UDP (hping3) | 20,659,491 | 0.7894 | [0.7824, 0.7967] | 0.8098 | 0.5420 | 1.000 | positive | ✗ | ✓ |
| DoS/HTTP (GoldenEye) | 29,706 | 0.3400 | [0.3318, 0.3486] | 0.4557 | 0.7127 | 0.962 | negative | ✓ | ✓ |
| Theft/Keylogging | 1,469 | 0.4110 | [0.4013, 0.4215] | 0.2236 | 0.2366 | **0.252** | negative | ✗ | – |
| Theft/Data theft | 118 | 0.2825 | [0.2587, 0.3085] | 0.0839 | 0.7095 | 0.966 | negative | – | – |

All ten groups are confidently oriented on `A_bytes`. On `A_packets` the
two GoldenEye groups fall in the near-neutral band (0.460 and 0.456); the
other eight are confident. The rule still holds on `A_packets`: Recon and
Data theft are negative, the hping3 floods positive.

**Role check.** All attack rows resolve to an attacker host. Keylogging is
the one group where the **victim is usually the source** (75%). That fits
the paper's host-pair labeling and the reverse connections of the
Metasploit scenarios. It is excluded from the qualifying pairs by the role
condition. The attack-oriented variant makes it more negative (0.2734), not
positive. Every other group has `src_is_attacker` ≥ 0.96.

## Caveats that belong next to the verdict (all visible in the frozen outputs)

1. **The benign reference is itself strongly source-dominated.** Normal has
   median `A_bytes` = **+4.49** (p25 −0.07, p90 +13.1). UNSW-NB15's Normal
   has median −0.22. The "negative" groups are mostly **balanced in absolute
   terms**:

   | group | median `A_bytes` |
   |---|--:|
   | Recon | 0.00 |
   | GoldenEye floods | −0.07 / +0.01 |
   | Keylogging | +0.21 |
   | Data theft | −0.66 |

   `AUC_signed` measures orientation **relative to the benign reference**,
   as defined and frozen. The verdict is therefore correct under the rule.
   But the heterogeneity here is "more source-dominated than Normal" vs.
   "less source-dominated than Normal", and Normal is 9,543 synthetic
   Ostinato flows (76% UDP). That limitation was recorded in the freeze
   (SS2) before any data existed. Only Data theft is destination-dominated
   in absolute terms.
2. **C1 (size-only arm).** Where directional asymmetry is weak, volume alone
   separates as well or better:
   - Recon: size `AUC_sep` 0.90–0.91 vs. direction 0.64–0.65.
   - GoldenEye floods: size 0.71 vs. direction 0.66–0.68.

   Direction beats size for the hping3 UDP floods (0.79 vs. 0.54). C1 does
   not enter the verdict, but "direction carries information volume does
   not" is **not** established here for Recon or HTTP floods.
3. **Small groups.** Data theft has n = 118 and Keylogging n = 1,469. Their
   CIs reflect that; both are nonetheless confident.

## Interpretation (FREEZE SS7)

- **H3 across the external tests:** UNSW-NB15 NO REPLICATION; BoT-IoT
  STRONG REPLICATION. Neither result erases the other. Per SS1 both are
  reported. The combined conclusion is that **orientation depends on the
  attack mechanism in some capture environments and not in others.** It is
  not a universal property of attack families.
- **The discriminating question, which reading predicts the sign?**
  H3-env, the reading derived from UNSW (targets that do not answer produce
  source-dominated flows), predicted all six flood groups correctly, **in
  advance**. H3-dir, the CICIDS reading ("floods invert"), got the hping3
  floods wrong: they are positive, as the fire-and-forget reading implies.
  It got Keylogging wrong too. The environment reading thereby moves from
  post-hoc explanation to a **prospectively supported prediction** on one
  dataset.
- **What this does not show:** that the sign is caused by target response
  in general. One dataset, six predictions, and a synthetic benign
  reference support it, but do not establish it.
- Nothing is re-analyzed post-hoc here. The caveats above are read directly
  off the frozen outputs (`asymmetry_by_attack.csv`,
  `asymmetry_distributions.csv`).
