# Novelty Audit — signed directional orientation (JISA)

Scope: literature audit only. No experiment, result, hypothesis, threshold, seed or figure was touched, and `main.tex` was **not** edited. Date: 2026-09-28.
Companion files: `literature_matrix.csv` (47 rows), `related_work_proposed.md`, `alignment_with_manuscript.md`, `search_log.md`.

**How reliable is this audit?** Read this first.
- Full text was extracted and read (keyword scan plus targeted passages) for: Layeghy & Portmann (arXiv preprint; published version also read in full on 2026-10-02), Apruzzese et al., Flood et al., Engelen et al., Pinto et al., Sarhan et al. (three papers), Layeghy et al. 2021 (preprint of the JISA 2024 paper), Luay et al., Cantone et al., Wilkinson & Thomson.
- **Not** read in full text: D'hooge et al. (JISA 2020), Liu et al. (CNS 2022), and most of the older references. Layeghy et al. (JISA 2024) was read in full on 2026-10-06 (see `verification_2026-10-02.md`). The publisher pages returned 403. Jin & Lee (2026) was read through a text proxy plus a summariser (`PARTIAL`).
- The search was broad but **not systematic**: web search and arXiv only, no Google Scholar/IEEE/ACM/Scopus forward-citation crawl. Therefore **no sentence of the form "this is the first study …" is supportable.**

---

## 1. What is already established

**Cross-dataset performance failure (A: classifier performance does not transfer).** Established by many studies: D'hooge et al. (JISA 2020) on CIC-IDS2017/2018; Apruzzese et al. (TNSM 2022); Cantone et al. (IEEE Access 2024: near-perfect in-dataset, near-chance cross-dataset accuracy); Layeghy & Portmann (CEE 2023); Hesford et al. 2024; Nougnanke et al. (ESORICS 2025). Background: Sommer & Paxson 2010, Arp et al. 2022.

**Feature–label relations differ across datasets, at model level (between A and C).** Layeghy & Portmann use SHAP summary plots to show that the correspondence between low/high values of a feature (e.g. `MAX_TTL`) and Benign/Attack in one target domain is absent in another, attributing failure to "different feature distributions". This is the nearest prior *statement* of our theme, on two of our datasets (UNSW-NB15, BoT-IoT) in a common NetFlow-v2 exporter.

**Score orientation can invert under cross-dataset transfer (closest to C, at score level).** Jin & Lee (Electronics 2026): under HIKARI-2021→CICIDS2017 transfer some detectors show AUC below 0.5 ("inverted score orientation"); they report an "oracle-flipped" AUC, max{AUC, 1−AUC}, as a diagnostic. In images/anomaly detection the same phenomenon is known as score-direction instability (Ascarate et al. 2026, not NIDS).

**Dataset, labelling and exporter artifacts.** Engelen et al. 2021 (CICFlowMeter: after a TCP-appendix timeout the next flow can go in the wrong direction, source and destination swapped; labelling depends on correct direction; many "attack" flows carry no forward data); Liu et al. 2022 and Lanvin et al. 2023 (further errors); Flood et al. 2024 (features of outsized importance unrelated to the attack mechanism, e.g. TTL/RTT in UNSW-NB15); Sarhan et al. (a single TTL feature nearly matches the full feature set on UNSW-NB15, attributed to testbed design); Pinto et al. 2025 (same PCAP, different exporters → different results); Apruzzese et al. 2022 (a NetFlow is a function of the communication plus the network and the exporter configuration).

**Benign reference.** Layeghy et al. (JISA 2024): the benign traffic of three testbed datasets differs in distribution from that of two production networks for most of six NetFlow-derived features (CDFs and Wasserstein distances, no hypothesis test; benign only, direction of flows not studied). Wilkinson & Thomson 2025: benign class shows internal structure (poster).

**Directional / asymmetry features as detectors.** MULTOPS (Gil & Poletto 2001: disproportion between packet rates in the two directions); scan detection from unanswered connection attempts (Jung et al. 2004); Producer–Consumer Ratio, (sent − received)/(sent + received), independent of load (Bullard & Gerth, FloCon 2014, presentation); biflow semantics (RFC 5103, which itself lists separating answered and unanswered requests as a use case).

**Statistics of dependence.** Cluster bootstrap (Field & Welsh 2007); few-cluster over-rejection (Cameron, Gelbach & Miller 2008).

**Preregistration / reproducibility.** Nosek et al. 2018; Arp et al. 2022; Kapoor & Narayanan 2023.

**Signed orientation of one fixed interpretable flow feature across datasets, with a named benign reference.** In the sources found, **no paper does this.** This is a statement about my search, not a proof of absence.

---

## 2. Closest prior work

### Layeghy & Portmann — *Explainable Cross-domain Evaluation of ML-based NIDS* (CEE 2023; arXiv 2205.04112)
- **A. Establishes.** Eight models (four supervised, four unsupervised/semi-supervised) on four NetFlow-v2 datasets (UNSW-NB15, BoT-IoT, ToN-IoT, CSE-CIC-IDS2018): none generalises over all; generalisation is asymmetric between source and target; SHAP plots show feature-value/class correspondences present in one target domain and absent in another.
- **B. Overlap.** Cross-dataset non-transport of feature–label relations; same exporter family (NetFlow-v2) as our A4; UNSW-NB15 and BoT-IoT.
- **C. Still ours.** The unit of analysis: one fixed, interpretable directional feature; its *sign* stated explicitly; a *named* benign reference; reply composition, host-pair dependence and representation audits; orientation separated from separability; preregistered external tests with a script-computed verdict.
- **D. Fair representation?** Our text says they "found that none generalized over all, attributing this to feature distributions, including feature–label relations present in one dataset and absent in another". Checked against the published version (2026-10-02): fair. Caveats: the evidence is model-level SHAP, not a per-feature sign test; the task is binary Benign vs. pooled Attack (no per-mechanism split); the worked SHAP examples hinge on single-rule classifiers (e.g. `MAX_TTL`), and they attribute the asymmetry to simple single-threshold rules that exist in one domain and not in another. The published title differs from the arXiv one.

### Jin & Lee — *Benchmark-Shift-Aware Intrusion Detection … Score-Orientation Diagnostics* (Electronics 2026)
- **A. Establishes.** Under strict transfer some detectors invert score orientation; oracle-flipped AUC used as a diagnostic; calibration and threshold transfer.
- **B. Overlap.** The phenomenon "AUC < 0.5 under dataset shift" and the device max{AUC, 1−AUC} (our `AUC_sep`) are both present.
- **C. Still ours.** The object is a fixed feature, not a trained detector; the reference population is named and varied; the mechanism side (reply composition, dependence, representation) is audited.
- **D. Fair?** We do not cite it yet. It must be cited, and we must not present the orientation/separability distinction as new in itself.

### Apruzzese, Pajola & Conti — *The Cross-evaluation of ML-NIDS* (TNSM 2022)
- **A.** A NetFlow = F(Comm, NetId, Conf): communication plus network identity plus exporter configuration; XeNIDS standardises datasets and controls artifacts.
- **B.** Same conceptual split as "network behaviour" vs "dataset as measurement instrument".
- **C.** We measure the consequence on the sign of a specific feature, with audits.
- **D.** Not yet cited; an automated summary attributed "sign inconsistencies" to this paper. The full text does not say that; do not repeat it.

### Flood et al. — *Bad Design Smells in Benchmark NIDS Datasets* (EuroS&P 2024)
- **A.** Six data-design smells; features of outsized importance unrelated to the mechanism; results of published papers change when smells are controlled.
- **B.** Supports reading dataset-specific feature behaviour as an artifact of design.
- **C.** Sign of a directional feature; reply composition; host-pair dependence.
- **D.** Cited nowhere yet. Should be central in Related Work and Discussion.

### Engelen et al. (2021), Liu et al. (2022)
- **A.** CICFlowMeter bugs, including swapped source/destination; attempted-attack flows with no forward data; corrected recreation of CSE-CIC-IDS-2018.
- **B.** Our A3/A4 finding that 75.5% of canonical HOIC and 94.1% of Hulk flows are zero-payload unidirectional records is consistent with "attempted attack" flows.
- **C.** We quantify the effect on orientation against different benign references.
- **D.** Current manuscript cites both only as generic labelling problems. It should state that direction swaps exist and that our CICIDS results use the original, not the corrected, data.

### Sarhan et al. (2021, 2022a, 2022b, feature analysis)
- **A.** Common NetFlow re-exports (nProbe); NetFlow vs CICFlowMeter feature sets generalise differently; testbed artifacts drive single-feature AUC on UNSW-NB15.
- **B.** Source of the NF-v2 data in A4; precedent for artifact-driven single-feature AUC.
- **C.** Sign and reference dependence.
- **D.** Cited once (standard feature set); the others are missing.

### Bullard & Gerth (PCR), Gil & Poletto (MULTOPS), Jung et al. (TRW)
- **A.** Directional imbalance and unanswered attempts are established, interpretable detection signals.
- **B.** Our `A_bytes` is a per-flow, log-difference analogue of PCR; the reply-presence effect is the basis of scan detection.
- **C.** We do not propose the feature; we test whether its sign transports.
- **D.** **Two of our current Introduction citations do not support the claim they are attached to** (see §3, item 1).

---

## 3. Novelty threats

| # | Threat | Class |
|---|---|---|
| 1 | The Introduction cites David & Thomas 2015 (entropy of flow counts) and Alturki et al. 2025 ("asymmetrical IoT systems" = heterogeneous devices) for "directional asymmetry recurs as a detection signal". Neither verified abstract concerns sent/received asymmetry. This is a **citation-accuracy defect**, not a novelty threat, but a reviewer will find it. Replace with MULTOPS, PCR, TRW, Sperotto, RFC 5103. | **CRITICAL** (accuracy) |
| 2 | "Feature–label relations do not transport across datasets" is already shown at model level (Layeghy & Portmann). Any wording that suggests we discovered non-transport of feature–label relations is unsafe. | **IMPORTANT** |
| 3 | "Orientation vs separability" as a contribution: `max(AUC, 1−AUC)` and oracle flipping are established diagnostics (Jin & Lee 2026); score-direction instability is known in anomaly detection (Ascarate et al. 2026). | **IMPORTANT** |
| 4 | "Resampling unit determines apparent precision" as a contribution: cluster bootstrap and the few-cluster problem are textbook (Field & Welsh; Cameron et al.). | **IMPORTANT** |
| 5 | "Exporter/labelling changes conclusions": established (Engelen, Liu, Lanvin, Flood, Pinto, Apruzzese). Novel only as applied to the sign of one feature. | **IMPORTANT** |
| 6 | "Benign reference matters": established at distribution level (Layeghy 2024, Wilkinson). Novel only as reference-dependence of the sign. | MINOR |
| 7 | Freeze/preregistration protocol: not novel (Nosek; Arp). | MINOR |
| 8 | Missing must-cite JISA works (D'hooge 2020; Layeghy 2024). | MINOR (fit/citation) |

No paper found substantially anticipates the *combination* now claimed as the central contribution, but that conclusion is limited by the coverage described at the top.

---

## 4. Claims we can safely make

1. "Signed orientation, `AUC_signed` of a fixed feature against a **named** benign reference, is a relational measurement: in the three benchmarks studied its sign depended on the reference population, reply composition, host-pair weighting and, for two CICIDS-2018 labels, on the representation-plus-reference pair."
2. "Prior cross-dataset NIDS studies report classifier performance [D'hooge; Apruzzese; Cantone], model-level attributions [Layeghy & Portmann; Sarhan] or the orientation of trained detectors' scores [Jin & Lee]. In the sources we found, none reports the sign of a single fixed interpretable directional feature against varied named benign references."
3. "Separating orientation from separability is a standard use of AUC (oracle flipping, [Jin & Lee]); we apply it to a fixed feature and show that separation can stay high while orientation changes, and that a confident sign change implies `AUC_sep ≥ 0.55` by construction."
4. "Exporter and labelling artifacts are documented [Engelen; Liu; Flood; Pinto]; our audits show, for one feature, that such choices can change the sign."
5. "Flow-level bootstrap intervals overstated precision relative to host-pair resampling in BoT-IoT (0.014–0.018 vs 0.27–0.41 wide)"; the statistical point is known [Field & Welsh; Cameron et al.]; ours is an instance in NIDS data.
6. The target-response reading stays *associative*; add that testbed layout can also produce single-feature artifacts [Flood; Sarhan].

## 5. Claims we must NOT make

- "This is the first study of sign/orientation instability of NIDS features" (search not systematic; Layeghy & Portmann and Jin & Lee are adjacent).
- "We show for the first time that feature–label relations differ across NIDS datasets."
- "We introduce the distinction between orientation and separability" or "AUC below 0.5 across domains is a new phenomenon."
- "We are the first to show that the exporter or benign reference changes NIDS conclusions."
- That the freeze protocol is a methodological contribution.
- That target response *causes* the sign, or that attack mechanism determines it.
- That the corrected CIC-IDS-2018 data (Liu et al.) give the same results (not tested).
- That PCR/MULTOPS-type detectors "fail to transport" (we tested none).

## 6. Recommended positioning for JISA

The narrowest contribution that is both interesting and true:

> A measurement-validity audit of one fixed, interpretable directional feature. The sign of its association with the attack label is not a property of the attack: it depends on the named benign reference, on reply composition, on how dependence among flows is handled and, for two labels, on flow representation, while separability can stay high. The paper documents this with preregistered external tests, post-hoc audits and reported negative results, in three benchmarks.

Position it against (i) classifier-transport work, (ii) model-level attribution work (closest: Layeghy & Portmann), (iii) score-orientation work (closest: Jin & Lee), and (iv) artifact work (Engelen, Flood, Pinto, Apruzzese). State plainly that the phenomenon "feature–label relation and score orientation vary with the dataset" is known; the addition is the fixed-feature, named-reference, audited version.

## 7. SUGGESTED_POSTHOC_ANALYSIS (not executed)

- **SUGGESTED_POSTHOC_ANALYSIS-1.** Check rank equivalence between `A_bytes` and the normalised (sent−received)/(sent+received) form (PCR-style) on the three datasets, to justify calling `A_bytes` a per-flow PCR analogue. Low cost, low risk.
- **SUGGESTED_POSTHOC_ANALYSIS-2.** Extend A4 (same traffic, common exporter) to NF-UNSW-NB15-v2 and NF-BoT-IoT-v2. Would test whether representation sensitivity extends beyond CICIDS-2018. Post-hoc only; both datasets remain spent for H3.
- **SUGGESTED_POSTHOC_ANALYSIS-3.** Re-run the CICIDS-2018 orientation on the corrected data of Liu et al. (2022) to check that HOIC/Hulk behaviour is not a bug artifact. Post-hoc only.
- **SUGGESTED_POSTHOC_ANALYSIS-4.** ~~Read the SHAP figures of Layeghy & Portmann for `IN_BYTES`/`OUT_BYTES`.~~ Done by reading (2026-10-02): the published SHAP analysis does not interpret the direction of `IN_BYTES`/`OUT_BYTES`. `IN_BYTES` appears once, in the top-10 of Fig. 9(b) (Extra Tree, ToN-IoT to BoT-IoT), without discussion; the interpreted features are `MAX_TTL`, `TCP_WIN_MAX_IN`, flags and DNS fields. No comparison with our UNSW/BoT signs is possible from that paper.
