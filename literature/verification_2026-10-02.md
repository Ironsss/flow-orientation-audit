# Source verification, 2026-10-02

Scope: checks of what `manuscript/` attributes to external papers, against sources reachable without payment. Literature only; no experiment, result or hypothesis was touched. Companion to `novelty_audit.md`. The parallel audit of J. E. Malagón (`review/literature/COMPARACION-CON-AUDITORIA-DEL-EQUIPO.md`, branch `jemm/review/manuscript-v2`) supplied the candidate additions.

## Verified against the source

| Claim in the package | Source consulted | Result |
|---|---|---|
| Layeghy & Portmann (CEE 2023): none of the models generalises; asymmetry; SHAP correspondences present in one target domain and absent in another; attributed to feature distributions; binary Benign/Attack task | Published article, full PDF supplied by the authors | Confirmed. Eight models (four supervised, four unsupervised), not seven; fixed in PR #66 |
| Layeghy et al. (JISA 2024, 80:103689): synthetic benign traffic differs from real benign traffic for most features | Published article, full text (CC BY), pasted by the authors 2026-10-06; abstract also checked in arXiv 2104.09029v1 | Confirmed, with scope: six NetFlow-v9 features (flow duration, flow size = IN_BYTES+OUT_BYTES, packet time, packet size, destination IPs per source IP, L7 protocols per source IP), converted with nProbe; three testbed datasets (UNSW-NB15, CIC-IDS2017, TON_IoT; not CSE-CIC-IDS-2018 or BoT-IoT) against two production networks (ISP 2017, UQ 2019), one manually inspected day each; benign traffic only; compared by box plots, CDFs, Wasserstein distance and embeddings, with no hypothesis test (so "statistically" was loose; the SM sentence now says "in distribution"). The authors state the difference is clear for some features and needs further investigation for others (CIC-IDS2017 is close to the real data in several), and that dataset distance is not uniform across features. Flow size is the sum of IN_BYTES and OUT_BYTES: no directional or sign analysis, so no overlap with `A_bytes`. Published title: "Benchmarking the benchmark - Comparing synthetic and real-world Network IDS datasets"; matches `references.bib` |
| Cantone et al. (IEEE Access 2024) title | Crossref | The registered title is "Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study"; fixed |
| Elangovan et al. 2026 (Future Internet 18(4):194): title, authors, article number | Crossref | Confirmed. Content claims (section 3.3.2, 4.6, Macro-F1 variance) not re-read; publisher returns 403 |
| Bouke et al. 2026 (arXiv 2606.29797), Fig. 11 | arXiv PDF | Caption: "MDE score delta (Attack - Benign mean) per dataset. The sign reversal between environments reveals that attack entropy signatures are environment-dependent, motivating cross-dataset evaluation." Binary attack/benign labels. The object is a model-derived score difference. The text said "without inference"; this could not be confirmed and was removed |
| Fernandez-Barrios et al. 2026 (arXiv 2609.04388) | arXiv PDF | "The replication protocol ... was committed and publicly tagged in version control before any confirmatory seed ran". Uses UNSW-NB15, CICIDS2017, ToN-IoT. Confirmed |
| Zmaimita 2026 (Zenodo 10.5281/zenodo.21996144) | Zenodo record | Preregistered analysis plan, resource type Preprint, 2026-08-18. Task is CICIDS2017 + CIC-MalMem-2022 (not UNSW). Confirmed as a preregistered plan |
| Argus source rule | Debian `ra(1)` manual | "The 'src' is generally the entity that first transmits a packet that is a part of a flow." For TCP: "the 'src' is the entity that initiated the flow." Confirmed |
| NetFlow-v2 labeling (`sarhan2021nfv2`) | arXiv 2101.11315 | "Two label features are created by matching the five flow identifiers; source/destination IPs and ports and protocol to the ground truth attack events published by the original dataset." Confirmed |
| Liu et al. (CNS 2022), Engelen et al. (SPW 2021), D'hooge et al. (JISA 2020) titles | Crossref | Bibliographic data match `references.bib` |

## Not verified here (publisher blocks or closed access)

- Jin & Lee 2026, section 2.2 ("all attack categories are assigned to the positive class") and the oracle-flipped AUC: MDPI returns 403. The statement rests on J. E. Malagón's reading of the publisher PDF.
- Elangovan et al. 2026, definition of the "Directional Behavior" group and its conclusion: same, MDPI 403. Rests on J. E. Malagón's reading.
- D'hooge et al. 2020 (closed access, no abstract in Crossref/OpenAlex): the sentence "strong inter-dataset generalization is not implied by strong intra-dataset scores" could not be checked. Institutional access is needed, or soften the sentence.
- Liu et al. 2022 and Engelen et al. 2021 full text (IEEE, restricted): the "TCP appendix" mechanism and the corrected-data claims rest on the earlier audit and on J. E. Malagón.
- Rosay et al. 2022 (CICFlowMeter record after the first FIN): title and DOI taken from his list; content not re-read.
- CROSS-IoT (Wiley, closed) and Aragao et al. 2026 (Wiley, 403 despite CC-BY): abstracts only. Neither is cited.
- Pawlicki et al. 2025/2026: no open copy found by either audit.
