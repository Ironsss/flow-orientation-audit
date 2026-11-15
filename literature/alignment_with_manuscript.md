# Alignment of the literature audit with the current manuscript

Applies to `manuscript/main.tex` (12 pages incl. references) and `supplementary.tex`. **Nothing in the manuscript has been edited.** Every item below is a recommendation for Introduction, Related Work, Discussion or Limitations. No result, hypothesis, threshold, seed or figure is affected.

## A. Defects to fix (accuracy)

| # | Where | Problem | Fix |
|---|---|---|---|
| A1 | Introduction, first paragraph | `\cite{david2015entropy}` (entropy of flow counts) and `\cite{alturki2025entropyiot}` ("asymmetrical IoT systems" = heterogeneous devices) are cited for "directional asymmetry recurs as a detection signal". Neither verified abstract concerns sent/received asymmetry. | Replace with MULTOPS, scan detection (unanswered attempts), PCR, Sperotto survey (text in §C-1). Drop both entries from `references.bib`. |
| A2 | Related work paragraph | Closest prior work missing: Jin & Lee 2026 (score-orientation inversion, oracle-flipped AUC); D'hooge et al. 2020 (JISA); Layeghy et al. 2024 (JISA); Flood et al. 2024; Apruzzese et al. 2022; Sarhan feature-analysis (TTL artifact). | Use the replacement paragraph in §C-2. |
| A3 | Contributions (Introduction) | "the separation of orientation from separability" and "resampling unit determines apparent precision" read as inventions. | Reword as applications of established devices (§C-3). |
| A4 | Positioning sentence | Fine as hedged ("to our knowledge … we do not claim to have excluded it") but now needs the two adjacent works named. | Keep the hedge; name Layeghy & Portmann and Jin & Lee (§C-2). |

## B. Content to add (Discussion and Limitations)

1. **Discussion, target response.** Add that testbed layout can generate single-feature artifacts unrelated to attack behaviour (Flood et al.: TTL/RTT in UNSW-NB15; Sarhan feature analysis: one TTL feature ≈ full feature set), which is one more reason the reply/target-response pattern is only associative.
2. **Discussion, definitional part of reply effects.** The dependence of a sent/received feature on reply presence is the same phenomenon that scan detection exploits (Jung et al.; RFC 5103 lists separating answered and unanswered requests). One clause.
3. **Limitations, source/destination semantics.** Engelen et al. document CICFlowMeter flows with source and destination swapped after a TCP timeout, and attack flows with no forward data. Add: the CICIDS-2018 orientations rest on the exporter's direction assignment, which we cannot role-check (nine of ten captures lack IP addresses). This upgrades an existing limitation.
4. **Limitations, corrected data.** Liu et al. (2022) released a corrected CSE-CIC-IDS-2018; our CICIDS results use the original labels and the NF-v2 re-export. State that orientation on the corrected data was not tested.
5. **Limitations, few clusters.** Cite Cameron, Gelbach & Miller for the over-rejection risk with 25–40 host-pair clusters (currently stated without a reference).
6. **Limitations, PCR.** State that `A_bytes` is a per-flow analogue of the Producer–Consumer Ratio and that we did not evaluate PCR-type detectors.

## C. Proposed text (LaTeX, drop-in candidates)

Keys refer to `references_candidate.bib`. Length is chosen to replace text of similar size; **the manuscript is at its 12-page ceiling**, so any net addition must be paid for (§D).

**C-1. Introduction, first paragraph, first three sentences (replace):**

```latex
Most legitimate network communication is bidirectional by construction, and many attacks break that balance: a port scan sends probes that go unanswered, a flood saturates one direction. Directional imbalance is accordingly an established detection primitive. MULTOPS flags bandwidth attacks from disproportionate packet rates in the two directions~\cite{gil2001multops}, scan detectors rely on connection attempts that receive no reply~\cite{jung2004portscan}, and the Producer--Consumer Ratio normalises sent minus received bytes~\cite{bullard2014pcr}; graph methods aggregate relational structure over hosts~\cite{akoglu2015graph,zhong2024gnnids}.
```

**C-2. "Related work" paragraph (replace the whole paragraph):**

```latex
Closed-world benchmark results can overstate field performance~\cite{sommer2010closedworld,arp2022dosdonts}, and cross-dataset studies of flow classifiers report near-chance accuracy~\cite{dhooge2020inter,cantone2024crossdataset}. Layeghy and Portmann found that no model generalised over four NetFlow-v2 benchmarks and, from SHAP plots, that feature-value/class correspondences present in one target domain are absent in another~\cite{layeghy2022generalisability}; at score level, Jin and Lee report inverted score orientation (AUC below 0.5) under cross-dataset transfer and use $\max\{AUC,1-AUC\}$ as an oracle diagnostic~\cite{jin2026benchmark}. Both concern trained models. We ask a narrower question: whether the \emph{sign} of one fixed, interpretable feature against a named benign reference transports, and which properties of the measurement determine it. Flow construction, labeling and the exporter can change conclusions, including flows assigned the wrong direction~\cite{engelen2021troubleshooting,liu2022errorprevalence,flood2024smells,pinto2024flowexporter}; a NetFlow reflects the communication, the network and the exporter configuration~\cite{apruzzese2022cross}; synthetic benign traffic differs from real benign traffic~\cite{layeghy2024benchmarking}; and NetFlow re-exports make feature sets comparable~\cite{sarhan2021nfv2}. We show, for one feature, that such choices can change the sign and not only the magnitude of an effect. To our knowledge the sign of a fixed directional feature has not been examined as a measurement-validity question with preregistered external tests and audited follow-ups; a systematic search for prior work was not part of this study and we claim no priority.
```

**C-3. Contributions sentence (replace the list inside the Introduction):**

```latex
Our contributions are a scoped negative result on H2; two preregistered external tests with opposite verdicts, reported beside the audits that qualify them; evidence that the sign depends on the benign reference, reply composition, dependence structure and (for two labels) the representation-plus-reference pair, with UNSW-NB15 as a counterexample; an application of the standard orientation/separability distinction ($AUC_{signed}$ vs.\ $\max\{AUC,1-AUC\}$) to a fixed feature; and a labeling of every result by evidential status.
```

**C-4. Limitations additions (one sentence each; see B3–B5):**

```latex
Nine of ten CICIDS-2018 captures lack IP addresses, so the exporter's direction assignment, which is known to swap source and destination after some TCP timeouts~\cite{engelen2021troubleshooting}, could not be role-checked; orientation on the corrected CSE-CIC-IDS-2018 data~\cite{liu2022errorprevalence} was not tested; and percentile intervals from 25--40 host-pair clusters can over-reject~\cite{cameron2008bootstrap}.
```

## D. Page budget (main.tex is at 12/12)

Net additions ≈ +120 words. Candidates to cut, in order of least loss: (i) the detail sentence on H2 synthetic runs in Results; (ii) the second half of the "Implications" paragraph; (iii) the BoT-IoT flow-level CIs column in Table 1 (they are in the SM); (iv) one of the two sentences describing PCR-style directional detectors in C-1. Any cut must keep the caveats about C2, sparse slices and post-hoc status.

## E. Bibliography changes

Add (from `references_candidate.bib`): gil2001multops, jung2004portscan, bullard2014pcr, sperotto2010overview (optional), dhooge2020inter, layeghy2024benchmarking, jin2026benchmark, flood2024smells, apruzzese2022cross, cameron2008bootstrap. Optional: rfc5103, lanvin2023errors, sarhan2021netflow, sarhan2021featureanalysis, kapoor2023leakage. Remove: david2015entropy, alturki2025entropyiot (unsupported use). Already fixed in the package: sarhan2021nfv2 (Mobile Netw. Appl.), liu2022errorprevalence (pages, DOI), layeghy2022generalisability (published CEE 2023).

## F. Human verification before submission

1. Read the PDFs of Jin & Lee (2026), D'hooge et al. (2020), Layeghy & Portmann (published 2023; read 2026-10-02, no discrepancy beyond the model count), Layeghy et al. (2024; read in full 2026-10-06, claim holds with the scope noted in `verification_2026-10-02.md`), Liu et al. (2022). They were not accessible in full (403) or only read through a proxy.
2. Confirm DOIs marked "not verified" (Jung, Wang, Mai, Zhong, Peterson).
3. Locate the primary PCR source (FloCon 2014 slides) or cite the implementation as software.
4. Re-run a forward-citation search (Google Scholar, IEEE Xplore, ACM DL) on Layeghy & Portmann 2023, Jin & Lee 2026, D'hooge 2020, and Flood 2024 for 2025–2026 papers on feature-sign or score-orientation instability.
5. Confirm with the actual RFC 5103 text before quoting the answered/unanswered use case.

## G. Effect on the story

No result becomes stronger or weaker. The novelty claim narrows from "sign instability is a relational measurement issue" (which could be read as a general discovery) to "an audited measurement of the sign of one fixed feature against named references", with Layeghy & Portmann and Jin & Lee as explicit adjacent work. That is the version that survives an adversarial reviewer with the search coverage available here.
