"""Builds literature_matrix.csv. Run: python build_matrix.py
Each row is a tuple in COLS order. Verification level is stated per row; nothing here was inferred from titles for HIGH-threat rows."""
# ruff: noqa: E501  (rows are data literals; reflowing them would risk changing the CSV)
import csv
import pathlib

COLS = ["id","citation","year","venue","doi_or_url","peer_reviewed","datasets","problem","feature_representation",
        "cross_dataset","common_exporter","signed_orientation_examined","separability_examined",
        "exporter_artifact_examined","benign_reference_examined","dependence_unit_examined","preregistered",
        "main_finding","overlap_with_our_work","difference_from_our_work","novelty_threat","must_cite","where_to_cite",
        "verified_from_full_text","notes"]

Y, N, P = "YES", "NO", "PARTIAL"
R = []
def add(*a):
    if len(a) != len(COLS) - 1:
        print("BAD", len(a), a[0][:50])
        return
    R.append((f"L{len(R)+1:02d}",) + a)

# ---------------- Workstream A / B: cross-dataset and the closest competitors ----------------
add("Layeghy S., Portmann M. Explainable Cross-domain Evaluation of ML-based Network Intrusion Detection Systems",
    2023, "Computers & Electrical Engineering 108:108692", "10.1016/j.compeleceng.2023.108692 (arXiv 2205.04112 'On Generalisability of ...')", Y,
    "NFv2-UNSW-NB15, NFv2-BoT-IoT, NFv2-ToN-IoT, NFv2-CSE-CIC-IDS2018", "cross-dataset failure of 8 supervised/unsupervised models; SHAP explanation",
    "common NetFlow-v2 feature set (nProbe); no single interpretable feature", Y, Y, "model level only (SHAP summary plots)", N, "indirect (feature distribution)", N, N, N,
    "None of the models generalises over all datasets; failure is asymmetric (A->B differs from B->A); SHAP plots show that the correspondence of low/high feature values with Benign/Attack (e.g. MAX_TTL) present in one target domain is absent in another",
    "Closest prior statement that the feature-label relation does not transport, on two of our datasets (UNSW-NB15, BoT-IoT) in a common exporter",
    "Model-level SHAP, not the sign of one fixed feature; no named benign reference; no reply conditioning; no dependence unit; no directional feature; no separability/orientation split; no preregistration",
    "HIGH", "YES", "Related Work; Introduction; Discussion (state that our claim is narrower)",
    P, "Full text read for the arXiv v1 (sections on SHAP summary plots, Figs 5-7). The published 2023 version is titled differently and was NOT accessible (403); re-read before submission")
add("Apruzzese G., Pajola L., Conti M. The Cross-evaluation of Machine Learning-based Network Intrusion Detection Systems",
    2022, "IEEE Transactions on Network and Service Management 19(4):5152-5169", "10.1109/TNSM.2022.3157344 (arXiv 2203.04686)", Y,
    "CTU13, UNSW-NB15, CSE-CIC-IDS2018, DDoS19; uniform re-exports (UF-*)", "framework (XeNIDS) for cross-evaluation on NetFlows; artifact control",
    "standardized NetFlow feature set; decomposes a NetFlow as F(Comm, NetId, Conf)", Y, Y, N, N, Y, "distributional shifts of benign traffic discussed", N, N,
    "Cross-evaluation is hazardous because a NetFlow reflects the communication plus the environment (NetId) and the exporter configuration (Conf); models trained on one dataset fail on another",
    "Conceptually the same separation we need: behaviour vs. dataset-as-instrument (Comm vs Env/Conf)",
    "Performance-level framework; does not measure the sign of any feature; no reply/dependence/benign-reference audit",
    "HIGH", "YES", "Related Work (artifacts/exporter); Discussion (Comm vs Env framing)", Y,
    "Full text extracted and grepped. An automated summariser had claimed 'sign/direction inconsistencies'; the text does NOT support that claim (do not repeat it)")
add("Jin H., Lee H. Benchmark-Shift-Aware Intrusion Detection for Evolving Network Traffic: Cross-Dataset Generalization, Calibrated Alerting, and Score-Orientation Diagnostics",
    2026, "Electronics (MDPI) 15(17):3761", "https://www.mdpi.com/2079-9292/15/17/3761", Y,
    "HIKARI-2021, CICIDS2017, CICIoT2023 (sample)", "cross-dataset transfer; calibration; threshold transfer; score-orientation stability",
    "two harmonised payload-free feature spaces (Rich-64, Minimal-13); XGBoost and Transformers", Y, N, Y, P, N, N, N, N,
    "Under strict transfer HIKARI-2021 -> CICIDS2017 some detectors show inverted score orientation (AUC<0.5, negative AP-lift); an 'oracle-flipped' AUC = max(AUC, 1-AUC) is used as a diagnostic",
    "Nearest competitor for 'orientation can invert under cross-dataset transfer' and for the AUC_sep = max(AUC, 1-AUC) device",
    "Orientation of a model score, not of one fixed interpretable feature; no named benign reference, reply composition, dependence unit or exporter/representation audit; explicitly no feature-level sign analysis",
    "HIGH", "YES", "Related Work (cross-dataset); Discussion (orientation vs separability is not new at score level)", P,
    "Page returned 403 from the publisher; content read through a text proxy + summariser. Re-read the PDF manually before citing details. Very recent (2026): check for later versions")
add("D'hooge L., Wauters T., Volckaert B., De Turck F. Inter-dataset generalization strength of supervised machine learning methods for intrusion detection",
    2020, "Journal of Information Security and Applications 54:102564", "10.1016/j.jisa.2020.102564", Y,
    "CIC-IDS2017, CSE-CIC-IDS2018", "inter-dataset generalisation of supervised methods", "CICFlowMeter features", Y, N, N, N, N, N, N, N,
    "Great intra-dataset scores do not imply inter-dataset generalisation (abstract-level)",
    "JISA precedent on transport failure of classifiers", "Classifier performance; no feature sign", "MEDIUM", "YES",
    "Related Work (cross-dataset); cover letter (JISA fit)", N, "Publisher page not accessible; metadata and abstract only")
add("Cantone M., Marrocco C., Bria A. Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study",
    2024, "IEEE Access 12:144489-144508", "10.1109/ACCESS.2024.3472907 (arXiv 2402.10974)", Y,
    "CIC-IDS-2017, CSE-CIC-IDS2018, LycoS-IDS2017, LycoS-Unicas-IDS2018", "cross-dataset generalisation; corrected CSE-CIC-IDS2018", "CICFlowMeter features; 4 classifiers", Y, N, N, N, P, N, N, N,
    "Near-perfect in-dataset, near-chance cross-dataset accuracy except few attack/dataset pairs; visualisation of data patterns; corrections applied to CSE-CIC-IDS2018",
    "Already cited; corroborates transport failure", "Performance-level; no per-feature sign", "MEDIUM", "YES", "Related Work", P,
    "Abstract and introduction read from arXiv text; no dedicated feature-sign analysis found by keyword scan")
add("Guo X.F., Meroño Peñuela A., Maffeis S., Pierazzi F. KnowML: Improving Generalization of ML-NIDS with Attack Knowledge Graphs",
    2025, "arXiv:2506.19802 (preprint)", "https://arxiv.org/abs/2506.19802", N, "multiple NIDS datasets", "generalisation across attack variants", "knowledge-guided features", P, N, N, N, N, N, N, N,
    "Homogeneous datasets inflate performance; attack knowledge improves generalisation", "Context only", "Method paper", "LOW", "NO", "optional", P, "Abstract only")
add("Hesford J. et al. Expectations Versus Reality: Evaluating Intrusion Detection Systems in Practice",
    2024, "arXiv:2403.17458 (preprint)", "https://arxiv.org/abs/2403.17458", N, "BoT-IoT, Stratosphere IoT and others", "empirical comparison of IDSs", "various", P, N, N, N, N, N, N, N,
    "No IDS is best across datasets; depends on attack type and environment", "Context: environment dependence", "Model comparison", "LOW", "NO", "optional", P, "Abstract only")
add("Nougnanke B., Blanc G., Robert T. How Dataset Diversity Affects Generalization in ML-Based NIDS",
    2025, "ESORICS 2025, LNCS 16053:269-288", "10.1007/978-3-032-07884-1_14", Y, "CIC-IDS2018", "diversity (intra-class, inter-class, domain shift) vs generalisation", "Vendi score, JS divergence", P, N, N, N, N, N, N, N,
    "Relates diversity measures to generalisation over 60 controlled train-test experiments", "Recent generalisation work (2025)", "Diversity metrics, one dataset", "LOW", "NO", "Related Work (optional)", N, "Metadata and abstract only")
add("Anser O., François J., Chrisment I., Kondo D. TATA: Benchmark NIDS Test Sets Assessment and Targeted Augmentation",
    2025, "ESORICS 2025 (LNCS)", "10.1007/978-3-032-07884-1_2", Y, "CIC-IDS2017, CSE-CIC-IDS2018", "quality of benchmark test sets", "latent-space metrics", N, N, N, N, N, N, N, N,
    "Test-set quality metrics correlate with detection difficulty", "Benchmark quality context", "Test-set augmentation", "LOW", "NO", "optional", N, "Metadata and abstract only")

# ---------------- Workstream C: dataset, labelling and exporter artifacts ----------------
add("Flood R., Engelen G., Aspinall D., Desmet L. Bad Design Smells in Benchmark NIDS Datasets",
    2024, "IEEE EuroS&P 2024, pp. 658-675 (Distinguished Paper)", "10.1109/EuroSP60621.2024.00042", Y,
    "7 datasets incl. CIC-IDS2017/2018, UNSW-NB15, BoT-IoT, TON_IoT", "six 'data design smells'; impact on downstream studies", "flow features (e.g. Total Source/Destination Bytes used as a probe)", N, N, N, N, Y, P, N, N,
    "Features of outsized importance unrelated to attack mechanism (e.g. TTL/RTT in UNSW-NB15; init-window bytes in CIC18); traffic collapse; artificial diversity; mislabels; replaying results shows conclusions of published papers depend on these artifacts",
    "Supports the reading that a feature's behaviour can be a property of the dataset-as-instrument (fingerprint, testbed layout) rather than of the attack",
    "No sign/orientation analysis and no directional feature; no reply conditioning; no named-reference or dependence-unit audit",
    "MEDIUM", "YES", "Related Work (artifacts); Discussion; Limitations", Y, "Full text extracted; sections on UNSW/CIC examples read; byte features appear only as probes (Fig 5)")
add("Engelen G., Rimmer V., Joosen W. Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study",
    2021, "IEEE SPW (WTMC) 2021, pp. 7-12", "10.1109/SPW53761.2021.00009", Y, "CIC-IDS2017", "flow-construction and labelling errors (CICFlowMeter)", "CICFlowMeter flows", N, N, N, N, Y, N, N, N,
    "Documents CICFlowMeter construction and labelling bugs; corrected dataset changes results. Verified in the full text: after a TCP-appendix timeout the subsequent flow can go in the wrong direction (Source and Destination swapped), and the labelling relies on correct direction; Web-attack and Bot flows include many with no forward data transfer (attempted attacks)", "Directly relevant to the SIGN of a forward/backward feature: exporter bugs can swap direction. Underpins A3/A4 caution and the unverifiable source-endpoint rule for CICIDS",
    "No feature-sign analysis; our role check cannot cover CICIDS because 9 of 10 captures lack IP addresses", "MEDIUM", "YES", "Related Work (artifacts); Limitations (source-endpoint semantics)", Y, "Full text extracted (5.7k words); direction-swap and no-forward-data passages read directly. Strong support for treating CICFlowMeter direction as unreliable and for the zero-payload HOIC/Hulk records in A4")
add("Liu L., Engelen G., Lynar T., Essam D., Joosen W. Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018",
    2022, "IEEE CNS 2022, pp. 254-262", "10.1109/CNS56114.2022.9947235", Y, "CIC-IDS-2017, CSE-CIC-IDS-2018", "errors in attack orchestration, feature generation, labelling; corrected recreation", "CICFlowMeter", N, N, N, N, Y, N, N, N,
    "Large number of previously undocumented errors in CSE-CIC-IDS-2018; corrected version released", "Our discovery dataset (CSE-CIC-IDS-2018) has documented errors",
    "No sign analysis. Our results use the original labels and NF-v2 re-export: must state that the corrected version was not used", "MEDIUM", "YES", "Related Work; Limitations", N, "Metadata and abstract only")
add("Lanvin M., Gimenez P.-F., Han Y., Majorczyk F., Mé L., Totel E. Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes",
    2023, "CRiSIS 2022, LNCS 13857:18-33", "10.1007/978-3-031-31108-6_2", Y, "CIC-IDS2017", "misordered packets, timestamps, duplicated traffic, mislabels", "CICFlowMeter", N, N, N, N, Y, N, N, N,
    "Fixing errors changes detection performance", "Artifact evidence", "CIC-IDS2017 only", "LOW", "NO", "Related Work (optional)", N, "Metadata and abstract only")
add("Kenyon A., Deka L., Elizondo D. Are public intrusion datasets fit for purpose: characterising the state of the art in intrusion event datasets",
    2020, "Computers & Security 99:102022", "10.1016/j.cose.2020.102022", Y, "many", "dataset quality survey", "n/a", N, N, N, N, P, N, N, N,
    "Survey of dataset fitness", "Context", "Survey", "LOW", "NO", "optional", N, "Metadata only")
add("Layeghy S., Gallagher M., Portmann M. Benchmarking the benchmark: comparing synthetic and real-world Network IDS datasets",
    2024, "Journal of Information Security and Applications 80:103689", "10.1016/j.jisa.2023.103689 (arXiv 2104.09029)", Y,
    "CIC-IDS2017, UNSW-NB15, TON_IoT vs two real NetFlow datasets", "statistical properties of benign traffic: synthetic vs real", "9 traffic features (duration, size, ports, addresses)", P, N, N, N, N, Y, N, N,
    "Synthetic benign traffic differs significantly from real-world benign traffic for most features; the two real datasets are mutually similar",
    "JISA paper supporting the premise that the benign reference of a benchmark is itself a property of the testbed",
    "Marginal feature distributions only; no attack-vs-benign orientation; no directional feature", "MEDIUM", "YES", "Related Work; Discussion (reference population)", P,
    "arXiv 2021 version read (abstract, Sec. 1-3); journal version details not checked")
add("Pinto D., Vitorino J., Maia E., Amorim I., Praça I. Flow Exporter Impact on Intelligent Intrusion Detection Systems",
    2025, "ICISSP 2025 (arXiv 2412.14021)", "https://arxiv.org/abs/2412.14021", Y, "CIC-IDS2017 and UNSW-NB15 re-exported from the same PCAPs with different exporters (HERA tools)", "does the flow exporter change ML results on identical traffic?", "same PCAP, different exporters", N, N, N, N, Y, N, N, N,
    "Datasets derived from the same PCAP by different exporters give different performance/reliability; some exporters add flows (e.g. Zeek/BRO adds malicious traffic)",
    "Direct precedent for A4 (same traffic, different representation)", "Performance-level; no orientation; no benign-reference or reply audit", "MEDIUM", "YES",
    "Related Work (artifacts); A4 discussion", Y, "Full text extracted; exporter comparison and Table on flow counts read")
add("Sarhan M., Layeghy S., Moustafa N., Portmann M. NetFlow Datasets for Machine Learning-based Network Intrusion Detection Systems",
    2021, "BDTA/WiCON 2020, LNICST 371, Springer", "10.1007/978-3-030-72802-1_9 (arXiv 2011.09144)", Y, "UNSW-NB15, BoT-IoT, ToN-IoT, CSE-CIC-IDS2018 (+NF-UQ-NIDS)", "common NetFlow re-export with nProbe", "NetFlow v9 feature set", Y, Y, N, N, P, N, N, N,
    "Provides NF-* datasets from the original PCAPs with a common NetFlow feature set", "Source of common-exporter re-exports; v2 files used in our A4",
    "Dataset paper; no sign analysis", "MEDIUM", "YES", "Methods (A4 data); Related Work", N, "Metadata and abstract only")
add("Sarhan M., Layeghy S., Portmann M. Towards a Standard Feature Set for Network Intrusion Detection System Datasets",
    2022, "Mobile Networks and Applications 27(1):357-370", "10.1007/s11036-021-01843-0 (arXiv 2101.11315)", Y, "UNSW-NB15, BoT-IoT, ToN-IoT, CSE-CIC-IDS2018", "proposes a NetFlow-based standard feature set (43 features)", "NetFlow (IN_BYTES, OUT_BYTES, ...)", Y, Y, N, N, P, N, N, N,
    "Standard feature set makes cross-dataset ML evaluation possible; datasets otherwise have unique proprietary feature sets", "Defines IN_BYTES/OUT_BYTES used in A4's NF-v2 representation",
    "No sign analysis", "MEDIUM", "YES", "Methods; Related Work (already cited)", P, "arXiv v2 read (abstract and feature table)")
add("Sarhan M., Layeghy S., Portmann M. Evaluating Standard Feature Sets Towards Increased Generalisability and Explainability of ML-based Network Intrusion Detection",
    2022, "Big Data Research 30:100359", "10.1016/j.bdr.2022.100359 (arXiv 2104.07183)", Y, "CSE-CIC-IDS2018, BoT-IoT, ToN-IoT, UNSW-NB15 (NetFlow vs CICFlowMeter features)", "generalisability of two feature sets + global SHAP", "NetFlow vs CICFlowMeter features", Y, Y, N, N, P, N, N, N,
    "NetFlow feature set improves detection and generalisation; Shapley values used to interpret feature impact across datasets",
    "Feature-impact comparison across datasets at model level", "Model-level SHAP; no per-feature sign of a fixed feature", "MEDIUM", "YES", "Related Work", P, "Abstract and structure read; SHAP sections keyword-scanned (no sign-reversal statement found)")
add("Sarhan M., Layeghy S., Portmann M. Feature Analysis for Machine Learning-based IoT Intrusion Detection",
    2021, "arXiv:2108.12732 (preprint)", "https://arxiv.org/abs/2108.12732", N, "UNSW-NB15, ToN-IoT and NetFlow variants, others", "feature selection and rankings across datasets", "feature rankings; single-feature AUC of TTL features", Y, P, N, N, Y, N, N, N,
    "A single TTL-based feature reaches near-maximal AUC in UNSW-NB15; authors attribute this to the testbed design (placement of attack and victim nodes), not to attack behaviour; feature ranks differ strongly between original and NetFlow variants",
    "Precedent for a testbed artifact driving a single-feature AUC", "Model-based AUC of feature subsets; no sign", "MEDIUM", "YES", "Related Work; Discussion", Y, "Text extracted; TTL passage read")
add("Luay M., Layeghy S., Hosseininoorbin S., Sarhan M., Moustafa N., Portmann M. Temporal Analysis of NetFlow Datasets for Network Intrusion Detection Systems",
    2025, "arXiv:2503.04404 (preprint)", "https://arxiv.org/abs/2503.04404", N, "NF-UNSW-NB15, NF-BoT-IoT, NF-ToN-IoT, NF-CSE-CIC-IDS2018 (temporal versions)", "temporal features and distributions in NetFlow datasets", "NetFlow with IAT and duration", Y, Y, N, N, P, N, N, N,
    "Distributions of NetFlow features (including IN_BYTES/OUT_BYTES over time) differ across datasets and attacks", "Feature-distribution comparison in common exporter", "No sign analysis", "LOW", "NO", "optional", P, "Text extracted; only keyword-scanned")
add("Wilkinson M., Thomson R.H. What Does Normal Even Mean? Evaluating Benign Traffic in Intrusion Detection Datasets",
    2025, "arXiv:2509.09564 (SBP-BRiMS 2025 poster)", "https://arxiv.org/abs/2509.09564", N, "NSL-KDD, UNSW-NB15, CIC-IDS 2017", "structure of the benign class", "clustering (HDBSCAN, mean shift)", N, N, N, N, Y, N, N, N,
    "Most papers accept the single benign class at face value; unsupervised clustering shows structure inside benign traffic", "Supports treating the benign reference as heterogeneous", "Poster; clustering, not orientation", "LOW", "NO", "Related Work (one clause)", P, "Abstract read; results not evaluated")
add("Peterson J.M., Leevy J.L., Khoshgoftaar T.M. A Review and Analysis of the Bot-IoT Dataset",
    2021, "IEEE SOSE 2021", "DOI not verified (IEEE SOSE 2021)", Y, "BoT-IoT", "dataset review, data-quality issues", "features", N, N, N, N, N, N, N, N,
    "Documents pitfalls (missing values, ports) of BoT-IoT", "BoT-IoT quality", "No benign-reference or orientation analysis", "LOW", "NO", "Limitations (optional)", N, "Metadata and snippet only; DOI not confirmed")

# ---------------- Workstream B: directional / asymmetry features (origins) ----------------
add("Gil T.M., Poletto M. MULTOPS: a data-structure for bandwidth attack detection",
    2001, "USENIX Security Symposium 2001", "https://www.usenix.org/conference/10th-usenix-security-symposium/multops-data-structure-bandwidth-attack-detection", Y, "none (design + simulation)", "flood detection from disproportion between packet rates in the two directions", "packet-rate ratio per subnet prefix", N, N, N, N, N, N, N, N,
    "Under normal operation the packet rates in the two directions are proportional; a disproportion flags a bandwidth attack",
    "Canonical directional-asymmetry detector; replaces our current Introduction citations for 'asymmetry as a detection signal'", "No dataset transport question", "MEDIUM", "YES", "Introduction; Related Work (directional features)", N, "Search-result abstract only")
add("Bullard C., Gerth J. Producer Consumer Ratio (PCR)",
    2014, "FloCon 2014 (presentation; Argus/Zeek implementations)", "https://github.com/reservoirlabs/bro-producer-consumer-ratio", N, "n/a", "host-level directionality of application data transfer", "PCR = (bytes sent - bytes received)/(bytes sent + bytes received)", N, N, N, N, N, N, N, N,
    "A normalised value in [-1, 1] indicating directionality of information transfer, independent of load; used for data-staging/exfiltration",
    "Same idea as the sign of A_bytes (per host instead of per flow)", "Not peer reviewed; host-level; no dataset-transport evaluation", "MEDIUM", "YES (with caveat)", "Introduction; Related Work (directional features)", N,
    "Only secondary descriptions (blog, mailing list, GitHub) were found; the primary FloCon slides were not located. Cite as a presentation or via the implementation")
add("Jung J., Paxson V., Berger A.W., Balakrishnan H. Fast portscan detection using sequential hypothesis testing",
    2004, "IEEE Symposium on Security and Privacy 2004", "DOI not verified (IEEE S&P 2004)", Y, "LBL and ICSI traces", "scan detection from failed/successful connection outcomes", "connection outcome (reply vs no reply)", N, N, N, N, N, N, N, N,
    "Benign and scanning hosts differ in the fraction of connection attempts that get a reply", "Reply presence as the core of scan detection (matches our 'unanswered' analysis)", "Host-level; no transport question", "LOW", "YES", "Introduction; Discussion (reply composition)", N, "Search-result abstract only; DOI not confirmed")
add("Wang H., Zhang D., Shin K.G. Detecting SYN flooding attacks",
    2002, "IEEE INFOCOM 2002", "DOI not verified (IEEE INFOCOM 2002)", Y, "traces", "SYN flood detection from SYN-FIN(RST) pair behaviour", "protocol pairing", N, N, N, N, N, N, N, N,
    "Protocol-level asymmetry between SYN and FIN/RST counts detects floods", "Protocol basis for unanswered-flood asymmetry", "No dataset transport", "LOW", "NO", "optional", N, "Search-result abstract only; DOI not confirmed")
add("Sperotto A., Schaffrath G., Sadre R., Morariu C., Pras A., Stiller B. An Overview of IP Flow-Based Intrusion Detection",
    2010, "IEEE Communications Surveys & Tutorials 12(3)", "10.1109/SURV.2010.032210.00054", Y, "n/a", "survey of flow-based detection of scans, worms, botnets, DoS", "flow records", N, N, N, N, P, N, N, N,
    "Reviews flow definitions and detection techniques", "Background for directional flow features", "Survey", "LOW", "YES", "Introduction; Related Work", N, "Abstract only")
add("Trammell B., Boschi E. RFC 5103: Bidirectional Flow Export Using IP Flow Information Export (IPFIX)",
    2008, "IETF RFC 5103", "https://www.rfc-editor.org/rfc/rfc5103", N, "n/a", "biflow record semantics (forward/reverse)", "IPFIX biflow", N, N, N, N, Y, N, N, N,
    "Defines how forward/reverse counters of a biflow are exported; notes use cases such as separating answered and unanswered TCP requests",
    "Normative source for forward/backward semantics and for answered/unanswered separation", "Standard, not a study", "LOW", "YES", "Methods (feature semantics); Limitations", N, "Search-result description only; read the RFC text before quoting")
add("David J., Thomas C. DDoS Attack Detection Using Fast Entropy Approach on Flow-Based Network Traffic",
    2015, "Procedia Computer Science 50:30-36", "10.1016/j.procs.2015.04.007", Y, "n/a", "DDoS detection by fast entropy of flow counts", "entropy of requests per flow", N, N, N, N, N, N, N, N,
    "Entropy of flow count with an adaptive threshold detects DDoS", "None on directional asymmetry", "Not about sent/received asymmetry", "LOW", "NO", "REPLACE in Introduction", P,
    "CURRENT MANUSCRIPT CITES THIS AS SUPPORT FOR 'directional asymmetry recurs as a detection signal'. The abstract describes entropy of flow counts, not directionality. Do not use it for that claim")
add("Alturki N. et al. Semi-Supervised Learning with Entropy Filtering for Intrusion Detection in Asymmetrical IoT Systems",
    2025, "Symmetry 17(6):973", "10.3390/sym17060973", Y, "RT-IoT2022, CICIoT2023, CICIoMT2024", "semi-supervised IDS with entropy-based uncertainty filtering", "tree-based classifiers", N, N, N, N, N, N, N, N,
    "'Asymmetrical' refers to heterogeneous IoT devices/communication flows; method filters uncertain predictions by entropy", "None on sent/received asymmetry",
    "Not about directional flow asymmetry", "LOW", "NO", "REPLACE in Introduction", P,
    "CURRENT MANUSCRIPT CITES THIS AS 'asymmetry-aware IoT learning'. The verified description does not concern directional byte asymmetry; the citation is misleading")
add("Akoglu L., Tong H., Koutra D. Graph based anomaly detection and description: a survey",
    2015, "Data Mining and Knowledge Discovery 29(3)", "10.1007/s10618-014-0365-y", Y, "n/a", "graph anomaly detection survey", "graphs", N, N, N, N, N, N, N, N, "Survey of graph anomaly detection", "Context for H2 (topology)", "Not directional", "LOW", "YES", "Related Work (H2)", N, "Not re-verified in this phase")
add("Zhong M. et al. A survey on graph neural networks for intrusion detection systems: methods, trends and challenges",
    2024, "Computers & Security", "DOI not verified (see manuscript references.bib)", Y, "n/a", "GNN-IDS survey", "graphs", N, N, N, N, N, N, N, N, "Survey", "Context for H2", "Not directional", "LOW", "YES", "Related Work (H2)", N, "Not re-verified in this phase; DOI unconfirmed")

# ---------------- Workstream A/B adjacent: score-direction and shift ----------------
add("Ascarate A., Lebrat L., Santa Cruz R., Fookes C., Salvado O. Testing the Test: Score-Direction Instability in Class-Split Anomaly Detection",
    2026, "arXiv:2606.02601 (preprint)", "https://arxiv.org/abs/2606.02601", N, "Fashion-MNIST, CIFAR-10, ImageNette, SVHN, ImageNet (not network data)", "score direction can collapse or invert when the held-out class overlaps normal data", "anomaly scores in pixel/VAE spaces", P, N, Y, N, N, N, N, N,
    "The preferred score direction depends on the (unknown) anomaly class; AUROC can invert", "General precedent that 'which direction means anomalous' is not fixed", "Images, not networks; class-split protocol", "LOW", "NO",
    "Discussion (optional; general ML precedent)", P, "Abstract and introduction read; not about NIDS")
add("Bouke M.A., Sayeed M.S., Heng S.-H., Abdullah A., Othman M. Multi-Level Distributional Entropy for Explainable Network Intrusion Detection",
    2026, "arXiv:2606.29797 (preprint)", "https://arxiv.org/abs/2606.29797", N, "KDD99, CIC-IDS2018, UNSW-NB15", "entropy features and attribution consistency", "entropy features", P, N, N, N, N, N, N, N,
    "Assesses attribution consistency of entropy features across datasets", "Search hit for feature-attribution consistency", "Excerpt read did not show a sign analysis", "LOW", "NO", "none", P, "Text extracted; no result on direction/sign of a feature found in the excerpt")

# ---------------- Workstream D: prereg / reproducibility / sampling / dependence ----------------
add("Sommer R., Paxson V. Outside the Closed World: On Using Machine Learning for Network Intrusion Detection",
    2010, "IEEE Symposium on Security and Privacy 2010", "10.1109/SP.2010.25", Y, "n/a", "why ML-NIDS fails in the field", "n/a", P, N, N, N, N, N, N, N, "Closed-world benchmark results do not transfer; call for realistic evaluation", "Already cited; generic context", "Position paper", "LOW", "YES", "Introduction; Related Work", N, "Already in bibliography")
add("Arp D. et al. Dos and Don'ts of Machine Learning in Computer Security",
    2022, "USENIX Security 2022, pp. 3971-3988", "https://www.usenix.org/conference/usenixsecurity22/presentation/arp", Y, "n/a", "ten recurring pitfalls in ML security papers", "n/a", N, N, N, N, N, N, N, N, "Documents pitfalls incl. sampling bias, data snooping, spurious correlations", "Framework for our evidential-status labelling", "General", "LOW", "YES", "Related Work; Methods (status)", N, "Already in bibliography")
add("Pendlebury F. et al. TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time",
    2019, "USENIX Security 2019", "https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury", Y, "Android malware", "spatial and temporal experimental bias", "n/a", P, N, N, N, N, N, N, N, "Spatial bias (unrepresentative distributions) inflates results", "Concept of spatial bias", "Malware, not flows", "LOW", "NO", "optional", N, "Metadata and abstract only")
add("Kapoor S., Narayanan A. Leakage and the reproducibility crisis in machine-learning-based science",
    2023, "Patterns 4(9):100804", "10.1016/j.patter.2023.100804", Y, "n/a", "leakage taxonomy, reproducibility", "n/a", N, N, N, N, N, N, N, N, "Leakage affects at least 294 papers in 17 fields", "Reproducibility context", "General", "LOW", "NO", "optional", N, "Metadata and abstract only")
add("Nosek B.A., Ebersole C.R., DeHaven A.C., Mellor D.T. The preregistration revolution",
    2018, "PNAS 115(11):2600-2606", "10.1073/pnas.1708274114", Y, "n/a", "confirmatory vs exploratory analysis", "n/a", N, N, N, N, N, N, N, Y, "Preregistration distinguishes confirmatory from exploratory analyses", "Already cited", "General science", "LOW", "YES", "Methods", N, "Already in bibliography. Do NOT claim the freeze protocol is novel")
add("Field C.A., Welsh A.H. Bootstrapping clustered data",
    2007, "Journal of the Royal Statistical Society B 69(3):369-390", "10.1111/j.1467-9868.2007.00593.x", Y, "n/a", "cluster bootstrap consistency", "cluster (host-pair) resampling", N, N, N, N, N, N, Y, N, "Cluster bootstrap is consistent under both the transformation and random-effect models", "Statistical basis for the host-pair bootstrap", "Statistics", "LOW", "YES", "Methods (A1); Discussion (inferential unit)", N, "Abstract only")
add("Cameron A.C., Gelbach J.B., Miller D.L. Bootstrap-based improvements for inference with clustered errors",
    2008, "Review of Economics and Statistics 90(3):414-427", "10.1162/rest.90.3.414", Y, "n/a", "inference with few clusters", "cluster bootstrap-t", N, N, N, N, N, N, Y, N, "Standard cluster-robust tests over-reject with 5-30 clusters; bootstrap-t refines", "Supports the few-clusters caveat (32 host pairs per group)", "Econometrics", "LOW", "YES", "Limitations", N, "Abstract only")
add("Brauckhoff D., Tellenbach B., Wagner A., May M., Lakhina A. Impact of packet sampling on anomaly detection metrics",
    2006, "ACM IMC 2006", "10.1145/1177080.1177101", Y, "traces", "how packet sampling changes anomaly-detection metrics", "byte/packet/flow counts, entropy", N, N, N, N, P, N, N, N, "Sampling leaves byte and packet volume metrics roughly intact but biases flow counts; entropy is less affected", "Context for H2 sampling operator", "Not about datasets", "LOW", "NO", "Related Work (H2, optional)", N, "Search-result abstract only")
add("Mai J., Chuah C.-N., Sridharan A., Ye T., Zang H. Is sampled data sufficient for anomaly detection?",
    2006, "ACM IMC 2006", "DOI not verified (ACM IMC 2006)", Y, "Tier-1 backbone traces", "effect of sampling on anomaly detection", "packet/flow sampling", N, N, N, N, P, N, N, N, "Examines four sampling methods and their effect on detection features", "Context for H2", "Not about datasets", "LOW", "NO", "Related Work (H2, optional)", N, "Search-result abstract only; DOI not confirmed")

# ---------------- Dataset papers (needed to cite) ----------------
add("Sharafaldin I., Lashkari A.H., Ghorbani A.A. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization",
    2018, "ICISSP 2018", "10.5220/0006639801080116", Y, "CIC-IDS2017 / CSE-CIC-IDS2018", "dataset", "CICFlowMeter", N, N, N, N, N, N, N, N, "Dataset paper", "Dataset provenance", "-", "LOW", "YES", "Methods", N, "Already in bibliography")
add("Moustafa N., Slay J. UNSW-NB15: a comprehensive data set for network intrusion detection systems",
    2015, "MilCIS 2015", "10.1109/MilCIS.2015.7348942", Y, "UNSW-NB15", "dataset", "Argus + Bro", N, N, N, N, N, N, N, N, "Dataset paper", "Dataset provenance", "-", "LOW", "YES", "Methods", N, "Already in bibliography")
add("Koroniotis N., Moustafa N., Sitnikova E., Turnbull B. Towards the development of realistic botnet dataset in the Internet of Things for network forensic analytics: Bot-IoT dataset",
    2019, "Future Generation Computer Systems 100:779-796", "10.1016/j.future.2019.05.041", Y, "BoT-IoT", "dataset", "Argus", N, N, N, N, N, N, N, N, "Dataset paper", "Dataset provenance", "-", "LOW", "YES", "Methods", N, "Already in bibliography")

with open(pathlib.Path(__file__).with_name("literature_matrix.csv"), "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(COLS)
    w.writerows(R)
print(len(R), "rows")
