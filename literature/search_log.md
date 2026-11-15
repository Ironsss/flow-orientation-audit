# Search log and coverage (2026-09-28)

**Tools:** general web search (results are aggregations, not a citation index), arXiv PDFs, publisher pages (many returned 403), one text proxy (r.jina.ai) for one MDPI page. **Not used:** Google Scholar, IEEE Xplore, ACM DL, Scopus, forward-citation crawls. Therefore priority claims cannot be supported.

## Queries run (abridged, grouped by workstream)

- **A. Cross-dataset / generalisation:** D'hooge JISA 2020; Apruzzese TNSM 2022; Layeghy JISA 2024; Layeghy & Portmann CEE 2023; Cantone IEEE Access 2024; "How dataset diversity affects generalization" (ESORICS 2025); TATA (ESORICS 2025); Hesford 2024; concept shift vs covariate shift in NIDS.
- **B. Sign / orientation:** feature effect reverses sign across datasets (SHAP); inverted AUC < 0.5 cross-dataset; "score orientation", "polarity"; Simpson's paradox / benign reference; byte-asymmetry features across CIC-IDS2017/UNSW-NB15; upload/download ratio and asymmetry in DDoS/botnet flow features; Producer–Consumer Ratio; MULTOPS; SYN-FIN pairs; TRW scan detection; RFC 5103; Sperotto survey.
- **C. Artifacts / exporters:** Engelen 2021; Liu 2022; Lanvin 2023; Kenyon 2020; Flood 2024; Pinto 2025; Sarhan NetFlow datasets / standard feature set / feature analysis / SHAP; Luay temporal; BoT-IoT review (Peterson); benign-traffic heterogeneity (Wilkinson & Thomson); sampling (Brauckhoff; Mai).
- **D. Prereg / repro / statistics:** Kapoor & Narayanan; TESSERACT; Field & Welsh; Cameron–Gelbach–Miller; Nosek (already cited).
- **Own bibliography check:** the meaning of "asymmetrical" in Alturki et al. 2025 and the content of David & Thomas 2015 (both found unrelated to directional asymmetry).

## Full-text handling

Downloaded PDFs were converted with `pdftotext` into `_fulltext/` (local only, not committed: copyright and size). Passages were read by keyword scan (`opposite|revers|invert|sign|direction|asymmetr|IN_BYTES|OUT_BYTES|SHAP|benign|exporter`) and by reading the surrounding paragraphs. An LLM summariser used on some PDFs produced at least one claim not present in the text (Apruzzese); every statement in the audit that matters was checked against extracted text where the PDF was available, and the matrix says where it was not.

## Known gaps

D'hooge 2020, Liu 2022, Layeghy & Portmann (published), Layeghy 2024 (published), Jin & Lee 2026 (only via proxy), Kenyon 2020, Sperotto 2010, Gil & Poletto 2001 (abstract-level). The primary PCR source. Forward citations of the closest papers. Non-English literature.
