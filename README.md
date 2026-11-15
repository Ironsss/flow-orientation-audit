# flow-orientation-audit

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24238405.svg)](https://doi.org/10.5281/zenodo.24238405)

Code, frozen plans, outputs and manuscript for the study **"The Sign of Directional Flow Asymmetry Depends on the Benign Reference and the Measurement Pipeline: Preregistered Tests and Robustness Audits in Network Intrusion Detection"**.

The study examines a fixed, interpretable directional flow feature,

`A_bytes = log(1 + bytes_forward) - log(1 + bytes_backward)`,

and asks whether the **sign** of its association with the attack label (`AUC_signed`, always relative to a *named* benign reference) transports across datasets, benign reference populations, dependence structures, reply compositions and flow representations. Orientation is kept separate from separability (`AUC_sep = max(AUC_signed, 1 - AUC_signed)`).

## Summary of results

| Question | Status | Outcome |
|---|---|---|
| H2: does graph topology degrade less than per-flow asymmetry under information restriction? | preregistered | **Rejected** (synthetic generator and one real CICIDS-2018 capture) |
| H3: does the CICIDS-2018 observation (sign varies with the attack) replicate on UNSW-NB15? | preregistered | **NO REPLICATION** |
| H3 on BoT-IoT | preregistered | **STRONG REPLICATION** by the frozen rule |
| Robustness audits A1-A4 (host-pair dependence, reply composition, CICIDS labels/reference, NetFlow-v2 re-export) | post-hoc | The BoT-IoT verdict does not support the reading it invited; only 3 of 8 evaluable groups keep a confident orientation under host-pair resampling; HOIC and Hulk reverse under the NetFlow-v2 representation-plus-reference pair |

Negative and qualifying results are kept with their numbers. Every result is labelled preregistered, exploratory or post-hoc; see `docs/methodology/CLAIMS_LEDGER.md` and `docs/reviewer_audit/AUDIT_SYNTHESIS.md`.

## Layout

| Path | Content |
|---|---|
| `src/` | Feature extractors, information-restriction operators, attribution-audit protocol, simulator, graph and model utilities |
| `scripts/` | One script per analysis (H2, UNSW-NB15, BoT-IoT, audits A1-A4, sensitivities, preflight checks) |
| `tests/` | Unit and regression tests |
| `results/` | Confirmatory and audit outputs (CSV/JSON/figures). No raw data |
| `docs/methodology/` | Frozen plans, findings, claims ledger and provenance |
| `docs/reviewer_audit/` | Protocols and reports of audits A1-A4 |
| `docs/metodologia/`, `docs/datos-reales/`, `docs/comprension-datos/` | Original methodological documents and real-data analysis (Spanish) |
| `data_manifests/` | SHA-256 manifests of the three datasets |
| `manuscript/` | Manuscript (`main.tex`), supplementary material (`supplementary.tex`), figures and `make_arxiv.py`, which builds the arXiv package (`arxiv/arxiv_submission.zip`) |
| `literature/` | Literature audit, source verification and the automatic bibliography check (`verify_bib.py`) |
| `docs/ESTADO-ACTUAL.md` | Current project status (single source of truth, Spanish) |
| `docs/ontologia/` | Concept map as an [Obsidian](https://obsidian.md) vault: open the folder as a vault. Structure only; numbers live in `docs/methodology/` |
| `PROJECT_NOTES.md` | Working notes with the project's rules and past mistakes (see note below) |

## Reproducing

1. Install: `pip install -e .` (Python >= 3.11; pinned CI dependencies are in `requirements-ci.txt`).
2. Download the datasets from their providers (not redistributed here): CICIDS-2018 / CSE-CIC-IDS2018, UNSW-NB15, BoT-IoT; verify them against `data_manifests/`. Put raw files under `data/raw/` (git-ignored).
3. Run the analysis scripts in `scripts/`; each writes to `results/`. Frozen plans are in `docs/methodology/`.
4. `pytest` and `ruff check .` should pass.

## Chronology and evidence

The "preregistered" label rests on the order freeze -> code -> single run, with the script computing the verdict. **This repository is a curated release with a condensed history.** The original development history (June-September 2026) is not reproduced here; the original commit hashes and timestamps of each freeze and run are recorded in `docs/methodology/PROVENANCE.md`. The authors keep the original repository. Commit dates in this repository are real and are not backdated.

## Note on document names

Several documents written during development refer to the project's working-notes file as `CLAUDE.md`. That file is included here as `PROJECT_NOTES.md`; the references in older documents point to it.

## Use of AI tools

During development the authors used Claude (Anthropic; Claude Code) to write and review code, tests and documentation, to draft text and to evaluate ideas, and Codex (OpenAI) as an independent reviewer of the methods. Verdicts are computed by committed scripts whose decision rules were frozen before execution. The authors reviewed the content and take responsibility for it. The manuscript contains the full declaration.

## Data and licence

The datasets belong to their providers and are not redistributed. Code and outputs: MIT licence (see `LICENSE`).

## Citation

See `CITATION.cff`. Archived release v1.0.1: [10.5281/zenodo.24238405](https://doi.org/10.5281/zenodo.24238405). The concept DOI, which always resolves to the latest version, is 10.5281/zenodo.24237993. (Release v1.0.0 was published before the history was pushed and archives only the initial commit; cite v1.0.1 or later.)

Manuscript build: `cd manuscript && pdflatex main && bibtex main && pdflatex main && pdflatex main`; arXiv package: `python manuscript/make_arxiv.py`.
