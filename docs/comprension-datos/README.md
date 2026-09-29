# Guía de comprensión de datos — CICIDS-2018

Documento pedagógico, separado de `docs/datos-reales/` (que es hallazgos de
investigación): asume que quien lo lee **no conoce CICIDS-2018**, y explica qué es, cómo
se genera, qué significa cada familia de columnas, y qué gotchas reales tiene — sin
pretender aportar un hallazgo nuevo.

## Contenido

- **`GUIA-CICIDS-2018.tex`** / **`GUIA-CICIDS-2018.pdf`** — el documento completo.

## Metodología

Reusa números y figuras ya generados por `scripts/analyze_real_data.py` y
`scripts/explore_real_data_structure.py` contra los archivos reales en `data/raw/` — no
introduce un tercer script de análisis, salvo la función `annotated_sample_flow()` (ya en
`scripts/explore_real_data_structure.py`) para extraer un flujo real anotado.

## Recompilar

```bash
cd docs/comprension-datos && pdflatex GUIA-CICIDS-2018.tex && pdflatex GUIA-CICIDS-2018.tex
```
