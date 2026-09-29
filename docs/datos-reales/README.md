# Análisis estadístico de datos reales

Primer análisis estadístico del proyecto sobre datos reales de CICIDS-2018, no
sintéticos. Hasta esta sesión, todo lo que el repositorio documentaba sobre comportamiento
de features, AUC de asimetría per-flujo, y criterios de Fase 0 venía de
`src/simulator/agents.py`.

## Contenido

- **`ANALISIS-DATOS-REALES.tex`** / **`ANALISIS-DATOS-REALES.pdf`** — el documento completo.
- Generado por `scripts/analyze_real_data.py`, corrido contra los dos archivos reales
  descargados en esta sesión (`data/raw/`, gitignored). Salida completa en
  `results/metrics/real_data_summary.json`.

## Metodología

Todos los números citados fueron generados ejecutando el código del repositorio contra los
archivos reales, no leídos de la documentación ni reproducidos de memoria — mismo criterio
que `docs/review/README.md`.

## Resumen de hallazgos (para no tener que abrir el PDF)

| # | Hallazgo |
|---|---|
| 1 | **Bug real encontrado y corregido** (PR #17): headers duplicados incrustados en `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` corrompían la inferencia de tipos de `load_csv()` — las 49 `CLASSIC_FEATURES` se leían como `String`, no numéricas. `_clean_data()` sólo limpia columnas numéricas, así que su limpieza de infinitos/NaN nunca corría sobre este archivo. |
| 2 | 1.085 / 2.919 infinitos reales (`flow_byts_per_s` / `flow_pkts_per_s`) antes de limpiar — división por duración cero, no un artefacto de parseo. |
| 3 | 24/49 `CLASSIC_FEATURES` son direccionales, confirmado con datos reales (no sólo por nombre de columna); sólo `bwd_psh_flags` resultó degenerada. |
| 4 | **El contraste central**: AUC per-flujo real = **0.537** en Infiltración (vs. 0.587–0.686 documentado sobre el *simulador*) y **0.381** en DDoS-LOIC-HTTP (vs. 0.9464 documentado) — en DDoS la dirección del efecto se invierte respecto al supuesto del simulador, no sólo se debilita. |
| 5 | El único archivo del bucket con IPs no cumple los criterios cuantitativos de Fase 0 en el punto (60s) que `preflight_data.py` probaba, pero un barrido `window`×`τ` muestra que `window=10s` sí cumple el criterio 3 y que el criterio 4 queda cerca (8.8–9.8% vs. 10%) en todo el rango — no es el fracaso categórico que parecía. |
| 6 | El AUC a nivel de ventana de la topología (0.60–0.78) no se despega del control de tamaño C1 (0.77–0.78) — no hay todavía evidencia limpia de que la topología aporte algo que el tamaño de ventana no explique, y son sólo 63 ventanas de ataque (muy por debajo de la potencia requerida). |
| 8 | **El signo per-flujo depende de la familia de ataque** (§Completitud, 10 capturas): floods HTTP invertidos (Hulk 0.023, HOIC/LOIC-UDP 0.003), mientras Bot (0.838) y Brute Force (0.63–0.69) son positivos. Se convirtió en **H3** y se probó como hipótesis preregistrada en datasets independientes: **no replicó en UNSW-NB15** (`docs/methodology/UNSW_H3_FINDINGS.md`), y BoT-IoT está pendiente. Estado: [`../ESTADO-ACTUAL.md`](../ESTADO-ACTUAL.md). |
| 7 | **H2 con datos reales, veredicto certificado por primera vez** (`scripts/run_h2_real.py`, windowing canónico P0.5): el per-flujo deja de saturar por completo (0.977–1.000 → 0.4571–0.8082) — el bug de deriva de ancla estaba inflando la separabilidad. 7 de 8 combinaciones a `window_seconds=10` despejan ambos gates; las 7 dan **`H2 REJECTED`** — coincide con el resultado sintético (`docs/methodology/H2_SYNTHETIC_FINDINGS.md`). Conclusión final del proyecto en `ANALISIS-DATOS-REALES.tex` §Conclusión. |

## Recompilar

```bash
python scripts/analyze_real_data.py data/raw/
python scripts/run_h2_real.py   # nuevo: veredicto H2 certificado, windowing canónico
cd docs/datos-reales && pdflatex ANALISIS-DATOS-REALES.tex && pdflatex ANALISIS-DATOS-REALES.tex
```
