# Freezes y hallazgos, en orden

Cada experimento confirmatorio tiene un **freeze** (plan congelado y subido antes de ejecutar) y un
documento de **hallazgos** (resultado del plan tal como se congeló). Ninguno se edita después del
hecho: las correcciones van en un documento nuevo. Estado vigente: [`../ESTADO-ACTUAL.md`](../ESTADO-ACTUAL.md).

## P2: generador sintético v2 (instrumento para H2)

| Documento | Tipo |
|---|---|
| [`P2_GENERATOR_V2_DESIGN_FREEZE.md`](P2_GENERATOR_V2_DESIGN_FREEZE.md) | freeze de diseño |
| [`P2_DEVELOPMENT_FINDINGS.md`](P2_DEVELOPMENT_FINDINGS.md) | hallazgos (desarrollo) |
| [`P2_CANDIDATE_FREEZE.md`](P2_CANDIDATE_FREEZE.md) | freeze del candidato |
| [`P2_VALIDATION_FINDINGS.md`](P2_VALIDATION_FINDINGS.md) | hallazgos (validación) |
| [`P2_5_FINDINGS.md`](P2_5_FINDINGS.md) | hallazgos (P2.5) |
| [`P2_PHASE0_REVALIDATION_FINDINGS.md`](P2_PHASE0_REVALIDATION_FINDINGS.md) | hallazgos (revalidación Fase 0) |
| [`P2_FINAL_FREEZE.md`](P2_FINAL_FREEZE.md) | freeze final |

## H2: restricción de información

| Documento | Resultado |
|---|---|
| [`H2_SYNTHETIC_FINDINGS.md`](H2_SYNTHETIC_FINDINGS.md) | **H2 RECHAZADA** (sintético). La ejecución real certificada está en [`../datos-reales/`](../datos-reales/) |

## H3: validación externa del signo según el mecanismo

| Documento | Resultado |
|---|---|
| [`UNSW_EXTERNAL_VALIDATION_FREEZE.md`](UNSW_EXTERNAL_VALIDATION_FREEZE.md) | freeze UNSW-NB15 (`6ba17f9`) |
| [`unsw/NUSW-NB15_features.csv`](unsw/NUSW-NB15_features.csv) | descripción oficial de columnas (dos mirrors idénticos byte a byte) |
| [`UNSW_H3_FINDINGS.md`](UNSW_H3_FINDINGS.md) | **NO REPLICATION** |
| [`BOTIOT_H3_FREEZE.md`](BOTIOT_H3_FREEZE.md) | freeze BoT-IoT, congelado sin datos en disco (`2fad302`); Fase 0 en §9.1 |
| [`BOTIOT_H3_FINDINGS.md`](BOTIOT_H3_FINDINGS.md) | **STRONG REPLICATION** (H3-env 6/6, H3-dir 2/7) |

## Reproducibilidad y trazabilidad (paquete de envío)

| Documento | Contenido |
|---|---|
| [`PROVENANCE.md`](PROVENANCE.md) | Cronología freeze → datos → código → ejecución, con commit y timestamp verificables por `git show` |
| [`CLAIMS_LEDGER.md`](CLAIMS_LEDGER.md) | Cada afirmación central del manuscrito con su estado, evidencia y redacción permitida |
| [`../../data_manifests/`](../../data_manifests/) | SHA256, tamaño y filas de cada archivo de CICIDS-2018, UNSW-NB15 y BoT-IoT usado en el análisis |
