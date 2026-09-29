# Estado actual del proyecto

> **Fuente única de verdad sobre dónde está el proyecto.** Los demás documentos (README, CLAUDE.md,
> onboarding, metodología) enlazan aquí en vez de repetir el estado. Si el estado cambia, se
> actualiza este archivo en el mismo PR que lo cambia.
>
> **Última actualización:** 2026-09-28, tras el cierre de W2 (PR #59) y la reescritura W3 (Introducción, Related Work, Abstract, Conclusiones).

## En una frase

La hipótesis topológica (H2) fue **rechazada** en datos sintéticos y reales. La observación que
surgió de ese fracaso, que el signo de la asimetría per-flujo depende del mecanismo del ataque (H3),
**no replicó** en UNSW-NB15 y **cumplió el criterio congelado** en BoT-IoT (STRONG REPLICATION, veredicto
que se conserva). Las auditorías post-hoc (A1–A4) muestran que esa lectura es demasiado simple: el
signo de `AUC_signed` es una **medición relacional** (depende de la población de referencia benigna,
de la composición de respuestas, de la estructura de dependencia y, para HOIC/Hulk de CICIDS, de la
representación de flujo junto con su referencia), y es distinto de la separabilidad (`AUC_sep`).
**La tesis vigente del manuscrito es de validez de medición / transportabilidad, no "el mecanismo
determina el signo"** (esa afirmación quedó descartada). UNSW-NB15 se mantiene como contraejemplo
donde la orientación fue en gran parte estable.

## Línea de tiempo de hipótesis

| Hipótesis | Pregunta | Estado | Dónde está la evidencia |
|---|---|---|---|
| H1 (preregistro original) | ¿Features relacionales suman ΔAUC ≥ 0.05 en el estrato sigiloso? | Nunca ejecutable: el simulador bloqueó la medición | `docs/metodologia/` |
| **H2** (replanteo operacional) | Bajo restricción de información, ¿la topología degrada menos que la asimetría per-flujo? | ❌ **RECHAZADA**: sintético con potencia completa, y 7/7 filas reales certificadas (CICIDS-2018) que son **5 condiciones distintas** (desviación de implementación respecto al freeze; ver la fe de erratas en `docs/methodology/CLAIMS_LEDGER.md`) | `docs/methodology/H2_SYNTHETIC_FINDINGS.md`, `docs/datos-reales/` |
| **H3** (validación externa) | ¿El signo y la magnitud de la asimetría per-flujo varían según el mecanismo del ataque? | CICIDS (descubrimiento): sí, aparentemente. **UNSW-NB15: NO REPLICA.** **BoT-IoT: STRONG REPLICATION** por la regla congelada, pero solo 3 de 8 grupos evaluables mantienen orientación confiada bajo host-pair (A1). Interpretación vigente: orientación relacional, no mecanismo | ver abajo |
| H4 | ¿La combinación supera a per-flujo bajo observabilidad parcial? | **No activada**: el protocolo la condiciona a que H3 replique | — |

> **Choque de nombres:** la tabla "Hypotheses (original)" del README usa H1–H3 para las
> hipótesis del manuscrito retirado (IAG). La H3 de esta tabla es otra hipótesis, la de
> validación externa del mecanismo. Cuando haya duda, esta tabla es la vigente.

## H3: validación externa, paso a paso

| Paso | Dataset | Resultado | Registro |
|---|---|---|---|
| Descubrimiento | CICIDS-2018 | Floods HTTP invertidos (Hulk 0.023, HOIC/LOIC-UDP 0.003); Bot 0.838 y Brute Force 0.63–0.69 positivos | `docs/datos-reales/ANALISIS-DATOS-REALES.pdf` §Completitud |
| Freeze 1 | UNSW-NB15 | Plan congelado antes de ejecutar (`6ba17f9`) | `docs/methodology/UNSW_EXTERNAL_VALIDATION_FREEZE.md`, PR #37 |
| **Ejecución 1** | UNSW-NB15 | **NO REPLICATION**: las 9 familias con orientación positiva segura (A_bytes 0.68–0.89); DoS 0.841, el signo opuesto a los floods de CICIDS. Igual sin duplicados | `docs/methodology/UNSW_H3_FINDINGS.md`, `results/unsw/`, PR #38 |
| Freeze 2 | BoT-IoT | Plan congelado **sin datos en disco** (`2fad302`); 10 grupos de mecanismo, control C1, predicciones H3-dir vs. H3-env | `docs/methodology/BOTIOT_H3_FREEZE.md`, PR #39 |
| Fase 0 | BoT-IoT | **PASS** (2026-09-23): 73.370.443 filas = 9.543 Normal + 73.360.900 ataque, igual que el paper; mapeo 1:1 a los 10 grupos; atacantes presentes en el 100%; 0 duplicados; C2 cumplido a nivel de captura | `BOTIOT_H3_FREEZE.md` §9.1, `results/botiot/preflight.json` |
| **Ejecución 2** | BoT-IoT | **STRONG REPLICATION**: grupos con orientación opuesta y segura en ambas features, con el rol verificado. H3-env 6/6, H3-dir 2/7. **Salvedad:** el Normal de BoT-IoT (9.543 flujos sintéticos) está muy dominado por el origen (mediana +4,49), así que los grupos "negativos" son casi balanceados en términos absolutos | `docs/methodology/BOTIOT_H3_FINDINGS.md`, `results/botiot/`, PR pendiente |

**Lectura POST-HOC de UNSW (no confirmatoria):** la mayoría de los flujos de ataque de UNSW no
reciben respuesta (`dbytes == 0`: 98% Generic, 78% DoS, frente a 11% Normal), y UNSW sólo etiqueta
los flujos que inicia el atacante. El signo parece depender del **entorno** (¿el objetivo
responde?) más que del nombre del ataque. BoT-IoT pone a prueba esa lectura de forma prospectiva,
por primera vez (H3-env en `BOTIOT_H3_FREEZE.md` §6.2).

## Resultado de BoT-IoT frente a lo declarado en el freeze

El freeze declaró antes de tener datos que, si BoT-IoT replicaba, no borraría el fallo de UNSW y se
reportarían ambos. Eso se hizo. BoT-IoT replicó (H3-env 6/6, H3-dir 2/7) y las auditorías A1–A4
cualifican qué significa ese veredicto (ver `manuscript/main.tex`, Secciones de robustez y Discusión).

## Manuscrito

**Reescritura JISA en curso**, fuente `manuscript/main.tex` (aún plantilla MDPI *Symmetry*; JISA usa
`elsarticle`; cambio de plantilla hecho en W4). Fases: **W1** (Métodos y Resultados) y **W2**
(Discusión y Limitaciones, PR #59) cerradas; **W3** (Introducción, Related Work, Abstract, Título,
Palabras clave, Conclusiones) escrita en este PR. Autoridad para cualquier discrepancia:
`manuscript/rewrite/WRITING_EVIDENCE_CONTRACT.md`, `docs/methodology/CLAIMS_LEDGER.md` y
`docs/reviewer_audit/AUDIT_SYNTHESIS.md`. Pendiente: autores/afiliaciones/contribuciones/financiación
(`TODO(authors)`) y la búsqueda sistemática de literatura (Related Work usa solo
las referencias ya verificadas de `references.bib` y su enunciado de posicionamiento lo declara).
`paper/` es el manuscrito anterior (IAG), superado.

## Siguiente acción concreta

1. ~~Manuscrito v2 con BoT-IoT~~: hecho (2026-09-23).
2. ~~Corregir dos sobreafirmaciones del abstract~~: hecho (2026-09-24) -- alcance de "confident
   orientations" restringido a $A_{bytes}$, y "rules out inflation" cambiado a "conservative with
   respect to" la política de etiquetado. Ver [`docs/methodology/CLAIMS_LEDGER.md`](methodology/CLAIMS_LEDGER.md).
3. ~~Trazabilidad mínima~~: hecho (2026-09-24) -- tabla de procedencia
   ([`docs/methodology/PROVENANCE.md`](methodology/PROVENANCE.md)), registro de afirmaciones
   ([`docs/methodology/CLAIMS_LEDGER.md`](methodology/CLAIMS_LEDGER.md)) y manifests SHA256 de los
   tres datasets ([`data_manifests/`](../data_manifests/)).
4. ~~Sensibilidad de dependencia y multiplicidad~~: hecho (2026-09-24) -- post-hoc, no toca los
   veredictos originales. Hallazgo real: los 9 grupos de UNSW-NB15 mantienen orientación confiada
   bajo cluster bootstrap por host-pair; en BoT-IoT solo 3 de 8 grupos verificables la mantienen (los
   dos de theft, con 4 y 6 host-pairs, no se pudieron calcular). La corrección de Holm por
   multiplicidad no cambió nada en ningún dataset (los 19 p-valores ya estaban en el piso, 0/2000
   draws cruzando 0.5). Ambos incorporados al manuscrito
   ([`docs/methodology/CLAIMS_LEDGER.md`](methodology/CLAIMS_LEDGER.md), Limitations v2).
5. Antes de enviar el manuscrito: autores, afiliaciones, contribuciones y financiación
   (`TODO(authors)`), y hacer público el repositorio o armar un paquete de reproducibilidad. Estas
   dos últimas son decisiones separadas, no tareas de ejecución automática.
6. BoT-IoT y UNSW quedan **gastados** como conjuntos confirmatorios para H3. Cualquier afirmación
   nueva sobre la lectura de entorno exige un freeze nuevo sobre datos que no provengan de ninguno de
   los dos (por ejemplo, tráfico no generado en un testbed).
7. Auditoría de robustez post-hoc para reviewers (2026-09-27): A1 (dependencia
   BoT-IoT más allá de host-pair), A2 (descomposición reply-conditional), A3
   (semántica de labels/features CICIDS) -- ver
   [`docs/reviewer_audit/AUDIT_SYNTHESIS.md`](reviewer_audit/AUDIT_SYNTHESIS.md).
   Fase I cerrada: A1 completo en 60/300/600s (DDoS/TCP, DDoS/UDP y DoS/UDP
   mantienen su orientación con todos los métodos; los otros 5 no: son 3 de 8,
   no "3 a 8"). La discrepancia time-block/host-pair está medida
   (`scripts/audit_a1_benign_concentration.py`): un solo host-pair benigno
   tiene el 25,2% de las 9.543 filas benignas, y time-block no puede variar
   su peso. Fase II (A4, sensibilidad a otra
   representación de flujos sobre el mismo tráfico CICIDS) se abrió después
   como decisión separada y ya está ejecutada (Caso C; ver abajo).
   **A4 (2026-09-27):** protocolo congelado (`5c93a54`/`ac7c768`), enmendado antes de ejecutar (regla de envolvente por composición, confusor de referencia benigna C2, gate sobre el archivo NF-CSE-CIC-IDS2018-v2 standalone), re-congelado a nivel de label fino (`0b705ad`, `946337f`). **Ejecutado** (implementación `923c8f4`, empujada antes de ejecutar; 171/171 gates canónicos pasados): **CASO C** sobre los 11 labels con soporte (`A_bytes`, benigno global): HOIC y Hulk REVERSED (separabilidad se mantiene), SSH EMERGED, 6 PRESERVED, 2 BOTH NEUTRAL. POST-HOC; C2 (referencia benigna distinta) no excluido, así que no se atribuye al exportador. No modifica H2/H3 ni el veredicto BoT-IoT. Ver [`docs/reviewer_audit/A4_REPRESENTATION_SENSITIVITY_REPORT.md`](reviewer_audit/A4_REPRESENTATION_SENSITIVITY_REPORT.md).
   **Fase II cerrada** (2026-09-27): resultado revisado adversarialmente e integrado a
   [`docs/methodology/CLAIMS_LEDGER.md`](methodology/CLAIMS_LEDGER.md) (7 filas nuevas) y a
   `AUDIT_SYNTHESIS.md` (sección "Phase II (A4) closure"). No se descargó ni ejecutó ningún otro
   dataset (NF-UNSW-v2, NF-BoT-IoT-v2, etc.); eso sigue siendo una decisión separada, pendiente.
8. ~~Frase de la línea ~315 sobre HOIC/LOIC~~: superada y ya reescrita en W1/W2 (A3: el 0,003 es el
   agregado ponderado de HOIC 0,0005 y LOIC-UDP 1,000).
9. Reescritura JISA W1–W3 (2026-09-27/28): W1 Métodos/Resultados, W2 Discusión/Limitaciones (PR #59),
   W3 Introducción/Related Work/Abstract/Título/Conclusiones. No cambió ningún resultado ni se
   re-ejecutó nada. W4 (2026-09-28): plantilla `elsarticle` aplicada a `main.tex` (compila, 48 pp en formato preprint). Paquete de envío en `manuscript_submission/` (2026-09-28): `main.tex` condensado a 12 pp con referencias, `supplementary.tex` con el manuscrito completo, highlights, cover letter y `SUBMISSION_CHECKLIST.md` (la guía de JISA no pudo consultarse: verificar). Pendiente: datos de autores, CRediT, declaración de uso de IA generativa y revisión externa de
   la literatura citada.

## Reglas que no cambian

- **UNSW-NB15 ya se usó como conjunto confirmatorio.** Probar variantes de H3 sobre él sería
  pescar features.
- Toda hipótesis nueva requiere un freeze nuevo sobre un dataset no visto.
- Rama → PR → revisión registrada → merge. `pytest` y `ruff check .` limpios (281 tests al
  2026-09-27, rama `reviewer-audit-phase1`).
- Los resultados negativos se conservan con sus números.
