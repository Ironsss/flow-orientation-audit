---
tipo: hipotesis
estado: replicó en BoT-IoT, no en UNSW; reinterpretada
tags: [hipotesis]
---

# H3 — el signo de la asimetría per-flujo depende del mecanismo del ataque

| Paso | Dataset | Veredicto |
|---|---|---|
| Descubrimiento | [[CICIDS-2018]] | aparente: floods HTTP invertidos, Bot/Brute Force positivos |
| Ejecución 1 | [[UNSW-NB15]] | **NO REPLICATION** (9/9 familias positivas) |
| Ejecución 2 | [[BoT-IoT]] | **STRONG REPLICATION** por la regla congelada (H3-env 6/6, H3-dir 2/7) |

El veredicto de BoT-IoT **se conserva como se calculó**, pero [[Auditorias A1-A4]] muestran que no soporta la
lectura que invitaba (solo 3 de 8 grupos mantienen orientación bajo [[Host-pair bootstrap]]). Interpretación
vigente: [[Tesis vigente]]. Ambos datasets están **gastados** como conjuntos confirmatorios.

Dos lecturas rivales prerregistradas: **H3-dir** (mecanismo, desde CICIDS) vs **H3-env** (entorno: ¿el objetivo
responde?, desde UNSW). Protocolo: [[Protocolo freeze-push-code-push-run]].
