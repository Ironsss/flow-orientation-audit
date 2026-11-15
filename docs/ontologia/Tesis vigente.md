---
tipo: afirmacion
estado: vigente
tags: [tesis]
---

# Tesis vigente

**El signo de `AUC_signed` es una medición relacional, no un atributo intrínseco del ataque**, y es distinto
de la separabilidad ([[Orientacion vs separabilidad]]). Depende de:

- la [[Referencia benigna]],
- la composición de respuestas (flujos con/sin respuesta),
- la estructura de dependencia ([[Host-pair bootstrap]]),
- y, para HOIC/Hulk de [[CICIDS-2018]], de la representación de flujo junto con su referencia ([[Auditorias A1-A4]], A4).

Descartada: "el mecanismo del ataque determina el signo" (resultado de [[H3 signo segun mecanismo]] tras las auditorías).
[[UNSW-NB15]] queda como contraejemplo donde la orientación fue en gran parte estable.

Alcance: tres datasets de testbed; **no** hay tráfico de producción (regla 5 de [[Cinco errores ya cometidos]]).
Salida: [[Manuscrito]], [[Preprint arXiv]]. Registro de afirmaciones: `docs/methodology/CLAIMS_LEDGER.md`.
