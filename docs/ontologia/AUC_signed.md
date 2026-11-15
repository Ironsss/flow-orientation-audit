---
tipo: concepto
tags: [concepto]
---

# AUC_signed

AUC de la feature de asimetría contra una [[Referencia benigna]] nombrada, **sin voltear el signo**:
>0.5 = el ataque envía más de lo que recibe respecto al benigno; <0.5 = lo contrario.
Reemplazar el score por su negación lleva AUC a 1−AUC. Es relacional por definición; el contenido empírico es que
cambios plausibles de referencia, slice de respuestas, dependencia o pipeline lo invierten. Pareja: [[AUC_sep]].
Feature concreta: [[A_bytes]].
