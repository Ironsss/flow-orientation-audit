---
tipo: metodo
tags: [metodo, auditoria]
---

# Auditorías A1–A4 (post-hoc, 2026-09-27)

| | Pregunta | Resultado clave |
|---|---|---|
| A1 | Dependencia en [[BoT-IoT]] más allá de host-pair | 3/8 grupos mantienen orientación (DDoS/TCP, DDoS/UDP, DoS/UDP); un host-pair benigno = 25.2% del benigno |
| A2 | Descomposición condicionada a respuesta | restringido a flujos respondidos, los 10 puntos estimados quedan positivos |
| A3 | Semántica de labels/features de [[CICIDS-2018]] | corrige la atribución del 0.003 (HOIC 0.0005 + LOIC-UDP 1.000) |
| A4 | Otra representación de flujo (NetFlow-v2) sobre el mismo tráfico | HOIC/Hulk REVERSED, SSH EMERGED; **Caso C**, C2 no excluido |

No modifican H2/H3 ni el veredicto de BoT-IoT; **cualifican** su lectura → [[Tesis vigente]].
Conceptos: [[Host-pair bootstrap]], [[Controles C1 y C2]]. Documentos: `docs/reviewer_audit/`, síntesis en `AUDIT_SYNTHESIS.md`.
