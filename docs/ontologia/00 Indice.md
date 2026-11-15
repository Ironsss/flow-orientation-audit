---
tipo: mapa
tags: [moc]
---

# Ontología del proyecto `flow-orientation-audit`

Mapa de contenido (MOC). Abre `docs/ontologia` como bóveda en Obsidian (*Open folder as vault*).
Estas notas **no son fuente de verdad de cifras**: las cifras viven en [[Fuentes en el repo]]. Aquí está la
*estructura*: qué cosas existen, cómo se relacionan y qué decidió qué.

> Estado vigente en una línea: [[Tesis vigente]]. Pendientes de envío: [[Pendientes de publicacion]].

## Preguntas y afirmaciones
- [[Tesis vigente]] · [[Pregunta del proyecto]]
- Hipótesis: [[H1 relacionales suman AUC]] · [[H2 topologia bajo restriccion]] · [[H3 signo segun mecanismo]] · [[H4 combinacion bajo observabilidad parcial]]

## Datos (instrumentos de medida)
[[CICIDS-2018]] · [[UNSW-NB15]] · [[BoT-IoT]] · [[Simulador y Generator v2]]

## Conceptos de medida
[[AUC_signed]] · [[AUC_sep]] · [[Orientacion vs separabilidad]] · [[A_bytes]] · [[Referencia benigna]] · [[Host-pair bootstrap]] · [[Controles C1 y C2]]

## Método
[[Protocolo freeze-push-code-push-run]] · [[Estado evidencial]] · [[Auditorias A1-A4]] · [[Cinco errores ya cometidos]]

## Salidas
[[Manuscrito]] · [[Preprint arXiv]] · [[Manuscritos superados]] · [[Autores y roles]] · [[Pendientes de publicacion]]

## Cómo leer el grafo
`Hipótesis` —*se prueba en*→ `Dataset` —*bajo*→ `Protocolo`; `Auditoría` —*cualifica*→ `Veredicto`;
`Concepto` —*define*→ `Afirmación del manuscrito`. Cada nota declara su `tipo:` en el frontmatter, así que
se puede filtrar en el grafo (`tipo:hipotesis`) o con Dataview.
