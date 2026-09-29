# Metodología experimental — preregistro

> ### 🧭 Estado al 2026-09-22: [`../ESTADO-ACTUAL.md`](../ESTADO-ACTUAL.md)
>
> Este preregistro (H1) y su enmienda (H2) son el **registro del método**, no el estado actual.
> H1 nunca fue ejecutable. **H2 fue rechazada** (datos sintéticos y reales). La línea vigente es
> **H3** (validación externa): **no replicó en UNSW-NB15**, y BoT-IoT está congelado antes de
> descargar los datos. Freezes y hallazgos, en orden:
> [`../methodology/`](../methodology/README.md).

> **Este es el documento que ordena el proyecto.** Los anteriores presentaban hallazgos y buscaban su
> marco. Éste fija el marco y declara que no hay hallazgos aún.

> ### 📎 Enmienda: [`REPLANTEO-OPERACIONAL.md`](REPLANTEO-OPERACIONAL.md)
>
> El preregistro de abajo compara representaciones **sobre un dataset limpio**. La enmienda argumenta
> que ese régimen de información no existe en producción: las features de CICIDS presuponen
> visibilidad completa de paquetes, mientras que un router real exporta NetFlow muestreado 1:1000 y a
> menudo sin conteos por dirección.
>
> Eso invierte el argumento a favor del grafo: no compite por ser mejor feature —en CICIDS pierde—
> sino por ser **la estructura que queda en pie cuando se retira la información**, ya que solo
> necesita la tupla `(src, dst)`.
>
> Incluye la respuesta a *cómo se combinan grafos y redes neuronales*, y por qué las GNN no son el
> siguiente paso todavía.

## Qué faltaba

El proyecto produjo un índice, una revisión crítica, un replanteamiento y un protocolo de auditoría.
Nunca produjo una **pregunta enunciada de forma que las respuestas posibles sean enumerables**, con
hipótesis falsable, operacionalización, controles, y criterio de decisión declarado antes de medir.

El patrón: *primero se construye un artefacto, después se busca qué significa.* Una metodología real
invierte ese orden.

## La evidencia de que esto importa: un confound producido hoy

Antes de escribir nada se corrió el diagnóstico más barato: *¿hay margen que estudiar en el régimen
donde la asimetría per-flujo falla?*

| Conjunto de features | AUC |
|---|---|
| per-flujo asimetría (baseline) | 0.6863 |
| + tamaño de grafo | 1.0000 |
| + IAG (relacional) | 1.0000 |
| solo IAG | 1.0000 |
| **solo tamaño de grafo (`n_nodes`, `n_edges`)** | **1.0000** ⚠️ |

La última fila es el resultado. Dos enteros sin relación con la asimetría separan las clases
perfectamente:

```
n_nodes en positivos: 51 exacto
n_nodes en negativos: 50 exacto
solapamiento: CERO
```

Los positivos venían de corridas de infiltración y los negativos de corridas benignas **separadas**.
Las corridas de ataque tienen hosts atacantes extra. `n_nodes` separa las **corridas**, no los
**ataques**.

> **Lo que casi se reporta:** sin la fila de control, la lectura natural habría sido *"el IAG alcanza
> AUC 1.0000 en el régimen sigiloso donde la per-flujo solo llega a 0.69"*. Espectacular, publicable,
> y completamente falso.
>
> El control estaba ahí por costumbre, no por diseño. Esa es la diferencia entre tener método y no
> tenerlo.

El diagnóstico **no respondió la pregunta**: demostró que el diseño era inválido.

## La pregunta, derivada

**¿La asimetría medida a nivel *relacional* aporta información de detección que las features
direccionales *per-flujo* no aportan ya, específicamente en el régimen donde las per-flujo fallan?**

Derivada de lo medido, no propuesta: per-flujo da AUC 0.998 (PortScan) y 0.946 (DDoS) pero cae a
0.587–0.686 en infiltración. Los ataques ruidosos ya los detecta cualquier cosa; el margen está en el
régimen sigiloso.

Respuestas posibles: sí (con magnitud), no, o "no se puede saber con estos datos". Las tres son
resultados.

## Preregistro (resumen — detalle en el PDF)

**H1.** En el estrato sigiloso (baseline per-flujo AUC ≤ 0.75), agregar features relacionales produce
ΔAUC ≥ 0.05.

**Controles** — cada uno descarta una explicación alternativa concreta:

| | Control | Descarta |
|---|---|---|
| C1 | Solo tamaño de grafo | "el grafo es más grande", no más asimétrico — **el que atrapó el confound** |
| C2 | **Diseño intra-corrida** | positivos y negativos de la *misma* corrida — corrección directa al error de arriba |
| C3 | Per-flujo no-direccionales | "más features ayudan", midan o no asimetría |
| C4 | Ventanas degeneradas excluidas | artefactos de borde (la ventana de 4 nodos que ya invalidó H1 una vez) |
| C5 | Umbral de etiqueta declarado | que el resultado dependa de dónde se puso τ |

**Regla de decisión, declarada antes:**

1. Δ ≥ 0.05, IC excluye 0, y C1 < mitad de la mejora → **H1 sostenida**
2. Δ < 0.05 o IC incluye 0 → **H1 rechazada**, se reporta el negativo
3. C1 explica la mayor parte → **confounded**, se rediseña

**Potencia** (medida por simulación, baseline 0.69):

| n/clase | Δ=0.05 | Δ=0.10 |
|---|---|---|
| 50 | 77% | 94% |
| 100 | 85% | 97% |
| **250** | **95%** | 100% |

**Requisito: ≥250 ventanas por clase por estrato.** El diagnóstico de arriba tenía 60 — insuficiente
aun si el diseño hubiera sido válido.

## ¿Ejecutable hoy? No — y ahora se sabe exactamente por qué

La Fase 0 deja de ser "arreglar el simulador" (nunca especificado) y pasa a ser una lista derivada:

| Requisito | Estado | Origen |
|---|---|---|
| Positivos/negativos intra-corrida | ❌ **violado** | C2 — causa del confound |
| Estrato sigiloso existe (AUC 0.6–0.75) | ✅ cumplido | medido: 0.686 |
| ≥250 ventanas/clase/estrato | ❌ **violado** | potencia; hoy ~60 |
| `attack_ratio` cruzando τ | ❌ **violado** | mediana 0.926 |
| Sin efecto techo en baseline | ⚠️ parcial | falla en brute force (AUC 1.0) |

> **Por qué esto es progreso y no otra postergación:** las sesiones anteriores dijeron "el simulador
> está roto" sin poder decir *en qué sentido* ni *cuándo estaría arreglado*. Ahora hay cinco
> criterios de aceptación, cada uno derivado de un requisito del diseño, cada uno verificable con una
> consulta. El generador ya no persigue realismo — persigue estas cinco propiedades. Es ingeniería
> acotada, no investigación abierta.

## Dónde encaja el protocolo de auditoría

Queda claro su rol, hasta ahora ambiguo: **es el instrumento, no la contribución.**

Con 24 de 49 features direccionales correlacionadas, cualquier atribución ingenua sobre el resultado
de este experimento daría la respuesta equivocada. El protocolo existe porque la pregunta lo necesita
para ser respondida, no al revés.

Si H1 se rechaza, el resultado publicable es doble: el negativo, más el instrumento que permitió
establecerlo sin equivocarse.

## Qué haría abandonar esta línea

Declarado ahora, para no decidirlo después con los resultados a la vista:

- H1 rechazada con potencia adecuada y controles limpios → la línea relacional se cierra.
- El generador no alcanza los cinco criterios en un esfuerzo acotado → el bloqueante pasa a ser datos
  reales, declarado como único, y el proyecto se detiene ahí.
- Un cuarto confound no anticipado sobrevive a los cinco controles → el instrumento no es de fiar
  para esta pregunta; hay que cambiar de diseño, no de features.

## Recompilar

```bash
cd docs/metodologia && pdflatex PREREGISTRO.tex && pdflatex PREREGISTRO.tex
```
