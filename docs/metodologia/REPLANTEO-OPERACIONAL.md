# Replanteo operacional — enmienda al preregistro

> Enmienda a [`PREREGISTRO.md`](README.md), motivada por una observación del autor que el proyecto no
> había hecho y que cambia qué pregunta vale la pena responder.

## 1. La observación, y por qué es correcta

> *"A lo mejor este dataset es demasiado limpio, a lo mejor son columnas que no siempre van a estar."*

Es correcta, y de forma más precisa de lo que parece a primera vista. Tres razones, en orden de
gravedad:

**(a) Las features de CICIDS presuponen visibilidad completa de paquetes.** `tot_bwd_pkts`,
`bwd_pkt_len_std`, `fwd_iat_mean` las produce CICFlowMeter reconstruyendo cada flujo paquete por
paquete. Un router de producción no hace eso a escala de línea. Exporta NetFlow/IPFIX, típicamente
**muestreado 1:1000**, y muchas configuraciones no preservan conteos por dirección.

**(b) La etiqueta es verdad de campo por construcción, no por detección.** `Label` viene del
calendario conocido de ataques del testbed. El dataset *ya contiene* la respuesta que un detector
debería inferir.

**(c) 24 de 49 features son direccionales.** Sobre datos así, que una regresión logística o una SVM
den señal fuerte no dice que el problema esté resuelto — dice que el dataset trae la asimetría
precocinada, con visibilidad que en producción no existe.

**Conclusión:** el proyecto ha estado midiendo en un régimen de información que ningún sistema real
tiene. Eso explica todos los resultados negativos: se comparó al grafo contra un baseline que opera
con un lujo informacional inalcanzable.

## 2. El replanteo — y es un argumento a favor del grafo que este proyecto nunca hizo

La pregunta deja de ser una comparación de features sobre un dataset limpio:

> ~~¿La asimetría relacional aporta sobre la per-flujo?~~

y pasa a ser una pregunta sobre **régimen operativo**:

> **¿Qué representación sobrevive a las restricciones de información de un despliegue real, y con
> qué anticipación da señal utilizable?**

El argumento estructural, que no depende de ganarle a nadie en CICIDS:

| Representación | Información mínima que exige | ¿La tiene un router? |
|---|---|---|
| Asimetría per-flujo | contabilidad direccional de bytes por flujo | ✗ raramente, y no bajo muestreo |
| **Topología** | **la tupla `(src, dst)`** | **✓ siempre — es lo primero que exporta** |

Ese es el punto que cambia el marco. En un dataset limpio la per-flujo gana. **Pero la per-flujo no
está disponible en el régimen que importa.** El grafo no compite por ser mejor feature: compite por
ser la estructura que *queda en pie* cuando se retira la información.

Y agrega el eje temporal: la topología es observable desde el primer paquete (que A contacte a B, C,
D se ve al instante); las estadísticas de flujo requieren que el flujo termine y que haya suficientes
flujos para promediar.

## 3. Qué se midió, y por qué no alcanzó

Se intentaron los dos experimentos que testean esto directamente. Ambos **saturaron**.

**Detección temprana** (DDoS, ventanas positivas y negativas de la misma corrida — control C2 sí satisfecho):

| observado | topología | per-flujo | C1 tamaño |
|---|---|---|---|
| 1 s | 0.9375 | **1.0000** | 0.7037 |
| 10 s | 0.9350 | **1.0000** | 1.0000 |
| 60 s | 1.0000 | **1.0000** | 1.0000 |

**Muestreo NetFlow:**

| muestreo | topología | per-flujo | C1 tamaño |
|---|---|---|---|
| 1:1 | 1.0000 | 1.0000 | 1.0000 |
| 1:100 | 1.0000 | 1.0000 | 0.9975 |
| 1:1000 | *una sola clase* | — | — |

La per-flujo llega a 1.0000 **con un segundo de observación**. No hay margen que medir. Bajo muestreo
agresivo las ventanas caen por debajo del mínimo de flujos y se pierde una clase.

Dato colateral útil: los flujos completan rápido (p50 = 0.01 s, p99 = 1.32 s), así que la limitación
temprana **no** es que estén incompletos — es que hay menos flujos observados. Es un efecto de tamaño
de muestra, no de disponibilidad de features. Eso reformula la hipótesis a *"¿la topología se
estabiliza con menos observaciones?"*, que es lo que se intentó medir.

> ### Quinta confirmación
>
> El simulador ya bloqueó cinco mediciones distintas: efecto techo en PR-AUC, ausencia de clase
> negativa en infiltración, AUC 1.0000 en los tres conjuntos de brute force, el confound de tamaño de
> grafo, y ahora saturación en los dos experimentos de restricción de información.
>
> **El instrumento está agotado.** No es que falten datos reales: es que este generador produce un
> problema trivial, y ningún experimento comparativo puede correr sobre un baseline saturado.

## 4. Sobre las redes neuronales de grafos

Pregunta directa: *"no me queda claro cómo se combinan"*. Respuesta corta.

Una GNN aprende un vector por nodo mediante **paso de mensajes**:

- **Capa 1:** el vector de cada host = f(sus propias features, features de los hosts con los que habló)
- **Capa 2:** ahora incorpora vecinos a 2 saltos
- **Tras k capas:** el vector de cada nodo resume su vecindario de k saltos
- **Para clasificar la ventana entera:** se agrupan (pooling) todos los vectores de nodo en uno solo

En vez de diseñar a mano `A_dir` y `A_ent`, la red aprende qué patrón estructural importa. Es
efectivamente **agregación aprendida** — la Propuesta C de `docs/replanteamiento/`, que los tres
revisores rechazaron *por ahora* y ninguno por estar equivocada.

### Por qué no es el siguiente paso

No porque esté mal, sino por secuencia:

1. **Datos.** Una GNN necesita miles de grafos etiquetados. El proyecto tiene ~60 ventanas por
   corrida. El Revisor #1 fue literal: *"entrenar atención con 61 ventanas es una fantasía."*
2. **Es el patrón que acabamos de corregir.** Saltar a GNN es construir un artefacto y después buscar
   qué significa. El preregistro existe para impedir exactamente eso.
3. **Responde otra pregunta.** GNN-vs-hecho-a-mano es una pregunta de arquitectura. La pregunta que
   importa ahora es de **régimen de información**, y esa se testea con features simples primero.
4. **Interpretabilidad.** Era el argumento de venta; una GNN lo debilita justo cuando el proyecto
   necesita poder explicar por qué dispara una alerta.

**La secuencia disciplinada:** si la topología sobrevive a la restricción de información mejor que la
per-flujo, *entonces* una GNN se justifica como la forma de extraer más de la topología. Si no
sobrevive, una GNN no la salva — le agrega capacidad a una representación que no tenía la señal.

Primero la pregunta, después la arquitectura.

## 5. Qué exige esto de la Fase 0

Los cinco criterios del preregistro siguen. El replanteo **agrega tres**, todos sobre el generador:

| | Criterio nuevo | Por qué |
|---|---|---|
| 6 | El baseline per-flujo **no** debe saturar (AUC ≤ 0.9 a observación completa) | sin esto ningún experimento comparativo puede correr — falló 5 veces |
| 7 | Ataque **gradual**, no binario: rampa de intensidad | detección temprana necesita un régimen donde "temprano" signifique algo |
| 8 | Tráfico de fondo con **estructura realista** (no aleatorio uniforme) | la dilución que mata a `A_dir` depende de la forma del fondo |

El criterio 6 es el que más importa y el que este proyecto ha violado en cada intento.

## 6. El experimento, ya con la forma correcta

**H2 (enmienda a H1).** Bajo restricción de información — muestreo 1:N, o solo tuplas sin conteos de
bytes — la topología degrada **menos** que la asimetría per-flujo, y la brecha crece con la
restricción.

Falsable en ambas direcciones, y **la dirección importa**: si la topología degrada igual o peor, el
argumento estructural a favor del grafo se cae por completo y el proyecto honesto es per-flujo.

Ejes de restricción, del más realista al más extremo:

1. **Muestreo** 1:1 → 1:10 → 1:100 → 1:1000 (realidad de NetFlow)
2. **Solo tuplas** — sin conteos de bytes por dirección (la per-flujo deja de existir; el grafo no)
3. **Truncamiento temporal** — primeros t segundos de la ventana
4. **Combinado** — muestreo + truncamiento, que es el caso operativo real

Controles: los cinco del preregistro. **C1 (solo tamaño) es obligatorio en cada arm** — en el
experimento de detección temprana ya subió de 0.7037 a 1.0000 entre 1 s y 10 s, o sea que buena parte
de lo que parecería "señal topológica" es conteo de nodos nuevos.

## 7. Lo que esto cambia en el encuadre del paper

De: *"proponemos un índice de asimetría de grafo"* — que no sobrevivió a la evidencia.

A: **"la detección de intrusiones se evalúa en un régimen de información que no existe en producción;
medimos qué representaciones sobreviven al régimen real, y el orden se invierte."**

Ese encuadre tiene tres virtudes que el anterior no tenía:

- **El baseline es honesto.** Per-flujo gana en CICIDS y se dice así, sin rodeos.
- **El resultado negativo ya acumulado se vuelve material**, no deuda.
- **Es útil aunque el grafo pierda.** Si la topología tampoco sobrevive, el hallazgo es que *nada*
  sobrevive, y eso es un resultado que la comunidad debería conocer.

Sigue sin haber resultados. Sigue bloqueado en Fase 0. Pero la pregunta ahora es una que importa
fuera del dataset.

---

**Crédito:** el replanteo de esta sección nace de una observación del autor —que el dataset es
demasiado limpio y que esas columnas no siempre van a estar— que el proyecto, tras cuatro sesiones,
no había hecho.
