# VerificaciÃ³n de referencias (automÃ¡tica, Crossref / arXiv)

Generado por `literature/verify_bib.py` sobre `references.bib` (39 entradas).
OK = tÃ­tulo, primer autor y aÃ±o coinciden con el registro.
CHECK / NOT FOUND = revisar a mano (ver motivo y la lista extendida abajo).

| Estado | Clave | Detalle |
|---|---|---|
| OK | `sharafaldin2018cicids` | Crossref/doi; matches |
| OK | `akoglu2015graph` | Crossref/doi; matches |
| OK | `zhong2024gnnids` | Crossref/doi; matches |
| CHECK | `moustafa2015unsw` | Crossref/doi; title differs (sim 0.85): registry='UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 net' |
| OK | `koroniotis2019botiot` | Crossref/doi; matches |
| OK | `engelen2021troubleshooting` | Crossref/doi; matches |
| OK | `cantone2024crossdataset` | Crossref/doi; matches |
| OK | `pinto2024flowexporter` | arXiv; matches |
| OK | `sommer2010closedworld` | Crossref/doi; matches |
| CHECK | `arp2022dosdonts` | Crossref/search; title differs (sim 0.26): registry='Das infizierte steife KniegelenkÂ â€“ Dos and Donâ€²ts'; first author differs: registry='Ismailidis'; year differs: bib=2022 registry=2025 |
| OK | `nosek2018preregistration` | Crossref/doi; matches |
| OK | `sarhan2021nfv2` | Crossref/doi; matches |
| OK | `efron1979bootstrap` | Crossref/doi; matches |
| OK | `liu2022errorprevalence` | Crossref/doi; matches |
| OK | `layeghy2022generalisability` | Crossref/doi; matches |
| OK | `wilkinson2025normal` | arXiv; matches |
| OK | `gil2001multops` | Crossref/search; matches |
| OK | `jung2004portscan` | Crossref/doi; matches |
| CHECK | `bullard2014pcr` | Crossref/search; title differs (sim 0.42): registry='Peer Review #1 of "Traffic flow simulation of modified cellular automata model based on pr'; year differs: bib=2014 registry=2022 |
| OK | `dhooge2020inter` | Crossref/doi; matches |
| OK | `layeghy2024benchmarking` | Crossref/doi; matches |
| OK | `jin2026benchmark` | Crossref/search; matches |
| OK | `flood2024smells` | Crossref/doi; matches |
| OK | `apruzzese2022cross` | Crossref/doi; matches |
| OK | `cameron2008bootstrap` | Crossref/doi; matches |
| OK | `sarhan2021featureanalysis` | arXiv; matches |
| OK | `sperotto2010overview` | Crossref/doi; matches |
| OK | `rfc5103` | Crossref/search; matches |
| OK | `lanvin2023errors` | Crossref/doi; matches |
| OK | `sarhan2021netflow` | Crossref/doi; matches |
| OK | `kapoor2023leakage` | Crossref/doi; matches |
| OK | `brauckhoff2006sampling` | Crossref/doi; matches |
| OK | `fieldwelsh2007` | Crossref/doi; matches |
| OK | `ascarate2026score` | arXiv; matches |
| OK | `elangovan2026crossdataset` | Crossref/doi; matches |
| OK | `bouke2026entropy` | arXiv; matches |
| OK | `fernandezbarrios2026candidate` | arXiv; matches |
| OK | `zmaimita2026prereg` | Crossref/datacite; matches |
| OK | `rosay2022cicflowmeter` | Crossref/doi; matches |

## Entradas por revisar a mano (lista extendida)

### `moustafa2015unsw` â€” CHECK
- Autores: Moustafa, Nour and Slay, Jill
- TÃ­tulo: {UNSW-NB15}: a comprehensive data set for network intrusion detection systems
- PublicaciÃ³n: MilCIS 2015  1--6 (2015)
- DOI/URL en el bib: 10.1109/MilCIS.2015.7348942
- Motivo: Crossref/doi; title differs (sim 0.85): registry='UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 net'
- Scholar: https://scholar.google.com/scholar?q=UNSW-NB15%3A%20a%20comprehensive%20data%20set%20for%20network%20intrusion%20detection%20systems

### `arp2022dosdonts` â€” CHECK
- Autores: Arp, Daniel and Quiring, Erwin and Pendlebury, Feargus and Warnecke, Alexander and Pierazzi, Fabio and Wressnegger, Christian and Cavallaro, Lorenzo and Rieck, Konrad
- TÃ­tulo: Dos and Don'ts of Machine Learning in Computer Security
- PublicaciÃ³n: 31st USENIX Security Symposium  3971--3988 (2022)
- DOI/URL en el bib: https://mlsec.org/docs/2022-sec.pdf
- Motivo: Crossref/search; title differs (sim 0.26): registry='Das infizierte steife KniegelenkÂ â€“ Dos and Donâ€²ts'; first author differs: registry='Ismailidis'; year differs: bib=2022 registry=2025
- Scholar: https://scholar.google.com/scholar?q=Dos%20and%20Don%27ts%20of%20Machine%20Learning%20in%20Computer%20Security

### `bullard2014pcr` â€” CHECK
- Autores: Bullard, Carter and Gerth, John
- TÃ­tulo: {PCR} -- A New Flow Metric: Producer Consumer Ratio
- PublicaciÃ³n: Presentation, FloCon 2014, Charleston, SC, 13--16 January 2014. \url{https://www.sei.cmu.edu/documents/3797/2014_017_001_90063.pdf}   (2014)
- DOI/URL en el bib: â€”
- Motivo: Crossref/search; title differs (sim 0.42): registry='Peer Review #1 of "Traffic flow simulation of modified cellular automata model based on pr'; year differs: bib=2014 registry=2022
- Scholar: https://scholar.google.com/scholar?q=PCR%20--%20A%20New%20Flow%20Metric%3A%20Producer%20Consumer%20Ratio

## Nota sobre los tres CHECK restantes (revisados a mano)

- **moustafa2015unsw**: falso aviso; el registro aï¿½ade '(UNSW-NB15 net...)' al tï¿½tulo. DOI 10.1109/MilCIS.2015.7348942 resuelve.
- **arp2022dosdonts**: artï¿½culo real (USENIX Security 2022, pp. 3971-3988). USENIX no usa DOI y Crossref no lo indexa; busca en https://www.usenix.org/conference/usenixsecurity22/presentation/arp o en Scholar.
- **bullard2014pcr**: presentaciï¿½n de FloCon 2014 sin registro; PCR original en Bullard/Gerth, implementaciï¿½n en github.com/reservoirlabs/bro-producer-consumer-ratio. Verificable solo con Scholar o el archivo de FloCon (nota 'not peer reviewed' ya en el .bib).

Correcciones aplicadas al .bib el 2026-11-14: autores completos de Koroniotis, Pinto, Liu, Flood y Jung (+DOI y pï¿½ginas de Jung); tï¿½tulo actual de Bouke (arXiv).


## Actualizaciï¿½n (2026-11-14, PDFs abiertos leï¿½dos)

- **arp2022dosdonts**: PDF https://mlsec.org/docs/2022-sec.pdf leï¿½do; tï¿½tulo y los 8 autores coinciden. Las pï¿½ginas 3971-3988 vienen de USENIX y no aparecen en el preprint. URL aï¿½adida al .bib.
- **bullard2014pcr**: PDF https://www.sei.cmu.edu/documents/3797/2014_017_001_90063.pdf leï¿½do: Carter Bullard (QoSient) y John Gerth (Stanford), FloCon 2014, Charleston, 13-16 enero 2014. Tï¿½tulo real: 'PCR - A New Flow Metric / Producer Consumer Ratio'. Definiciï¿½n (diap. 7): PCR = (SrcAppBytes - DstAppBytes)/(SrcAppBytes + DstAppBytes), rango [-1,1], con bytes de aplicaciï¿½n (sin cabeceras L2-4 ni retransmisiones). Respalda las dos frases del manuscrito ('normalises sent minus received bytes'; 'A_bytes es un anï¿½logo log-diferencia'). .bib corregido.
- **moustafa2015unsw**: pendiente de acceso al PDF; solo se citan sus metadatos.


## D'hooge et al. 2020 (preprint leído, 2026-11-14)

Leído el preprint Elsevier proporcionado por los autores (15 pp). Abstract: 'Our first results question the implied link that great intra-dataset generalization leads to great inter- or extra-dataset generalization.' Alcance real: 12 algoritmos supervisados, clasificación binaria, solo las clases DoS(-SSL) y botnet compartidas entre CIC-IDS2017 y CSE-CIC-IDS2018. Resultados mixtos: muchos casos ~50% de exactitud balanceada (sobre todo sin escalado), pero algunos altos (SVM lineal 90% en botnet, heartbleed muy bien clasificado). Conclusión: 'Generalization on the whole is underwhelming, but some singular results stand out.' -> frase del manuscrito OK con ese alcance; 'near-chance' como descripción general era excesivo y se cambió a 'weak transfer, often near chance'. La versión publicada (JISA) puede diferir del preprint.


## Jin & Lee, Elangovan, Engelen (PDF leídos, 2026-11-14)

- **Jin & Lee 2026** (Electronics 15, 3761): §2.2 confirma 'benign traffic is assigned to the negative class, and all attack categories are assigned to the positive class'. §2.7 y Tabla 4: HIKARI-2021 -> CICIDS2017, XGBoost y Transformer+SSL con orientación 'flipped' (ROC-AUC 0.214 y 0.311, bajo 0.5); diagnóstico oracle AUC_oracle = max{AUC(y,s), AUC(y,1-s)}. Frases del manuscrito OK.
- **Elangovan et al. 2026** (Future Internet 18, 194): §3.3.2 define asimetría direccional como desbalance bidireccional dentro de un flujo (conteos fwd/bwd, ratios de bytes, down/up); §4.6 'moderate transferability' del grupo y estabilidad por varianza entre datasets (Fig. 8); métrica principal Macro-F1. Bajo transferencia cross-domain el Macro-F1 baja de 0.84-0.96 a 0.69-0.78, es decir degradación, NO casi azar: se cambió 'near chance' en el texto principal.
- **Engelen et al. 2021** (WTMC): estudia CICIDS2017 (no CSE-CIC-IDS-2018). Confirma: tras el timeout de un 'TCP appendix' el flujo siguiente puede salir con Source/Destination intercambiados; Web Attack BF/XSS, Bot y DoS con muchos flujos sin datos forward; los 'TCP appendices' (flujo tras el primer FIN) heredan la etiqueta. Texto ajustado a CICIDS2017.
- **Liu et al. 2022**: sin acceso al texto; se descartó como respaldo de afirmaciones concretas. Solo se cita para lo que dice su título (prevalencia de errores en CIC-IDS-2017 y CSE-CIC-IDS-2018) y como 'cf.' en la limitación de datos corregidos.

