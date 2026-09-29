# Provenance: chronology of freeze, code, data, and results

Consolidates the git-verifiable ordering that the manuscript claims (Methods,
`\S`\ref{sec:protocol}): each confirmatory test is *frozen and pushed* before
the data behind it is analyzed. This document does not establish new facts;
every row here is already stated in a freeze/findings doc or a `results/`
JSON file. It exists so the chain can be read as one table instead of
reconstructed from separate commits.

**How to verify a row:** `git show -s --format="%H|%ad|%s" --date=iso-strict <commit>`
reproduces the commit and timestamp columns. `git log --follow -- <path>`
reproduces which commit introduced a given file.

## H2: information restriction

| Event | Commit (full SHA) | Timestamp | Data available at commit? | Results inspected before commit? |
|---|---|---|---|---|
| P2 candidate freeze + synthetic H2 verdict (REJECTED) | `403165b6bd1cae957382bd7bd01bae054a18a760` | 2026-09-19T23:42:27-06:00 | n/a (synthetic generator) | n/a |
| H2 real-data execution, canonical windowing (certified verdict, REJECTED) | `2fb37f44ab03cecca915d404fc634450c03ced13` | 2026-09-20T02:56:52-06:00 | Yes (CICIDS-2018, local) | Yes -- this commit *is* the execution |

CICIDS-2018 raw files were not hashed at H2 run time (no `run_metadata.json`
existed for this era of the project); `data_manifests/cicids2018_manifest.csv`
records hashes computed post hoc, 2026-09-24, from the files currently in
`data/raw/`. This is a real gap, not filled retroactively by claiming
otherwise: the manifest says so in its `notes` column.

## H3: UNSW-NB15 (external validation, NO REPLICATION)

| Event | Commit (full SHA) | Timestamp | Data available? | Results inspected before commit? |
|---|---|---|---|---|
| Freeze (blind preflight, plan pushed before any label-conditioned statistic) | `6ba17f964ae354ec2bc5b4c2b58f035bbb54ecf4` | 2026-09-22T21:50:03-06:00 | Files present locally (downloaded 2026-09-20, per file mtime); **not label-conditioned or outcome-inspected**, per the freeze doc's own constraint | No |
| Code fix (numpy-bool JSON serialization) | `fac0dac2fc8672bb8183a4d78ae240508c52b379` | 2026-09-22T22:01:35-06:00 | Yes | No (serialization fix only, no outcome computed yet) |
| Preflight + execution + verdict (NO REPLICATION) | `f9b4602d276684724fd80347a499741557408b1a` | 2026-09-22T22:08:09-06:00 | Yes | Yes -- this commit *is* the execution |

Freeze (21:50) precedes the fix (22:01) precedes the verdict (22:08): all
three from the same evening, in the declared order.

## H3: BoT-IoT (external validation, STRONG REPLICATION)

| Event | Commit (full SHA) | Timestamp | Data available? | Results inspected before commit? |
|---|---|---|---|---|
| Freeze (plan pushed **before any BoT-IoT file had been downloaded**) | `2fad302cedf3e7ef93d156bc101db23fecc628ad` | 2026-09-22T22:51:24-06:00 | **No** -- per the freeze doc's own declared constraint | No |
| Phase 0 blind preflight (structural checks only: row counts, duplicates, attacker presence; PASS) | `afd487000ab76710f02355eabbf2f57556798721` | 2026-09-23T00:03:33-06:00 | Yes (downloaded between freeze and this commit) | No -- structural only, no outcome statistic computed |
| H3 runner code committed ("not yet run on real data") | `4554139a7dabaec837f9afe226069a1b60d88d40` | 2026-09-23T00:11:26-06:00 | Yes | No |
| Execution + verdict (STRONG REPLICATION) | `4db7fc4fdcfcbbc03a43504375027eab45592ed3` | 2026-09-23T00:17:47-06:00 | Yes | Yes -- this commit *is* the execution |

Order proven by commit timestamp: freeze (22:51) < preflight (00:03, next
calendar day) < runner code (00:11) < verdict (00:17). This is the chain the
manuscript's abstract and Methods section rely on for BoT-IoT; it is fully
reconstructible from the four commits above, no separate claim required.

## Dataset identity

Exact bytes, row counts, and SHA256 for every file behind H2 and H3 are in
`data_manifests/`. For UNSW-NB15, the hashes were independently recomputed
against the file still on disk on 2026-09-24 and matched the ones recorded
at analysis time exactly. For BoT-IoT, the hashes in the manifest are the
ones the confirmatory run itself computed and folded into
`dataset_manifest_sha256` in `results/botiot/run_metadata.json` -- not
recomputed after the fact.

## Environment

`requirements-ci.txt` already pins exact versions with hashes (regenerated
via `uv pip compile`, see its header). The versions it pins match what the
confirmatory runs actually used, recorded independently in each run's
`run_metadata.json`:

| Package | Pinned in `requirements-ci.txt` | Used by UNSW run | Used by BoT-IoT run |
|---|---|---|---|
| Python | 3.11 (CI platform) | 3.11.16 | 3.11.16 |
| numpy | 2.4.6 | 2.4.6 | 2.4.6 |
| polars | 1.44.1 | 1.44.1 | 1.44.1 |
| matplotlib | 3.11.1 | 3.11.1 | 3.11.1 |
| scikit-learn | 1.9.0 | 1.9.0 | 1.9.0 |

Measured runtime on the machine that produced the confirmatory results
(from `started_utc`/`finished_utc` in each `run_metadata.json`): UNSW-NB15
(2.5M rows) ran in 4m52s; BoT-IoT (73.4M rows) ran in 4m1s. Both fit in
ordinary developer hardware and RAM; no cluster or special resources were
used. `results/unsw/run_metadata.json` additionally records `git_dirty:
true` for the UNSW run -- the working tree had uncommitted changes at
execution time. This does not affect the frozen decision rule or the code
that ran (both were committed before the run), but it means the exact
working-tree state at that instant is not separately reconstructible beyond
what the commit and `run_metadata.json` already capture.
