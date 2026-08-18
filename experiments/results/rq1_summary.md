# RQ1 — the cost of the cryptography

Runs: 20 sessions over QUIC (two traders each), 20 in-process sessions, 20 single-prover runs.
One observation is recorded per session; two-process phase values use the slower trader.

## Latency per phase and session (ms)

| configuration | build | prove | open | verify | proof core | session total | p95 session |
|---|---:|---:|---:|---:|---:|---:|---:|
| single prover | — | 318 | — | 5.6 | 324 | 324 | 373 |
| two parties, one process | 17 | 1 352 | 2 646 | 8.3 | 4 006 | 4 030 | 5 141 |
| two processes, QUIC | 88 | 1 693 | 3 332 | 6.8 | 4 810 | 5 139 | 6 182 |

Overhead over the single prover: 12.5x in one process, 15.9x over QUIC.

## Resources and constant sizes

| metric | value |
|---|---:|
| peak memory per trader (median) | 1.69 GiB |
| peak memory per trader (p95) | 1.71 GiB |
| trader A sends | 62.4 MiB in 56,841 datagrams |
| trader B sends | 61.1 MiB in 55,235 datagrams |
| TurboPlonk gates | 2048 |
| public signals | 6 |
| proof size | 769 B compressed (1185 B uncompressed) |
| verifying key size | 938 B compressed |

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2.
