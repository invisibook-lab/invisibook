# RQ1 — the cost of the cryptography

Runs: 20 sessions over QUIC (two traders each), 20 in-process sessions, 20 single-prover runs.
One observation is recorded per session; two-process phase values use the slower trader.

## Latency per phase and session (ms)

| configuration | build | prove | open | verify | proof core | session total | p95 session |
|---|---:|---:|---:|---:|---:|---:|---:|
| single prover | — | 419 | — | 6.2 | 425 | 425 | 763 |
| two parties, one process | 15 | 1 385 | 2 269 | 8.1 | 3 942 | 3 962 | 4 629 |
| two processes, QUIC | 74 | 1 300 | 3 161 | 6.5 | 4 866 | 5 150 | 5 457 |

Overhead over the single prover: 9.3x in one process, 12.1x over QUIC.

## Resources and constant sizes

| metric | value |
|---|---:|
| peak memory per trader (median) | 1.68 GiB |
| peak memory per trader (p95) | 1.72 GiB |
| trader A sends | 62.4 MiB in 55,507 datagrams |
| trader B sends | 61.3 MiB in 60,829 datagrams |
| TurboPlonk gates | 2048 |
| public signals | 6 |
| proof size | 769 B compressed (1185 B uncompressed) |
| verifying key size | 938 B compressed |

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2.
