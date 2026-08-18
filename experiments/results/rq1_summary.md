# RQ1 — the cost of the cryptography

Runs: 20 sessions over QUIC (two traders each), 20 in-process sessions, 20 single-prover runs.

## Latency per phase (ms)

| configuration | build | prove | open | verify | total | p95 total |
|---|---:|---:|---:|---:|---:|---:|
| single prover | — | 524 | — | 7.4 | 531 | 715 |
| two parties, one process | 16 | 1 445 | 2 869 | 8.5 | 4 282 | 4 617 |
| two processes, QUIC | 95 | 1 317 | 3 129 | 6.1 | 4 537 | 4 680 |

Overhead over the single prover: 8.1x in one process, 8.5x over QUIC.

## Resources and constant sizes

| metric | value |
|---|---:|
| peak memory per trader (median) | 1.57 GiB |
| peak memory per trader (p95) | 1.59 GiB |
| trader A sends | 60.0 MiB in 56,622 datagrams |
| trader B sends | 58.2 MiB in 52,194 datagrams |
| TurboPlonk gates | 2048 |
| public signals | 5 |
| proof size | 769 B compressed (1185 B uncompressed) |
| verifying key size | 938 B compressed |

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2.
