# RQ1 — the cost of the cryptography

Runs: 20 sessions over QUIC (two traders each), 20 in-process sessions, 20 single-prover runs.
One observation is recorded per session; two-process phase values use the slower trader.
Protocol: native-final-kzg-spdz-share-v1.

## Latency per phase and session (ms)

| configuration | build | prove | share export | local verify | proof core | session total | p95 session |
|---|---:|---:|---:|---:|---:|---:|---:|
| single prover | — | 474 | — | 7.5 | 481 | 481 | 767 |
| two parties, one process | 19 | 1 530 | 2 389 | 0.0 | 3 982 | 4 017 | 11 109 |
| two processes, QUIC | 73 | 1 321 | 3 240 | 0.0 | 4 652 | 4 937 | 5 739 |

Overhead over the single prover: 8.4x in one process, 10.3x over QUIC.

## Resources and constant sizes

| metric | value |
|---|---:|
| peak memory per trader (median) | 1.68 GiB |
| peak memory per trader (p95) | 1.70 GiB |
| trader A sends | 62.2 MiB in 55,797 datagrams |
| trader B sends | 61.0 MiB in 57,873 datagrams |
| TurboPlonk gates | 2048 |
| public signals | 6 |
| proof size | 769 B compressed (1185 B uncompressed) |
| comparison share size | 771 B compressed |
| verifying key size | 938 B compressed |

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS, kernel 6.18.33.2-microsoft-standard-WSL2.
