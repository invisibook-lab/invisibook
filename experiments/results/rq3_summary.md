# RQ3 — the end-to-end cost of one trade

5 trade(s). Scenario: one trade: A sells 2 ETH @ 3 (maker), B buys 1 ETH @ 3.

## Wall clock, step by step (ms, median)

| step | trader A | trader B |
|---|---:|---:|
| order proof (Groth16) | 192 | 193 |
| order submission until it lands | 4 007 | 6 010 |
| matching | 4 006 | 4 006 |
| 1 preamble fingerprint | 2 | 0 |
| 2 share inputs + collateral binding | 43 | 44 |
| 3 three-way compare | 14 | 13 |
| 4 signature ferry + exchange | 1 | 1 |
| 5 collaborative prove + local verify | 3 646 | 3 643 |
| 6 on-chain compare anchor (host wait) | 6 010 | 6 010 |
| 7 smaller-side reveal | 2 | 2 |
| 8 payout-note keys + WAL | 1 | 1 |
| session subprocess, total | 10 034 | 10 034 |
| settlement driver, both traders | 20 144 | 20 144 |
| **full trade** | **34 553** | |

## Where the time goes

| category | ms |
|---|---:|
| collaborative cryptography | 4 024 |
| single-prover order proofs | 385 |
| chain waits (blocks and polling) | 20 033 |
| settlement submission, own leg and confirmation | 10 110 |

## What the chain does

| proof | verifications | median (ms) | p95 (ms) |
|---|---:|---:|---:|
| send_order | 10 | 4.83 | 4.96 |
| settle_cozk2p | 5 | 12.37 | 13.39 |
| settle_large | 5 | 4.62 | 4.70 |
| settle_small | 5 | 4.42 | 4.45 |

| writing | submissions | payload each (B) | payload total (B) |
|---|---:|---:|---:|
| SendOrder | 10 | 1522 | 15215 |
| SettlePair | 10 | 2221 | 22194 |
| SubmitCompareCoZk2p | 10 | 1999 | 19990 |

On-chain payload of one trade: 7264 B. Both traders submit the comparison and the settlement for liveness, so the node receives 11479 B and rejects the second copy of each.

Peak memory per trader: 1.59 GiB (A), 1.57 GiB (B).

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS.
