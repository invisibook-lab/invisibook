# RQ3 — the end-to-end cost of one trade

5 trade(s). Scenario: one trade: A limit-sells 2 ETH @ 3 (maker), B market-buys 1 ETH with protection 4.

## Wall clock, step by step (ms, median)

| step | trader A | trader B |
|---|---:|---:|
| order proof (Groth16) | 300 | 287 |
| order submission until it lands | 4 008 | 6 010 |
| matching | 4 005 | 4 005 |
| 1 preamble fingerprint | 2 | 0 |
| 2 share inputs + collateral binding | 40 | 40 |
| 3 three-way compare | 14 | 14 |
| 4 signature ferry + exchange | 1 | 1 |
| 5 collaborative prove + local verify | 4 487 | 4 488 |
| 6 on-chain compare anchor (host wait) | 12 017 | 12 020 |
| 7 smaller-side reveal | 2 | 1 |
| 8 payout-note keys + WAL | 1 | 1 |
| session subprocess, total | 16 917 | 16 917 |
| settlement driver, both traders | 29 009 | 29 009 |
| **full trade** | **43 630** | |

## Where the time goes

| category | ms |
|---|---:|
| collaborative cryptography | 4 899 |
| single-prover order proofs | 587 |
| chain waits (blocks and polling) | 26 040 |
| settlement submission, own leg and confirmation | 12 092 |

## What the chain does

| proof | verifications | median (ms) | p95 (ms) |
|---|---:|---:|---:|
| send_order | 10 | 5.16 | 5.68 |
| settle_cozk2p | 5 | 12.21 | 17.06 |
| settle_large | 5 | 4.92 | 5.25 |
| settle_small | 5 | 4.53 | 4.73 |

| writing | submissions | payload each (B) | payload total (B) |
|---|---:|---:|---:|
| RegisterSettleAddr | 10 | 434 | 4340 |
| SendOrder | 10 | 1796 | 17962 |
| SettlePair | 10 | 2385 | 23844 |
| SubmitCompareCoZk2p | 10 | 1999 | 19990 |
| SubmitSettleCheckpoint | 10 | 322 | 3220 |

On-chain payload of one trade: 9488 B. Both traders submit the comparison and the settlement for liveness, so the node receives 13871 B and rejects the second copy of each.

Peak memory per trader: 1.70 GiB (A), 1.69 GiB (B).

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS.
