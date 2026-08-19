# RQ3 — the end-to-end cost of one trade

5 trade(s). Scenario: one trade: A limit-sells 2 ETH @ 3 (maker), B market-buys 1 ETH with protection 4.

## Wall clock, step by step (ms, median)

| step | trader A | trader B |
|---|---:|---:|
| order proof (Groth16) | 325 | 308 |
| order submission until it lands | 4 007 | 6 010 |
| **order phase: proof start → confirmed** | **4 334** | **6 318** |
| matching | 4 006 | 4 006 |
| 1 preamble fingerprint | 2 | 0 |
| 2 share inputs + collateral binding | 54 | 54 |
| 3 three-way compare | 19 | 19 |
| 4 signature ferry + exchange | 1 | 1 |
| 5 collaborative prove + native share export | 3 948 | 3 931 |
| 6 on-chain compare anchor (host wait) | 6 010 | 6 011 |
| 7 payout-note keys + pre-reveal WAL | 1 | 1 |
| 8 smaller-side reveal | 0 | 0 |
| 9 outputs + complete WAL | 0 | 0 |
| session subprocess, total | 10 366 | 10 364 |
| settlement driver, both traders | 20 498 | 20 498 |
| **full trade** | **35 187** | |

## Paper phase boundaries (ms, median)

The settlement rows use the critical-path trader selected separately in each run. Rendezvous, comparison, and final settlement are non-overlapping.

| phase | median (ms) | p95 (ms) |
|---|---:|---:|
| order, maker | 4 334 | 5 924 |
| order, taker | 6 318 | 6 334 |
| rendezvous (reported separately) | 4 020 | 5 624 |
| comparison: MPC start → both proof shares verified | 10 082 | 10 268 |
| final settlement: comparison confirmed → settlement confirmed | 6 309 | 6 380 |
| **complete trade** | **35 187** | **37 146** |

## Cryptographic work (ms)

| operation | trader A | trader B |
|---|---:|---:|
| order Groth16 generation | 325 | 308 |
| settlement Groth16 generation | 121 | 111 |
| collaborative comparison proof core (slower trader) | 3 947 | — |

## What the chain does

| proof | verifications | median (ms) | p95 (ms) |
|---|---:|---:|---:|
| send_order | 10 | 5.35 | 8.39 |
| settle_cozk2p | 5 | 12.46 | 14.93 |
| settle_large | 10 | 4.99 | 5.15 |
| settle_small | 10 | 4.84 | 5.99 |

| writing | submissions | payload each (B) | payload total (B) |
|---|---:|---:|---:|
| RegisterSettleAddr | 10 | 434 | 4340 |
| SendOrder | 10 | 1797 | 17969 |
| SubmitCompareCoZk2pShare | 10 | 2008 | 20080 |
| SubmitSettleLeg | 10 | 1544 | 15451 |

On-chain payload of one trade: 11567 B. This includes one identity-bound comparison share and one owner-bound settlement leg from each trader; all four submissions are required and accepted. Each settlement leg is verified when submitted and re-verified before the pair executes atomically.

Peak memory per trader: 1.68 GiB (A), 1.68 GiB (B).

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS.
