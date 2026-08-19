# RQ3 — the end-to-end cost of one trade

5 trade(s). Scenario: one trade: A limit-sells 2 ETH @ 3 (maker), B market-buys 1 ETH with protection 4.

## Wall clock, step by step (ms, median)

| step | trader A | trader B |
|---|---:|---:|
| order proof (Groth16) | 312 | 300 |
| order submission until it lands | 4 008 | 6 009 |
| **order phase: proof start → confirmed** | **4 320** | **6 309** |
| matching | 4 006 | 4 006 |
| 1 preamble fingerprint | 2 | 0 |
| 2 share inputs + collateral binding | 48 | 48 |
| 3 three-way compare | 15 | 15 |
| 4 signature ferry + exchange | 1 | 1 |
| 5 collaborative prove + local verify | 5 101 | 5 095 |
| 6 on-chain compare anchor (host wait) | 6 016 | 6 016 |
| 7 smaller-side reveal | 3 | 2 |
| 8 payout-note keys + WAL | 2 | 1 |
| session subprocess, total | 11 781 | 11 780 |
| settlement driver, both traders | 19 856 | 19 856 |
| **full trade** | **34 478** | |

## Paper phase boundaries (ms, median)

The settlement rows use the critical-path trader selected separately in each run. Rendezvous, comparison, and final settlement are non-overlapping.

| phase | median (ms) | p95 (ms) |
|---|---:|---:|
| order, maker | 4 320 | 4 389 |
| order, taker | 6 309 | 6 321 |
| rendezvous (reported separately) | 4 019 | 5 624 |
| comparison: MPC start → both proof shares verified | 11 545 | 13 565 |
| final settlement: comparison confirmed → settlement confirmed | 4 477 | 6 542 |
| **complete trade** | **34 478** | **40 323** |

## Cryptographic work (ms)

| operation | trader A | trader B |
|---|---:|---:|
| order Groth16 generation | 312 | 300 |
| settlement Groth16 generation | 165 | 187 |
| collaborative comparison proof core (slower trader) | 5 101 | — |

## What the chain does

| proof | verifications | median (ms) | p95 (ms) |
|---|---:|---:|---:|
| send_order | 10 | 5.27 | 5.47 |
| settle_cozk2p | 5 | 11.97 | 20.18 |
| settle_large | 10 | 5.12 | 5.45 |
| settle_small | 10 | 4.84 | 5.57 |

| writing | submissions | payload each (B) | payload total (B) |
|---|---:|---:|---:|
| RegisterSettleAddr | 10 | 434 | 4340 |
| SendOrder | 10 | 1796 | 17965 |
| SubmitCompareCoZk2pShare | 10 | 1983 | 19830 |
| SubmitSettleLeg | 10 | 1545 | 15450 |

On-chain payload of one trade: 11517 B. This includes one identity-bound comparison share and one owner-bound settlement leg from each trader; all four submissions are required and accepted. Each settlement leg is verified when submitted and re-verified before the pair executes atomically.

Peak memory per trader: 1.69 GiB (A), 1.68 GiB (B).

Machine: 12th Gen Intel(R) Core(TM) i9-12900HX, 24 logical CPUs, 29.4 GiB, Ubuntu 22.04.5 LTS.
