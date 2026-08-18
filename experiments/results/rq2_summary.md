# RQ2 — the effect of the round-trip time

Rate cap 1000 Mbit/s, 3 sessions per point. One observation is recorded per session; phase values use the slower trader.

| RTT (ms) | build | prove | open | verify | proof core | session total | p95 session |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 119 | 1 421 | 4 331 | 5.6 | 5 845 | 6 123 | 7 739 |
| 10 | 1 233 | 1 063 | 10 088 | 7.1 | 12 313 | 14 169 | 14 628 |
| 30 | 3 298 | 1 160 | 15 392 | 7.1 | 19 761 | 24 465 | 26 442 |
| 60 | 6 376 | 1 279 | 21 716 | 7.2 | 29 351 | 38 320 | 42 571 |
| 100 | 10 471 | 1 142 | 20 739 | 6.6 | 32 295 | 46 948 | 48 423 |

From 0 ms to 100 ms the total grows 7.7x, from 6 123 ms to 46 948 ms.

Traffic per session (both directions): 123.2 MiB.

The relay itself costs 984 ms: the same session without the relay (RQ1) takes 5 139 ms, and the 0 ms point here takes 6 123 ms. Every point carries that same hop, so the points compare with each other.
