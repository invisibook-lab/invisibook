# RQ2 — the effect of the round-trip time

Rate cap 1000 Mbit/s, 3 sessions per point, medians of both traders.

| RTT (ms) | build | prove | open | verify | total | p95 total |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 164 | 1 420 | 4 340 | 7.0 | 5 794 | 6 361 |
| 10 | 1 235 | 1 494 | 11 253 | 6.3 | 13 962 | 14 083 |
| 30 | 3 285 | 1 466 | 15 602 | 7.6 | 20 364 | 22 200 |
| 60 | 6 369 | 1 363 | 22 681 | 7.6 | 30 446 | 30 562 |
| 100 | 10 536 | 1 079 | 21 325 | 6.7 | 33 029 | 34 460 |

From 0 ms to 100 ms the total grows 5.7x, from 5 794 ms to 33 029 ms.

Traffic per session (both directions): 117.9 MiB.

The relay itself costs 1 257 ms: the same session without the relay (RQ1) takes 4 537 ms, and the 0 ms point here takes 5 794 ms. Every point carries that same hop, so the points compare with each other.
