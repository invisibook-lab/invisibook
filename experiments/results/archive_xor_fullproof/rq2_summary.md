# RQ2 — the effect of the round-trip time

Rate cap 1000 Mbit/s, 3 sessions per point. One observation is recorded per session; phase values use the slower trader.

| RTT (ms) | build | prove | open | verify | proof core | session total | p95 session |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 94 | 1 336 | 4 930 | 7.7 | 6 360 | 6 660 | 6 756 |
| 10 | 1 202 | 1 298 | 13 487 | 7.0 | 15 850 | 17 734 | 18 290 |
| 30 | 3 307 | 1 249 | 21 027 | 6.8 | 25 557 | 30 234 | 31 214 |
| 60 | 6 399 | 1 268 | 18 844 | 6.9 | 26 606 | 35 486 | 36 531 |
| 100 | 10 527 | 1 183 | 26 277 | 7.5 | 37 967 | 52 533 | 54 949 |

From 0 ms to 100 ms the total grows 7.9x, from 6 660 ms to 52 533 ms.

Traffic per session (both directions): 123.4 MiB.

The relay itself costs 1 510 ms: the same session without the relay (RQ1) takes 5 150 ms, and the 0 ms point here takes 6 660 ms. Every point carries that same hop, so the points compare with each other.
