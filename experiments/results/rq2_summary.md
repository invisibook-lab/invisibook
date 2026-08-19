# RQ2 — the effect of the round-trip time

Rate cap 1000 Mbit/s, 3 sessions per point. One observation is recorded per session; phase values use the slower trader.

| RTT (ms) | build | prove | share export | local verify | proof core | session total | p95 session |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 134 | 1 275 | 4 491 | 0.0 | 5 852 | 6 210 | 6 573 |
| 10 | 1 210 | 1 216 | 10 520 | 0.0 | 12 923 | 14 713 | 14 784 |
| 30 | 3 249 | 1 160 | 13 483 | 0.0 | 17 921 | 22 476 | 23 842 |
| 60 | 6 365 | 1 153 | 26 711 | 0.0 | 34 148 | 42 886 | 48 349 |
| 100 | 10 507 | 1 217 | 20 452 | 0.0 | 33 264 | 47 489 | 49 231 |

From 0 ms to 100 ms the total grows 7.6x, from 6 210 ms to 47 489 ms.

Traffic per session (both directions): 123.2 MiB.

The relay itself costs 1 273 ms: the same session without the relay (RQ1) takes 4 937 ms, and the 0 ms point here takes 6 210 ms. Every point carries that same hop, so the points compare with each other.
