# Experiments

Each experiment has ONE script. The script builds what it needs, runs the
measurement, writes the raw records, and prints a summary. Results go to
`experiments/results/` (add `--out-dir DIR` to send them somewhere else).

| Experiment | Question | Command |
|---|---|---|
| RQ1 | What does the cryptography cost? | `./experiments/rq1_crypto_overhead.sh` |
| RQ2 | How much does the round-trip time between the traders cost? | `./experiments/rq2_network_latency.sh` |
| RQ3 | What does one complete trade cost, on the traders and on the chain? | `./experiments/rq3_end_to_end.sh` |

Run them one at a time: each measurement uses every core, and two
measurements at once give wrong numbers.

## RQ1 — the cost of the cryptography

Measures the collaborative comparison against a single prover of the SAME
relation and the SAME keys, which is the computational lower bound. Three
configurations run: one prover, two parties in one process with in-memory
channels, and two trader processes that speak QUIC. For each one the
script separates circuit build and witness check, collaborative proving,
authenticated opening, and local verification. It also records the peak
memory of each trader, the traffic each trader sends, and the constant
sizes: circuit gates, proof, and verifying key.

```bash
./experiments/rq1_crypto_overhead.sh                 # 20 runs, 3 warm-up runs
./experiments/rq1_crypto_overhead.sh --runs 5 --warmup 1
```

Time: about 4 minutes with the defaults, plus the build. Memory: about
7 GB — the in-process configuration holds both parties, and the two
trader processes take 1.6 GiB each.

Output:

| File | Content |
|---|---|
| `rq1_raw.json` | every measured run, all three configurations |
| `rq1_traffic.json` | bytes and datagrams each trader sent |
| `rq1_summary.json` | median, 95th percentile, minimum, maximum per phase |
| `rq1_summary.md` | the tables |
| `rq1_phases.csv` | one row per configuration for the stacked bar chart |

## RQ2 — the effect of the round-trip time

The two trader processes speak QUIC through `experiments/netdelay`, a UDP
relay that holds every datagram for half of the wanted round-trip time and
caps the link at a fixed rate. The relay runs in user space, so this sweep
needs no root rights and no `tc`. Everything except the round-trip time
stays equal: the same order, the same witness, the same binaries, the same
machine, and the same rate cap.

```bash
./experiments/rq2_network_latency.sh                       # 0, 10, 30, 60, 100 ms
./experiments/rq2_network_latency.sh --rtts "0 20 50" --runs 5 --rate-mbit 100
```

Time: it grows with the round-trip time, because the protocol is bound by
its rounds. The default sweep took 7 minutes on the reference machine. A
point that does not finish inside `--timeout` seconds is marked `did not
finish` and the sweep continues.

Output:

| File | Content |
|---|---|
| `rq2_rtt<N>.json` | every measured session at that round-trip time |
| `rq2_rtt<N>_traffic.json` | bytes and datagrams the relay carried |
| `rq2_summary.json`, `rq2_summary.md` | median and 95th percentile per point |
| `rq2_latency.csv` | one row per round-trip time for the line chart |

## RQ3 — one complete trade

Runs a whole trade on a live single-node chain with two real trader
processes: order proving and submission, matching, the collaborative
comparison, the on-chain comparison anchor, the two local settlement
proofs, the settlement-message exchange, and the atomic settlement. The
node verifies every proof, and it logs each verification time and each
writing's payload size, which the summary collects.

```bash
./experiments/rq3_end_to_end.sh              # one trade
./experiments/rq3_end_to_end.sh --runs 3     # three trades, one after the other
```

Time: about 3 minutes for the first build, then about 50 seconds per
trade. Memory: about 4 GB, because two collaborative provers run at the
same time. The script needs Go, and it binds the chain ports 7999 and
8999.

Output:

| File | Content |
|---|---|
| `rq3_run<N>_stats.json` | the per-step record the trade wrote |
| `rq3_run<N>.log` | the full log, node lines included |
| `rq3_summary.json`, `rq3_summary.md` | steps, categories, chain costs |

## Shared parts

| Path | Purpose |
|---|---|
| `common.sh` | build, key warm-up, and environment recording |
| `summarize.py` | turns the raw records into JSON, Markdown, and CSV |
| `netdelay/` | the UDP delay relay RQ2 needs (Rust, no dependencies) |

## What the numbers do not include

- The proving keys and the structured reference string come from a fixed
  development seed. Key setup happens before the measurement, so no
  measured run pays for it.
- The Beaver triples come from the mock source. The measurements therefore
  give the cost of the online protocol only, not of a secure offline
  phase.
- Both traders run on one machine. RQ1 and RQ3 use the loopback interface,
  so they carry no wide-area latency; RQ2 adds that latency on purpose.
