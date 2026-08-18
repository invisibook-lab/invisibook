# Settlement — Measurements

> **Status:** Current (2026-08-18, branch `cozk-split`). Every number in
> this document comes from a script in [../experiments](../experiments),
> and each section names the command that makes it. The last section
> keeps the record of the historical 3-party experiment, which is not
> part of the protocol any more.

The protocol has one collaborative step: the two matched traders prove
the quantity comparison together (`cozk2p/`, mpc-jellyfish TurboPlonk
over ark-mpc SPDZ, see [cozk2p_design.md](cozk2p_design.md)). Everything
after that is single-prover Groth16 and chain work. The three experiments
measure that step, its behaviour on a slow link, and the complete trade.

| Experiment | Question | Command |
|---|---|---|
| RQ1 | What does the cryptography cost? | `./experiments/rq1_crypto_overhead.sh` |
| RQ2 | What does the round-trip time between the traders cost? | `./experiments/rq2_network_latency.sh` |
| RQ3 | What does one complete trade cost? | `./experiments/rq3_end_to_end.sh --runs 5` |

## Machine and software

- CPU: 12th Gen Intel Core i9-12900HX, 24 logical processors
- Memory: 29.4 GiB
- OS: Ubuntu 22.04.5 LTS on WSL2, kernel 6.18
- Rust nightly-2025-02-20 (the `cozk2p` workspace), Go 1.26, circom 2.2.3,
  snarkjs 0.7.6, rapidsnark
- Curve BN254 everywhere: collaborative TurboPlonk with a KZG reference
  string from a fixed development seed, and Groth16 for the single-prover
  circuits

Each script writes its own `*_environment.json` with these values, so a
result always carries the machine it came from.

## RQ1 — the cost of the cryptography

```bash
./experiments/rq1_crypto_overhead.sh          # 20 measured runs, 3 warm-up runs
```

The collaborative comparison runs against a single prover of the SAME
relation with the SAME keys. That prover is the lower bound: it does the
identical arithmetic, but it holds both witnesses in one process. Three
configurations run: the single prover, the two parties in one process
with in-memory channels, and two trader processes that speak QUIC.

Medians of 20 sessions, in milliseconds:

| configuration | build | prove | open | verify | total | p95 total |
|---|---:|---:|---:|---:|---:|---:|
| single prover | — | 524 | — | 7.4 | 531 | 715 |
| two parties, one process | 16 | 1 445 | 2 869 | 8.5 | 4 282 | 4 617 |
| two processes, QUIC | 95 | 1 317 | 3 129 | 6.1 | 4 537 | 4 680 |

| metric | value |
|---|---:|
| peak memory per trader | 1.57 GiB (p95 1.59 GiB) |
| traffic, trader A sends | 60.0 MiB in 56 622 datagrams |
| traffic, trader B sends | 58.2 MiB in 52 194 datagrams |
| TurboPlonk gates | 2 048 |
| public signals | 5 |
| proof | 769 B compressed |
| verifying key | 938 B compressed |

Reading the numbers:

- **Collaboration costs 8.5x the single prover** — 4.5 s against 531 ms.
  The two traders prove the same statement without a helper node and
  without either quantity leaving its owner.
- **The open phase is 69 % of that time.** `ark-mpc` builds a lazy
  dataflow graph, so the authenticated open drains the whole graph and
  pays for its network rounds. The prove phase, 29 %, is mostly local
  work on shares.
- **The transport is almost free on this machine.** Two processes over
  QUIC cost 6 % more than the same session in one process (4 537 ms
  against 4 282 ms), because a loopback round trip is short. RQ2 shows
  what happens when it is not.
- **Memory stays near 1.6 GiB per trader**, which any current laptop
  has. The proof stays 769 B, so the chain's cost does not change with
  the trade.
- **The traffic is large for the circuit size**: about 59 MiB per trader
  for 2 048 gates, in more than 50 000 datagrams. `ark-mpc` serializes
  its messages as JSON, which is where that volume comes from.


## RQ2 — the effect of the round-trip time

```bash
./experiments/rq2_network_latency.sh          # 0, 10, 30, 60, 100 ms; 3 sessions each
```

The two trader processes speak QUIC through
[`experiments/netdelay`](../experiments/netdelay), a UDP relay that holds
every datagram for half of the wanted round-trip time and caps the link
at 1 Gbit/s. Only the round-trip time changes between points.

Medians of 3 sessions, in milliseconds:

| RTT (ms) | build | prove | open | verify | total | p95 total |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 164 | 1 420 | 4 340 | 7.0 | 5 794 | 6 361 |
| 10 | 1 235 | 1 494 | 11 253 | 6.3 | 13 962 | 14 083 |
| 30 | 3 285 | 1 466 | 15 602 | 7.6 | 20 364 | 22 200 |
| 60 | 6 369 | 1 363 | 22 681 | 7.6 | 30 446 | 30 562 |
| 100 | 10 536 | 1 079 | 21 325 | 6.7 | 33 029 | 34 460 |

Reading the numbers:

- **The protocol is bound by its rounds, not by its bandwidth.** From
  0 ms to 100 ms the total grows 5.7x, from 5.8 s to 33 s. One session
  moves 118 MiB in both directions, which needs about 1 s at 1 Gbit/s,
  so the link speed is not what costs the time.
- **The local work does not move.** The prove phase stays near 1.4 s at
  every point, because it computes on shares that are already there.
  The build phase and the open phase grow with the round-trip time:
  they share the inputs and they drain the dataflow graph, and both of
  those wait for the counterparty.
- **The boundary between build and open moves at the high points.** At
  100 ms the build phase takes work the open phase did at 60 ms, because
  the fabric evaluates lazily. Use the total, not one phase, to compare
  the points.
- **The relay costs 1.3 s of the 0 ms point.** The same session without
  the relay (RQ1) takes 4.5 s. Every point carries that same hop, so the
  points compare with each other.
- **A same-region deployment is comfortable, a global one is not.** At
  10 ms — one metropolitan area — the settlement cryptography takes 14 s.
  At 100 ms — between continents — it takes 33 s.


## RQ3 — one complete trade

```bash
./experiments/rq3_end_to_end.sh --runs 5
```

One trade runs on a live single-node chain with two real trader
processes: trader A sells 2 ETH at price 3 and is the maker, trader B
buys 1 ETH at the same price. The node verifies every proof. The block
interval is 3 s and the wallet polls the order state every 2 s, so each
chain row is quantized by both periods.

Medians of 5 trades, in milliseconds:

| step | trader A | trader B |
|---|---:|---:|
| 0 `SendOrder` proof (rapidsnark) | 192 | 193 |
| 0 `SendOrder` submission until it lands | 4 007 | 6 010 |
| 0 matching, both orders `Matched` | 4 006 | 4 006 |
| 1 preamble fingerprint | 2 | 0 |
| 2 share inputs and bind the collateral | 43 | 44 |
| 3 three-way compare | 14 | 13 |
| 4 signature ferry and exchange | 1 | 1 |
| 5 collaborative prove and local verify | 3 646 | 3 643 |
| 6 on-chain comparison anchor (chain wait) | 6 010 | 6 010 |
| 7 smaller-side reveal | 2 | 2 |
| 8 payout-note keys and write-ahead log | 1 | 1 |
| **session subprocess, total** | **10 034** | **10 034** |
| 9, 9', R, 10 own settle leg, leg exchange, `SettlePair`, confirmation | 10 110 | 10 110 |
| **settlement, both traders** | **20 144** (p95 22 094) | |
| **full trade** | **34 553** (p95 36 507) | |

Where the time goes:

| category | ms | share of the trade |
|---|---:|---:|
| chain waits (blocks and polling) | 20 033 | 58 % |
| settlement submission, own leg, confirmation | 10 110 | 29 % |
| collaborative cryptography | 4 024 | 12 % |
| single-prover order proofs | 385 | 1 % |

What the chain does, per trade:

| proof | verifications | median (ms) | p95 (ms) |
|---|---:|---:|---:|
| `send_order` (Groth16) | 2 | 4.83 | 4.96 |
| `settle_cozk2p` (collaborative PLONK) | 1 | 12.37 | 13.39 |
| `settle_large` (Groth16) | 1 | 4.62 | 4.70 |
| `settle_small` (Groth16) | 1 | 4.42 | 4.45 |

| writing | payload (B) |
|---|---:|
| `SendOrder`, one per order | 1 522 |
| `SubmitCompareCoZk2p` | 1 999 |
| `SettlePair` | 2 221 |
| **one trade** | **7 264** |

Reading the numbers:

- **The chain decides the user-visible latency.** Blocks and polling are
  58 % of the trade, and the settlement tail is another 29 %, most of
  which is the wait for the settlement block. The cryptography is 12 %.
  A shorter block interval, or a subscription instead of 2 s polling,
  takes more time out of a trade than any change to the prover.
- **Verification is cheap and constant.** The node verifies the
  collaborative proof in 12.4 ms and each Groth16 proof in about 4.6 ms.
  The proof sizes do not change with the trade, so this cost is flat.
- **A trade puts 7 264 B on chain.** Both traders submit the comparison
  and the settlement, for liveness, so the node receives 11 479 B and
  rejects the second copy of each.
- **The collaborative step measures 3.6 s here against 4.5 s in RQ1.**
  Same code, different harness: RQ1 runs 20 heavy sessions back to back,
  and this run has idle chain waits between them. Treat the second digit
  of the cryptographic figure as noise.


## What the numbers do not include

- **The offline phase.** The Beaver triples come from the mock source.
  The measurements give the cost of the online protocol only.
- **A trusted setup.** The KZG reference string comes from a public seed,
  so the proofs carry no soundness. Key generation happens before the
  measurement, so no measured run pays for it.
- **A real network.** Both traders run on one machine. RQ1 and RQ3 use
  the loopback interface; RQ2 adds the round-trip time on purpose.

## Historical record — the 3-party REP3 experiment

> The 3-party path (`lib/cozk`, co-snarks, Groth16) lives only in git
> history, on the `cozk-settlement` branch. It used a helper node, so it
> needed an honest majority; the protocol uses two parties, which is the
> trust model the application has. The record stays here because it
> explains that decision. The circuit and the model changed since, so
> these numbers do not compare with the sections above.

### Environment

- CPU: 12th Gen Intel Core i9-12900HX (24 threads), 29 GiB RAM
- OS: Linux 6.18 (WSL2); Rust nightly; circom 2.2.3; snarkjs 0.7.6; rapidsnark
- Curve BN254, Groth16, dev trusted setup (pot13)

### Circuit

| metric | value |
|---|---|
| R1CS constraints (`--O2`) | 3600 |
| public signals | 15 (7 outputs + 8 inputs) |
| private inputs per trader | 9 |

### Results

Timings are mean ± population stdev over the measured runs.

#### Proving time

| configuration | witness gen | prove | total | notes |
|---|---|---|---|---|
| **single prover — rapidsnark** (production) | 60 ± 15 ms | 74 ± 18 ms | ~134 ms | witness via circom wasm + rapidsnark |
| **single prover — arkworks** (plain, the code path MPC lifts) | — | 152 ± 17 ms | ~152 ms | pure-Rust reference |
| **co-zk 3-party, in-memory channels** (compute cost, no network latency) | 136 ± 40 ms | 274 ± 68 ms | 416 ± 93 ms | per-node; local verify 6 ms |
| **co-zk 3-party, TCP loopback** (compute + real round-trips) | ~670 ms | ~87 ms | ~1.6–2.0 s | incl. per-process zkey load; see note |

Reading the numbers:

- **Compute overhead of collaboration is ≈2–3×** a single arkworks prover
  (416 ms total vs 152 ms). This is consistent with Ozdemir–Boneh's finding
  that honest-majority collaborative Groth16 runs at ~1–2× a single prover
  plus the MPC witness-extension cost (which a single prover skips entirely —
  it generates the witness locally with a wasm circuit in ~60 ms, whereas the
  MPC VM evaluates Poseidon rounds and comparators on shared values).
- **Network round-trips dominate over TCP.** Witness extension jumps from
  ~136 ms (in-memory) to ~670 ms (loopback TCP): the Poseidon-heavy,
  comparator-heavy extension is round-bound, so each RTT is paid many times.
  The Groth16 prove phase is nearly RTT-insensitive (~87 ms both ways) because
  it is one degree-2 Beaver layer over otherwise-local MSM/FFT work. On a real
  LAN this gap sits between the two; on WAN, witness extension is the term to
  optimize (batching / fewer rounds).

#### Memory (peak RSS)

| configuration | peak RSS |
|---|---|
| single prover — rapidsnark | ~8 MB |
| co-zk per node (TCP, own process) | ~109 MB |

Each MPC node loads the full Groth16 proving key (`.zkey`) plus the co-circom
MPC VM state, hence ~109 MB per process vs rapidsnark's ~8 MB. This is a
constant per node, independent of trade size.

#### Proof size

| encoding | bytes |
|---|---|
| snarkjs `proof.json` (on-wire, what the chain receives) | ~706–725 |
| arkworks compressed (2×G1 + 1×G2, BN254) | 128 |

**The collaborative proof is byte-for-byte a normal Groth16 proof.** It is
produced from the same snarkjs zkey and verifies against the same vk via
go-rapidsnark — the chain's verification path, on-chain proof size, and gas
cost are identical to the single-prover circuits. The entire cost of hiding
the amounts is on the proving side; the verifier sees nothing different. This
is exactly what the indistinguishability argument in
the historical design needs: a constant-size proof plus public
commitments, simulatable and hiding.

#### Communication (co-zk, per node, in-memory accounting)

| phase | bytes sent (party 0 / A) |
|---|---|
| witness extension | ~141 KiB |
| Groth16 prove | ~1 KiB (party A); the REP3 "next" neighbour carries more (~850 KiB observed on party B) |

Communication is dominated by witness extension and is a few hundred KiB per
node for this ~3.6k-constraint circuit — trivial on any real link, matching
the Θ(n) field-element communication bound for collaborative Groth16.

### Note on the TCP loopback harness

The 3-process TCP mode is intended for a true per-machine memory/latency
measurement. On this single loopback host the co-snarks `TcpNetwork`
connection setup occasionally races and one node wedges in the first
witness-extension round (surfaced as a `recv` timeout); the harness retries a
run on fresh ports. The per-process numbers above (witness ~670 ms, prove
~87 ms, RSS ~109 MB, proof 720 B) are from clean completed runs. In-memory
3-party numbers are deterministic and are the primary compute-overhead
measurement; they run in CI (`cargo test -p cozk`).

