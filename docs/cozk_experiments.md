# Settlement — Measurements

> **Status:** Current final rerun (2026-08-19). The active protocol in every
> RQ1/RQ2/RQ3 record is **`native-final-kzg-spdz-share-v1`**. Every current
> number comes from a script in [../experiments](../experiments), and each
> section names the command that produces it. The final section separately
> preserves the historical 3-party experiment, which is no longer part of the
> protocol.

The protocol has one collaborative step: the two matched traders prove the
quantity comparison together (`cozk2p/`, mpc-jellyfish TurboPlonk over
ark-mpc SPDZ, see [cozk2p_design.md](cozk2p_design.md)). Both submissions
repeat the same Fiat–Shamir-opened canonical template; only the final two
unopened KZG G1 points are native SPDZ value shares. The chain matches the
templates, adds each point-share pair, constructs the standard proof, and
verifies it. Neither trader reconstructs or locally verifies a complete
proof. After the on-chain comparison gate, both sessions exchange and WAL
their payout-note keys, the smaller side reveals, and only then do the owners
finish independent single-prover Groth16 and chain work; no peer/MPC
dependency remains after reveal. The three experiments measure that flow, its
behaviour on a slow link, and the complete trade.

| Experiment | Question | Command |
|---|---|---|
| RQ1 | What does the cryptography cost? | `./experiments/rq1_crypto_overhead.sh` |
| RQ2 | What does the round-trip time between the traders cost? | `./experiments/rq2_network_latency.sh` |
| RQ3 | What does one complete trade cost? | `./experiments/rq3_end_to_end.sh --runs 5` |

## Machine and software

- CPU: 12th Gen Intel Core i9-12900HX, 24 logical processors
- Memory: 29.4 GiB
- OS: Ubuntu 22.04.5 LTS on WSL2, kernel
  6.18.33.2-microsoft-standard-WSL2
- Rust nightly-2025-02-20 (the `cozk2p` workspace), Go 1.26, circom 2.2.3,
  snarkjs 0.7.6, rapidsnark
- Curve BN254 everywhere: collaborative TurboPlonk with a KZG reference
  string from a fixed development seed, and Groth16 for the single-prover
  circuits

Each script writes its own `*_environment.json` with these values, so a
result always carries the machine it came from.

## Measurement and comparison caveats

- RQ1 has 20 observations per configuration, RQ2 only 3 sessions per RTT,
  and RQ3 only 5 trades. Medians and interpolated p95 values are descriptive;
  the RQ2/RQ3 samples are too small for tail-latency or significance claims.
- The archived XOR-full-proof run and the native-share rerun were sequential,
  not paired or interleaved. Percentage changes therefore include ordinary
  scheduler, cache, chain-block, and polling variation. They show the observed
  runs, not a causal confidence interval.
- Old `open_ms` and new `share_export_ms` are intentionally **not** compared
  by percentage. The old phase reconstructed/opened a standard proof; the new
  phase materializes and exports the unopened native final-point share. Only
  session totals and other unchanged semantic boundaries are like-for-like.
- RQ1/RQ2 phase boundaries move because ark-mpc evaluates a lazy dataflow
  graph. Use session total for cross-run conclusions, especially with only
  three RQ2 samples.

## RQ1 — the cost of the cryptography

```bash
./experiments/rq1_crypto_overhead.sh          # 20 measured runs, 3 warm-up runs
```

The collaborative comparison runs against a single prover of the SAME
relation with the SAME keys. That prover is the lower bound: it does the
identical arithmetic, but it holds both witnesses in one process. Three
configurations run: the single prover, the two parties in one process
with in-memory channels, and two trader processes that speak QUIC.

Medians of 20 sessions, in milliseconds. One two-process observation is one
session; phase values use its slower trader.

| configuration | build | prove | share export | local verify | proof core | session total | p95 session |
|---|---:|---:|---:|---:|---:|---:|---:|
| single prover | — | 474 | — | 7.5 | 481 | 481 | 767 |
| two parties, one process | 19 | 1 530 | 2 389 | 0.0 | 3 982 | 4 017 | 11 109 |
| two processes, QUIC | 73 | 1 321 | 3 240 | 0.0 | 4 652 | 4 937 | 5 739 |

| metric | value |
|---|---:|
| peak memory per trader | 1.68 GiB (p95 1.70 GiB) |
| traffic, trader A sends | 62.2 MiB in 55 797 datagrams |
| traffic, trader B sends | 61.0 MiB in 57 873 datagrams |
| TurboPlonk gates | 2 048 |
| public signals | 6 |
| standard proof | 769 B compressed (1 185 B uncompressed) |
| native comparison share | 771 B compressed |
| verifying key | 938 B compressed |

Reading the numbers:

- **Collaboration costs 8.4x in process and 10.3x over QUIC** relative to
  the 481 ms single prover. The two traders prove the same statement without
  a helper node while each API supplies only its owner's quantity. The current
  predictable preprocessing masks do not make that interface private; see
  “What the numbers do not include” below.
- **Zero local-verify time is intentional.** A session exports only its native
  unopened point share; the chain constructs and verifies the complete proof
  after both identity-bound submissions arrive.
- **Share export is not merely a 771-byte serialization.** It is where the
  lazy fabric materializes the final shared proof state, so it includes most
  network-dependent dataflow evaluation.
- **Loopback QUIC adds about 920 ms over the in-process median** (4 937 ms
  versus 4 017 ms). RQ2 isolates the effect of longer round trips.
- **Memory stays near 1.7 GiB per trader.** The signed on-chain request is
  larger than the 771-byte share itself, but both are constant-sized.
- **Traffic remains large for the circuit size:** roughly 61–62 MiB sent by
  each trader for 2 048 gates, in more than 55 000 datagrams.


## RQ2 — the effect of the round-trip time

```bash
./experiments/rq2_network_latency.sh          # 0, 10, 30, 60, 100 ms; 3 sessions each
```

The two trader processes speak QUIC through
[`experiments/netdelay`](../experiments/netdelay), a UDP relay that holds
every datagram for half of the wanted round-trip time and caps the link
at 1 Gbit/s. Only the round-trip time changes between points.

Medians of 3 sessions, in milliseconds. Each phase uses the slower trader.

| RTT (ms) | build | prove | share export | local verify | proof core | session total | p95 session |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 134 | 1 275 | 4 491 | 0.0 | 5 852 | 6 210 | 6 573 |
| 10 | 1 210 | 1 216 | 10 520 | 0.0 | 12 923 | 14 713 | 14 784 |
| 30 | 3 249 | 1 160 | 13 483 | 0.0 | 17 921 | 22 476 | 23 842 |
| 60 | 6 365 | 1 153 | 26 711 | 0.0 | 34 148 | 42 886 | 48 349 |
| 100 | 10 507 | 1 217 | 20 452 | 0.0 | 33 264 | 47 489 | 49 231 |

Reading the numbers:

- **The protocol is bound by its rounds, not by its bandwidth.** From
  0 ms to 100 ms the observed total grows 7.6x, from 6.2 s to 47.5 s. One
  session moves 123.2 MiB in both directions, which needs about 1 s at 1 Gbit/s,
  so the link speed is not what costs the time.
- **The local work does not move much.** The prove phase stays near 1.2 s at
  every point, because it computes on shares that are already there.
  The build and share-export phases pay for counterparty round trips.
- **The phase split is non-monotonic.** The 60 ms share-export median exceeds
  the 100 ms value even though the 100 ms session total is higher. Lazy
  evaluation and three-sample scheduling noise move work across phase
  boundaries; do not interpret one phase as a monotone network model.
- **The relay costs 1.27 s at the 0 ms point.** The same session without
  the relay (RQ1) takes 4.94 s. Every point carries that same hop, so the
  points compare with each other.
- **The observed WAN sensitivity is material.** At 10 ms the measured
  comparison session takes 14.7 s; at 100 ms it takes 47.5 s. These are
  three-session medians, not capacity or tail guarantees.


## RQ3 — one complete trade

```bash
./experiments/rq3_end_to_end.sh --runs 5
```

One trade runs on a live single-node chain with two real trader
processes: trader A sells 2 ETH at price 3 and is the maker, trader B
market-buys 1 ETH with protection price 4. The node verifies every proof. The block
interval is 3 s and the wallet polls the order state every 2 s, so each
chain row is quantized by both periods.

Medians of 5 trades, in milliseconds:

| step | trader A | trader B |
|---|---:|---:|
| order proof (Groth16) | 325 | 308 |
| order submission until it lands | 4 007 | 6 010 |
| **order proof start → confirmed** | **4 334** | **6 318** |
| matching, both orders `Matched` | 4 006 | 4 006 |
| 1 preamble fingerprint | 2 | 0 |
| 2 share inputs and bind the collateral | 54 | 54 |
| 3 three-way compare | 19 | 19 |
| 4 signature ferry and exchange | 1 | 1 |
| 5 collaborative prove + native share export | 3 948 | 3 931 |
| 6 on-chain comparison anchor (host wait) | 6 010 | 6 011 |
| **7 payout-note keys + pre-reveal WAL** | **1** | **1** |
| **8 smaller-side reveal** | **<1** | **<1** |
| **9 outputs + complete WAL** | **<1** | **<1** |
| session subprocess, total | 10 366 | 10 364 |
| settlement driver, both traders | 20 498 | 20 498 |
| **full trade** | **35 187** (p95 37 146) | |

The app records semantic phase boundaries directly. The critical-path trader
is selected separately per run; rendezvous, comparison, and final settlement
are non-overlapping. Settlement-proof generation is shown separately because
it is contained inside the final-settlement window.

| semantic phase | median (ms) | p95 (ms) |
|---|---:|---:|
| order, maker | 4 334 | 5 924 |
| order, taker | 6 318 | 6 334 |
| rendezvous | 4 020 | 5 624 |
| comparison: MPC start → both proof shares verified | 10 082 | 10 268 |
| final settlement: comparison confirmed → settlement confirmed | 6 309 | 6 380 |
| **complete trade** | **35 187** | **37 146** |

| cryptographic work | trader A (ms) | trader B (ms) |
|---|---:|---:|
| order Groth16 generation | 325 | 308 |
| settlement Groth16 generation | 121 | 111 |
| collaborative comparison proof core (slower trader) | 3 947 | — |

What the chain does across all five trades:

| proof | verifications | median (ms) | p95 (ms) |
|---|---:|---:|---:|
| `send_order` (Groth16) | 10 | 5.35 | 8.39 |
| `settle_cozk2p` (collaborative PLONK) | 5 | 12.46 | 14.93 |
| `settle_large` (Groth16) | 10 | 4.99 | 5.15 |
| `settle_small` (Groth16) | 10 | 4.84 | 5.99 |

The counts above cover all five trades. Each settlement leg is verified when
submitted and re-verified before the pair executes atomically.

| writing | submissions | median payload each (B) | observed total (B) |
|---|---:|---:|---:|
| `RegisterSettleAddr` | 10 | 434 | 4 340 |
| `SendOrder` | 10 | 1 797 | 17 969 |
| `SubmitCompareCoZk2pShare` | 10 | 2 008 | 20 080 |
| `SubmitSettleLeg` | 10 | 1 544.5 | 15 451 |
| **effective payload per trade** | | | **11 567** |

Reading the numbers:

- **The chain schedule dominates the user-visible boundaries.** The 3 s block
  interval and 2 s polling cadence quantize order landing, the comparison
  anchor, and the 6.3 s final-settlement phase. A subscription or shorter
  block interval targets a different cost than prover optimization.
- **Verification is cheap and constant.** The node verifies the
  collaborative proof in 12.46 ms and each settlement Groth16 proof in about
  4.8–5.0 ms.
  The proof sizes do not change with the trade, so this cost is flat.
- **A trade puts 11 567 effective bytes on chain.** It has two accepted
  identity-bound comparison-share submissions and two accepted owner-bound
  settlement legs, plus order and rendezvous writings. There is no rejected
  duplicate one-shot comparison or `SettlePair` request in this protocol.
- **The comparison proof core is 3.95 s here versus a 4.65 s RQ1 QUIC
  median.** The harnesses schedule work differently, and RQ3 has only five
  runs; this difference is descriptive rather than an optimization claim.

## Archived XOR full-proof vs. native final-KZG share

The reproducible comparison is generated by
[`compare_protocol_results.py`](../experiments/compare_protocol_results.py)
from `experiments/results/archive_xor_fullproof/{rq1,rq2,rq3}_summary.json`
and the current summaries. Its generated
[JSON](../experiments/results/protocol_comparison.json) and
[Markdown](../experiments/results/protocol_comparison.md) retain the exact
floating-point values used below. “Old” is the equal-length XOR split of a complete
standard proof; “new” is `native-final-kzg-spdz-share-v1`, where only the two
final unopened KZG points remain native SPDZ value shares. Change is
`(new - old) / old`, so a negative value is a reduction.

### RQ1 core results

| median session total | old (ms) | new (ms) | change |
|---|---:|---:|---:|
| single prover | 425.07 | 480.80 | +13.11 % |
| two-party in-process | 3 962.34 | 4 016.72 | +1.37 % |
| two-party QUIC | 5 150.06 | 4 936.51 | −4.15 % |

| constant-size / traffic metric | old | new | change |
|---|---:|---:|---:|
| comparison material per party (B) | 769 | 771 | +0.26 % |
| A → B traffic (B) | 65 466 086 | 65 201 409 | −0.40 % |
| B → A traffic (B) | 64 277 160 | 63 917 197 | −0.56 % |
| both directions (B) | 129 743 246 | 129 118 606 | −0.48 % |

The old 769-byte value is the compressed standard-proof length because its
XOR share was equal-length; the new 771-byte value is the compressed native
comparison-share object. These are comparison materials, not the complete
signed chain requests measured in RQ3.

For transparency, the protocol-specific phase medians were:

| configuration | old `open_ms` | new `share_export_ms` |
|---|---:|---:|
| two-party in-process | 2 268.73 | 2 388.70 |
| two-party QUIC | 3 160.52 | 3 239.56 |

No percentage is reported for this table because the two columns do not
measure the same operation.

### RQ2 session totals

| RTT (ms) | old median (ms) | new median (ms) | change |
|---:|---:|---:|---:|
| 0 | 6 659.61 | 6 209.68 | −6.76 % |
| 10 | 17 734.04 | 14 712.51 | −17.04 % |
| 30 | 30 234.27 | 22 475.62 | −25.66 % |
| 60 | 35 486.33 | 42 886.27 | +20.85 % |
| 100 | 52 532.73 | 47 488.87 | −9.60 % |

With only three sessions per point, the non-monotonic changes—including the
60 ms regression—must not be read as a fitted latency curve. The session
total is like-for-like; old `open_ms` and new `share_export_ms` are not.

### RQ3 end-to-end and semantic phases

| metric | old median (ms) | new median (ms) | change |
|---|---:|---:|---:|
| full trade | 34 478.36 | 35 187.14 | +2.06 % |
| rendezvous | 4 019.47 | 4 019.84 | +0.01 % |
| comparison | 11 544.84 | 10 081.72 | −12.67 % |
| settlement proof | 164.82 | 121.46 | −26.31 % |
| final settlement | 4 476.62 | 6 309.32 | +40.94 % |
| settlement-driver semantic total | 19 856.47 | 20 497.60 | +3.23 % |

The full-trade increase is dominated in this five-run sample by the
block/poll-quantized final-settlement boundary, while the comparison boundary
decreased. These rows describe the observed run; they do not establish that
the proof-share representation caused either wall-clock change.

| chain verification | old median (ms) | new median (ms) | change |
|---|---:|---:|---:|
| `send_order` | 5.2665 | 5.3495 | +1.58 % |
| `settle_cozk2p` | 11.975 | 12.456 | +4.02 % |
| `settle_large` | 5.125 | 4.991 | −2.61 % |
| `settle_small` | 4.8395 | 4.8390 | −0.01 % |

| on-chain payload metric | old (B) | new (B) | change |
|---|---:|---:|---:|
| comparison share per submission | 1 983 | 2 008 | +1.26 % |
| two comparison shares per trade | 3 966 | 4 016 | +1.26 % |
| all effective payload per trade | 11 517 | 11 567 | +0.43 % |

Both protocols have two comparison submissions per trade. The new signed
request is 25 bytes larger per owner, while the total effective trade payload
increased by 50 bytes.


## What the numbers do not include

- **The offline phase or production privacy.** The configured
  `PartyIDBeaverSource` supplies predictable mock preprocessing; it provides
  no input privacy or proof zero knowledge. The measurements cover only this
  development online path, not a real SPDZ preprocessing system.
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
