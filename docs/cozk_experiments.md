# Co-zk Settlement — Experiments

Two collaborative provers are measured: the **3-party REP3** path
(`lib/cozk`, co-snarks, Groth16) and the **2-party SPDZ** path
(`cozk2p/`, mpc-jellyfish, TurboPlonk — see
[cozk2p_design.md](cozk2p_design.md)). §"2-party" at the bottom compares
them.

Measurements of the collaborative settlement prover (`settle_cozk` circuit)
against single-prover baselines: **time**, **memory**, and **proof size**.

Reproduce with:

```bash
cd lib
cargo build --release -p cozk --bins
cargo run --release -p cozk --bin bench_settle_cozk -- --runs 8
```

The harness ([`lib/cozk/src/bin/bench_settle_cozk.rs`](../lib/cozk/src/bin/bench_settle_cozk.rs))
proves the same trade (A sells 80 token1 @ price 3, B buys 60 → `cmp = 1`)
five/eight ways and writes a JSON report.

## Environment

- CPU: 12th Gen Intel Core i9-12900HX (24 threads), 29 GiB RAM
- OS: Linux 6.18 (WSL2); Rust nightly; circom 2.2.3; snarkjs 0.7.6; rapidsnark
- Curve BN254, Groth16, dev trusted setup (pot13)

## Circuit

| metric | value |
|---|---|
| R1CS constraints (`--O2`) | 3600 |
| public signals | 15 (7 outputs + 8 inputs) |
| private inputs per trader | 9 |

## Results

Timings are mean ± population stdev over the measured runs.

### Proving time

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

### Memory (peak RSS)

| configuration | peak RSS |
|---|---|
| single prover — rapidsnark | ~8 MB |
| co-zk per node (TCP, own process) | ~109 MB |

Each MPC node loads the full Groth16 proving key (`.zkey`) plus the co-circom
MPC VM state, hence ~109 MB per process vs rapidsnark's ~8 MB. This is a
constant per node, independent of trade size.

### Proof size

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
[cozk_design.md](cozk_design.md) §7 needs: a constant-size proof plus public
commitments, simulatable and hiding.

### Communication (co-zk, per node, in-memory accounting)

| phase | bytes sent (party 0 / A) |
|---|---|
| witness extension | ~141 KiB |
| Groth16 prove | ~1 KiB (party A); the REP3 "next" neighbour carries more (~850 KiB observed on party B) |

Communication is dominated by witness extension and is a few hundred KiB per
node for this ~3.6k-constraint circuit — trivial on any real link, matching
the Θ(n) field-element communication bound for collaborative Groth16.

## 2-party settlement (cozk2p, mpc-jellyfish + ark-mpc SPDZ)

Reproduce with:

```bash
cd cozk2p
cargo build --release --bins
cargo run --release --bin bench_settle2p -- --runs 5
```

Same trade, same statement (15 public signals, canonical order), same
Poseidon commitments — different proof system (TurboPlonk/KZG instead of
Groth16) and different MPC (2-party malicious-secure SPDZ instead of
3-party semi-honest REP3).

### Circuit

| metric | value |
|---|---|
| TurboPlonk gates | 8192 (domain 16384) |
| public signals | 15 |
| proof size | **769 B compressed** (1185 B uncompressed; 13 G1 + 10 Fr) |
| verifying key | 938 B compressed |

### Results (5 runs, same machine as above)

| configuration | prove wall-clock | verify | peak RSS |
|---|---|---|---|
| single prover (TurboPlonk, same relation/keys) | 618 ± 62 ms | 6 ms | — |
| **2-party collaborative, in-process mock network** | ~24 s | 6 ms | shared process |
| **2-party collaborative, 2 processes over QUIC** | ~20–22 s steady-state (48 s first run, cold cache) | 4–6 ms | **~7.4 GB per trader** |

Phase split (QUIC, per trader): circuit build ~40 ms, PLONK rounds ~6 s,
open/drain ~14 s. The fabric evaluates lazily, so "open" includes draining
the whole dataflow graph; the split is indicative, not a strict phase
boundary. Both traders always revealed byte-identical proofs, each locally
verified before release.

### Reading the numbers

- **The 2-party protocol works end-to-end** — two processes, QUIC
  transport, malicious-secure SPDZ shares, standard PLONK proof out. That
  answers the feasibility question this path was built for.
- **The overhead is ~35× a single prover** (vs ~2–3× for 3-party REP3).
  This is not the 2PC arithmetic itself but `ark-mpc`'s dataflow-fabric
  constant cost per operation: the Poseidon-heavy witness (12 hashes × 65
  rounds, each S-box = 2 Beaver multiplications) creates ~10⁵ sequential
  fabric results, and memory (~7.4 GB/trader) is the retained dataflow
  graph plus its growable buffers. The `multithreaded_executor` feature was
  tried and measured 5–6× *slower* (lock contention), so the serial
  executor is kept.
- **Structural directions to close the gap** (not pursued here): batch the
  Poseidon layers with `batch_mul` (ark-mpc's batch ops amortize the per-op
  overhead), a Rescue-style hash native to TurboPlonk's `q_hash` selector,
  or ark-mpc's `ExecutorSizeHints` to right-size buffers.

### 3-party vs 2-party at a glance

| | 3-party (lib/cozk) | 2-party (cozk2p) |
|---|---|---|
| topology | 2 traders + helper node | **2 traders only** |
| adversary tolerated | semi-honest, no 2-of-3 collusion; helper must not collude | **1 fully malicious counterparty** |
| proof system | Groth16 (circom, snarkjs zkey) | TurboPlonk (KZG) |
| proof size | 128 B (ark) / ~720 B (snarkjs JSON) | 769 B compressed |
| chain verifier | go-rapidsnark (already wired) | needs a PLONK verifier bridge (documented follow-up) |
| prove wall-clock | 0.4 s (in-proc) / ~1.6-2 s (TCP) | ~24 s (in-proc) / ~20 s (QUIC) |
| peak RSS per node | ~110 MB | ~7.4 GB |
| offline phase | none (REP3) | Beaver triples (mock in dev; LowGear/OT for production) |
| trusted setup | circuit-specific (snarkjs dev) | universal KZG SRS (dev seed) |

The trade-off is clean: the 2-party path buys the *right topology* (no
third machine, no non-collusion assumption) and *malicious security* at a
~10× wall-clock and ~70× memory premium under this framework, plus a
chain-verifier gap. The 3-party path stays the performance-practical
default; the 2-party path matches the application's trust model.

## Note on the TCP loopback harness

The 3-process TCP mode is intended for a true per-machine memory/latency
measurement. On this single loopback host the co-snarks `TcpNetwork`
connection setup occasionally races and one node wedges in the first
witness-extension round (surfaced as a `recv` timeout); the harness retries a
run on fresh ports. The per-process numbers above (witness ~670 ms, prove
~87 ms, RSS ~109 MB, proof 720 B) are from clean completed runs. In-memory
3-party numbers are deterministic and are the primary compute-overhead
measurement; they run in CI (`cargo test -p cozk`).
