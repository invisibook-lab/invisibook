# cozk2p — 2-party collaborative-ZK settlement

Two matched traders jointly prove the invisibook settlement statement —
no helper node — using [mpc-jellyfish](https://github.com/invisibook-lab/mpc-jellyfish)
(collaborative TurboPlonk) over [ark-mpc](https://github.com/invisibook-lab/ark-mpc-1)
(malicious-secure 2-party SPDZ). Design: [docs/cozk2p_design.md](../docs/cozk2p_design.md).
Results: [docs/cozk_experiments.md](../docs/cozk_experiments.md).

Two settlement flavors coexist (select with `settle2p_session --mode`):

- **split** (default): the MPC proves only the comparison (pi_cmp);
  each side then proves its own Groth16 settle leg and the chain runs
  the atomic `SettlePair`.
- **merged**: ONE collaborative proof covers the comparison AND both
  settle legs (`relation_pair.rs`, 15 publics, 16 384 gates); the chain
  runs `SettlePairCoZk2p` and no quantity is revealed before the
  settlement is final. See design doc §8.

This is a **separate workspace** from `lib/` on purpose: it pins
`nightly-2025-02-20` (rustup auto-installs it) because ark-mpc uses the
unstable `inherent_associated_types` feature that regressed on newer
nightlies, and it lives on the ark 0.4 ecosystem while `lib/` is on 0.5.
The 3-party path (`lib/cozk`) is unchanged; the two coexist.

## Test

```bash
cd cozk2p
cargo test               # unit + satisfiability + tamper (~seconds)
cargo test --release --test settle_2p   # includes the mock-MPC 2-party e2e
```

## Demo: two traders over QUIC

```bash
cargo build --release --bins
# generate inputs for the sample trade (or craft your own JSON)
cargo run --release --bin bench_settle2p -- --runs 1 --skip-quic  # warms key cache
# shell 1 (trader B listens):
./target/release/settle2p_party --role trader-b \
    --listen 127.0.0.1:23402 --peer 127.0.0.1:23401 \
    --side-json b_side.json --public-json public.json --out-dir out_b
# shell 2 (trader A dials):
./target/release/settle2p_party --role trader-a \
    --listen 127.0.0.1:23401 --peer 127.0.0.1:23402 \
    --side-json a_side.json --public-json public.json --out-dir out_a
```

Both parties end with the identical, locally-verified PLONK proof.

## Benchmarks

```bash
cargo run --release --bin bench_settle2p -- --runs 5 --out results.json
```

## Chain verification

The chain verifies the revealed proof through this crate's C ABI
(`src/ffi.rs`), built as a staticlib and linked over cgo into the
`SettleOrdersCoZk2p` writing (`go build -tags cozk2p`). From the repo root:

```bash
make build-chain-cozk2p   # staticlib + tagged chain binary
make dump-cozk2p-fixture  # chain/vk/settle_cozk2p_vk.bin + test fixture
make test-e2e-cozk2p      # real proof settled on a running chain
```

Dev caveats (SRS from a public seed, mock Beaver triples, unauthenticated
TLS) are listed in the design doc §5 — testnet only.
