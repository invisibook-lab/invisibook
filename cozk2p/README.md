# cozk2p — 2-party collaborative-ZK settlement

Two matched traders jointly prove the invisibook settlement statement —
no helper node — using [mpc-jellyfish](https://github.com/invisibook-lab/mpc-jellyfish)
(collaborative TurboPlonk) over [ark-mpc](https://github.com/invisibook-lab/ark-mpc-1)
(malicious-secure 2-party SPDZ). Design: [docs/cozk2p_design.md](../docs/cozk2p_design.md).
Results: [docs/cozk_experiments.md](../docs/cozk_experiments.md).

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

Dev caveats (SRS from a public seed, mock Beaver triples, unauthenticated
TLS) are listed in the design doc §5 — testnet only.
