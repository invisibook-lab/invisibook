# cozk2p — 2-party collaborative-ZK settlement

Two matched traders jointly prove the invisibook settlement statement —
no helper node — using [mpc-jellyfish](https://github.com/invisibook-lab/mpc-jellyfish)
(collaborative TurboPlonk) over [ark-mpc](https://github.com/invisibook-lab/ark-mpc-1)
(SPDZ-authenticated 2-party fabric; the current Beaver source is dev-only).
Design: [docs/cozk2p_design.md](../docs/cozk2p_design.md).
Results: [docs/cozk_experiments.md](../docs/cozk_experiments.md).

The MPC proves the comparison (pi_cmp); each owner submits one
identity/round/deadline-bound native comparison-share payload. The two
payloads contain the same canonical template for every Fiat–Shamir-opened
component and that owner's native SPDZ value shares for only the final
`opening_proof` and `shifted_opening_proof` KZG G1 points. They contain no
SPDZ MAC shares. The chain checks template equality, group-adds those two
pairs of point shares,
constructs and verifies the standard PLONK proof, and only then permits the
next pre-reveal phase. The comparison payload deadline is the current round's
`MatchHeight + 10`; successful verification immediately creates a separate
absolute ten-block settlement-leg window. Before any quantity reveal, both
sessions exchange both payout-note key pairs and durably write them locally.
Those pairs are not yet owner-signed or committed on chain, and the settle
circuits do not publicly bind the counterparty's pre-reveal choice; the
end-to-end protocol therefore assumes compliant clients until that binding is
added.
Once the smaller opening is delivered and locally checked, no peer or MPC
operation remains: each owner independently builds and submits its Groth16
settlement proof. At expiry, zero legs release both orders without blame;
for `cmp != 0`, only a lone valid large-side leg is punitive: constructing it
requires the smaller opening, so the large owner is released and the missing
small owner is frozen. A lone small-side leg cannot prove delivery to the
large owner. Only-small, zero-leg, and incomplete `cmp = 0` rounds release
both without blame. The timeout rule is conservative against false blame and
asymmetric, but does not make the whole protocol Byzantine-safe; the chain
executes atomically after both settlement legs verify.

This is a **separate workspace** from `lib/` on purpose: it pins
`nightly-2025-02-20` (rustup auto-installs it) because ark-mpc uses the
unstable `inherent_associated_types` feature that regressed on newer
nightlies, and it lives on the ark 0.4 ecosystem while `lib/` is on 0.5.

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

Each party ends with its own native share payload; neither party constructs or
locally verifies the final standard PLONK proof in the settlement session.

## Benchmarks

```bash
cargo run --release --bin bench_settle2p -- --runs 5 --out results.json
```

## Chain verification

The chain passes both opaque share payloads through this crate's C ABI
(`src/ffi.rs`). Rust checks the party tags and canonical-template equality,
adds only the two pairs of final KZG G1 value shares, constructs the standard
proof, and verifies it. The staticlib is linked over cgo into the
`SettleOrdersCoZk2p` writing (`go build -tags cozk2p`). From the repo root:

```bash
make build-chain-cozk2p   # staticlib + tagged chain binary
make dump-cozk2p-fixture  # chain/vk/settle_cozk2p_vk.bin + test fixture
make test-e2e-cozk2p      # real proof settled on a running chain
```

Dev caveats (SRS from a public seed, unauthenticated TLS, and especially the
deterministic `PartyIDBeaverSource`) are listed in the design doc §5. That
Beaver source uses predictable, party-local material rather than jointly
generated or dealer-distributed authenticated triples, so it does not provide
production input privacy or zero knowledge. Testnet only.
