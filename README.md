# invisibook

A privacy-preserving order book built on pure cryptography — no TEE, no centralized infrastructure. Invisibook tackles the three hard problems of **privacy**, **censorship resistance**, and **price discovery** simultaneously, solving what traditional DEXs, CEXs, and dark pools cannot. Trade amounts are encrypted end-to-end: only the order creator can see the plain-text amount; everyone else sees the cipher.

![invisibook desktop](docs/invisibook_desktop.png)

## Prerequisites

- **Go 1.21+** – [install](https://go.dev/dl/)
- **Rust nightly** – [install](https://www.rust-lang.org/tools/install), then `rustup install nightly`
- **GCC / C compiler** – required by CGo (SQLite driver)
- **Node.js 18+** – [install](https://nodejs.org/) (required for circom witness generation)
- **circom 2.2+** – `cargo install --git https://github.com/iden3/circom.git`
- **snarkjs** – `npm install -g snarkjs`
- **rapidsnark** (optional, for fast proving) – build from [iden3/rapidsnark](https://github.com/iden3/rapidsnark)

## Build & Run

### Chain

The default build includes the cozk2p PLONK verifier (the collaborative
settlement path); it needs Rust for the verifier staticlib:

```bash
make build-chain     # builds the cozk2p staticlib + go build -tags cozk2p
cd chain && ./invisibook
```

`make build-chain-lite` produces a pure-Go binary WITHOUT the verifier —
dev only. It refuses to boot on any config that sets
`settle_cozk2p_vk_path`, so it cannot silently run as a production node.

The chain node listens on:
- **HTTP** `localhost:7999` – reading & writing API
- **WebSocket** `localhost:8999`
- **P2P** `localhost:8887`

Configuration files are in `chain/cfg/`:
- `chain.toml` – yu framework config (ports, consensus, chain_id)
- `core.toml` – tripod config (DB paths, verifying keys, genesis pool notes)

### Docker

Build the image and start the container:

```bash
docker-compose build
docker-compose up -d
```


To stop:

```bash
docker-compose down
```

### Desktop

```bash
cd app/desktop
cargo run --release
```

### Mobile (iOS / Android)

Mobile builds use [Dioxus CLI](https://dioxuslabs.com/learn/0.6/CLI/installation). Install it first:

```bash
cargo install dioxus-cli
```

**iOS** (requires macOS + Xcode):

```bash
cd app/mobile
dx serve --platform ios
```

**Android** (requires Android SDK + NDK):

```bash
cd app/mobile
dx serve --platform android
```

## Usage

Use the trade form on the right panel to place orders:

- Select **Buy** or **Sell**
- Choose a token pair from the dropdowns
- Enter a **Price** and **Amount** (positive integers)
- Click the submit button

### Privacy

- **Your own orders:** amount is displayed in plain text.
- **Other orders:** amount is shown as encrypted cipher text.

## Collaborative ZK Settlement (co-zk)

Matched orders settle in two phases. First the two traders **jointly
prove the comparison of their hidden quantities** ([cozk2p](cozk2p/):
2-party SPDZ fabric + collaborative TurboPlonk, no helper node; the current
Beaver source is explicitly dev-only) and
submit one identity/round/deadline-bound native proof-share payload each.
Both payloads repeat the same Fiat–Shamir-opened canonical template; only the
final two unopened KZG G1 points are native SPDZ value shares (MAC shares
never leave the MPC). The comparison-share deadline is the current round's
`MatchHeight + 10`, not either order's original admission height. No explicit
quantity opening `(q, r_locked)` is disclosed until the chain checks the
templates, adds each pair of point shares, reconstructs the standard proof,
and verifies it; that verification also
creates an absolute ten-block settlement-leg deadline. Both parties exchange
and durably record both payout-note key pairs before the smaller opening is
revealed. This WAL barrier currently assumes compliant clients: the pairs are
not owner-signed or committed on chain, and the settle circuits do not
publicly bind the counterparty's choice, so a malicious payer can redirect a
payout. After reveal, each owner can construct and submit its settlement
proof with no further peer/MPC dependency. At the deadline, zero legs release
both owners without blame. For `cmp != 0`, a lone valid **large-side** leg
proves that its owner knew the smaller opening, so the chain releases that
owner and freezes the missing small owner. A lone small-side leg cannot prove
delivery to the large owner; only-small, zero-leg, and every incomplete
`cmp = 0` round therefore release both without blame. This timeout rule is
conservative against false blame but asymmetric; the overall prototype claims
only compliant-until-fail-stop security (see the threat-model note in the
protocol reference). After both verify, the chain applies both sides atomically:
the fully filled order closes, the surviving order is relisted in place with
fresh residual commitments (keeping its time priority),
and both payout notes mint in one step. See
[docs/cozk2p_design.md](docs/cozk2p_design.md) for the protocol and
threat model, and [docs/cozk_experiments.md](docs/cozk_experiments.md)
for measurements.

```bash
# unit + satisfiability + 2-party e2e (mock network)
cd cozk2p && cargo test

# real collaborative proof settled on a running chain
make test-e2e-cozk2p
```

### Measurements

Each experiment is one script in [experiments/](experiments/), and
[experiments/README.md](experiments/README.md) states what each one
measures. The results are in
[docs/cozk_experiments.md](docs/cozk_experiments.md).

```bash
./experiments/rq1_crypto_overhead.sh    # what the cryptography costs
./experiments/rq2_network_latency.sh    # what the round-trip time costs
./experiments/rq3_end_to_end.sh --runs 5  # one complete trade
```

## Documentation

The documentation index is [docs/README.md](docs/README.md). It lists
every design document with its status, and
[docs/paper_deviations.md](docs/paper_deviations.md) records each place
the implementation differs from the protocol paper
([papers/invisibook.pdf](papers/invisibook.pdf)).

## License

See [LICENSE](LICENSE).
