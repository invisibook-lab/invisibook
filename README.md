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

```bash
cd chain
go build -o invisibook .
./invisibook
```

The chain node listens on:
- **HTTP** `localhost:7999` – reading & writing API
- **WebSocket** `localhost:8999`
- **P2P** `localhost:8887`

Configuration files are in `chain/cfg/`:
- `chain.toml` – yu framework config (ports, consensus, chain_id)
- `core.toml` – tripod config (DB paths, genesis accounts)

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

Matched orders can settle with a **single Groth16 proof generated jointly by
both traders via MPC** ([co-snarks](https://github.com/invisibook-lab/co-snarks)
REP3: the two traders + one helper node), so neither trader ever learns the
other's hidden amount. The chain verifies the proof, removes the fully-filled
order from the book, and updates the surviving order's hidden amount
commitment in place (keeping its time priority). See
[docs/cozk_design.md](docs/cozk_design.md) for the protocol, circuit, and
threat model, and [docs/cozk_experiments.md](docs/cozk_experiments.md) for
measurements.

```bash
# circuit + collaborative-proving tests
cd lib && cargo test -p zk settle_cozk && cargo test -p cozk

# 3-node distributed proving demo / benchmark
cargo build --release -p cozk --bins
./target/release/bench_settle_cozk --runs 5
```

## License

See [LICENSE](LICENSE).
