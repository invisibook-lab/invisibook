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

1. Copy config files to the host path:

```bash
mkdir -p ~/.invisibook/chain/cfg
cp chain/cfg/*.toml ~/.invisibook/chain/cfg/
```

2. Build the image and start the container:

```bash
docker compose build
docker compose up -d
```

The chain data is persisted at `~/.invisibook/chain/data/` and config is read from `~/.invisibook/chain/cfg/`.

To stop:

```bash
docker compose down
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

## License

See [LICENSE](LICENSE).
