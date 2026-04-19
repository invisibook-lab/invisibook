# invisibook

A privacy-preserving order book built on pure cryptography — no TEE, no centralized infrastructure. Invisibook tackles the three hard problems of **privacy**, **censorship resistance**, and **price discovery** simultaneously, solving what traditional DEXs, CEXs, and dark pools cannot. Trade amounts are encrypted end-to-end: only the order creator can see the plain-text amount; everyone else sees the cipher.

![invisibook desktop](doc/invisibook_desktop.png)

## Prerequisites

- **Go 1.21+** – [install](https://go.dev/dl/)
- **Rust 1.74+** – [install](https://www.rust-lang.org/tools/install)
- **GCC / C compiler** – required by CGo (SQLite driver)

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
