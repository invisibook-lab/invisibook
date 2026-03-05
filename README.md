# invisibook

A privacy-preserving order book where trade amounts are encrypted. Only the order creator can see the plain-text amount; everyone else sees the cipher.

## Prerequisites

- **Rust 1.74+** – [install](https://www.rust-lang.org/tools/install)
- **Make**

## Build

```bash
make build-cli
```

This compiles the CLI and outputs an `invisibook` binary in the project root.

## Run

```bash
./invisibook
```

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move cursor between orders |
| `Enter` | Expand / collapse order detail |
| `Esc` | Quit |

### Place an Order

Type a command in the input box at the bottom and press `Enter`:

```
buy/sell {token_1} {price} {amount} {token_2}
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `buy/sell` | Trade direction |
| `token_1` | Token you want to trade (e.g. `ETH`, `BTC`) |
| `price` | Price per unit (positive integer) |
| `amount` | Quantity to trade (positive integer) |
| `token_2` | Quote token (e.g. `USDT`) |

**Examples:**

```bash
buy ETH 3500 10 USDT    # Buy 10 ETH at price 3500, quoted in USDT
sell BTC 64000 5 USDT    # Sell 5 BTC at price 64000, quoted in USDT
```

Auto-complete suggestions appear as you type – press `Tab` to accept.

### Privacy

- **Your own orders:** amount is displayed in plain text.
- **Other orders:** amount is displayed as encrypted cipher text (first 7 characters in the list view, full cipher in the detail view).



## License

See [LICENSE](LICENSE).
