# App Design

## 1. Overview

The `app/` component is Invisibook's end-user trading client. It is a
cross-platform Rust application built on [Dioxus 0.6](https://dioxuslabs.com/),
sharing one set of RSX components across desktop (macOS / Windows / Linux)
and mobile (iOS / Android). The app's responsibilities are:

1. Render the order book and a trade form so users can place buy / sell orders.
2. Locally encrypt the plaintext amount before any network call, so the
   chain only ever sees ciphertext (see `encrypt_amount` in
   [lib/chain/src/orderbook.rs](../lib/chain/src/orderbook.rs)).
3. Track which orders the user *originated* (so those amounts can be
   displayed as plaintext) vs. which came from others (displayed as cipher).
4. Drive the L2 chain through the shared Rust client in [lib/chain/](../lib/chain/).

The app is deliberately thin: all business logic (ciphering, order-ID
hashing, chain RPC shapes) lives in the shared `invisibook-lib` so both the
desktop and mobile crates can reuse it verbatim, and so the CLI can
exercise the same code paths. Each platform crate only differs in the
startup entry point, window/layout configuration, and the CSS theme.

## 2. Main Components

```
┌───────────────────────────────────── app/ ─────────────────────────────────────┐
│                                                                                │
│  ┌───────────────────┐                         ┌───────────────────┐           │
│  │ app/desktop       │                         │ app/mobile        │           │
│  │  src/main.rs      │                         │  src/main.rs      │           │
│  │  Dioxus::desktop  │                         │  Dioxus::launch   │           │
│  │  fixed layout     │                         │  Tab bar (OB/Trade)           │
│  │  style::CSS       │                         │  style_mobile::CSS_MOBILE     │
│  └─────────┬─────────┘                         └─────────┬─────────┘           │
│            │                                             │                     │
│            └──────────────┬──────────────────────────────┘                     │
│                           ▼                                                    │
│                 ┌──────────────────────────┐                                   │
│                 │ app/ui (shared RSX)      │                                   │
│                 │   components/            │                                   │
│                 │     Header               │                                   │
│                 │     OrderBook            │  ← reads `orders`, `own_order_ids`│
│                 │     TradeForm            │  ← writes new orders              │
│                 │     Toast                │                                   │
│                 │   constants.rs  TOKENS   │                                   │
│                 │   style.rs / style_mobile│                                   │
│                 └─────────────┬────────────┘                                   │
│                               │ uses                                           │
│                               ▼                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐    │
│  │ lib/chain  (invisibook-lib)                                            │    │
│  │   types.rs        Order, TradeType, OrderStatus, CipherText, ...       │    │
│  │   orderbook.rs    encrypt_amount, compute_order_id, sort_orders, …     │    │
│  │   chain.rs        ChainClient (send_order / settle_order / query)      │    │
│  │   command.rs      higher-level flows                                   │    │
│  └──────────────────────────────┬─────────────────────────────────────────┘    │
│                                 │ yu-sdk (HTTP/WS)                             │
└─────────────────────────────────┼──────────────────────────────────────────────┘
                                  ▼
                         chain/ (yu node @ :7999)
```

### 2.1 Platform crates

| Crate | Purpose |
|---|---|
| [app/desktop/](../app/desktop/) | Desktop entry point. `main()` builds a Dioxus desktop `Config` with a titled window (1060×720, min 860×520) and disabled context menu, then launches the shared `App` component. Uses the desktop stylesheet. |
| [app/mobile/](../app/mobile/) | Mobile entry point. Adds a viewport meta tag, a `Tab` enum (`OrderBook` / `Trade`) and a bottom tab bar because the screen is too narrow to host both panes side-by-side. Uses the mobile stylesheet. |

Both `App` components maintain the same set of Dioxus signals:

- `orders: Signal<Vec<Order>>` — the current order book snapshot.
- `own_order_ids: Signal<HashMap<OrderID, String>>` — orders originated on
  this device, keyed by order ID, with the plaintext amount as value (the
  *only* place plaintext lives; it is never sent over the network).
- `selected`, `expanded` — UI state for the order list.
- `message: Signal<Option<(String, bool)>>` — toast queue, `bool` = is-error.

### 2.2 `app/ui` — shared component library

All RSX components are declared here and re-exported via
[app/ui/src/components/mod.rs](../app/ui/src/components/mod.rs):

- **`Header`** — branding plus the active token pair badge. Reads
  `token1 / token2` from the first order.
- **`OrderBook`** — scrollable list. For each row it looks up the order's
  `id` in `own_order_ids`:
  - if present → render the plaintext amount
  - otherwise → render the ciphertext hex, truncated
- **`TradeForm`** — Buy/Sell tabs, token pair selectors (sourced from
  `constants::TOKENS`), price + amount inputs, computed total, submit
  button. On submit the form:
  1. validates positive-integer price and amount,
  2. calls `orderbook::encrypt_amount(amount_str)` to produce the
     ciphertext,
  3. generates a local `input_cash_ids` list and derives
     `id = compute_order_id(input_cash_ids)`,
  4. pushes a new `Order` into the `orders` signal (plus the plaintext into
     `own_order_ids`),
  5. in release builds, sends the order through the `ChainClient`.
- **`Toast`** — observes `message` signal and renders a transient banner.

Two stylesheets, [style.rs](../app/ui/src/style.rs) and
[style_mobile.rs](../app/ui/src/style_mobile.rs), embed CSS as `pub const
CSS: &str`. The platform crate injects the right one with `style { {CSS} }`.

### 2.3 `invisibook-lib` (see `lib/chain/src/`)

The app never talks to the chain directly; it goes through the shared lib:

- [types.rs](../lib/chain/src/types.rs) — `Order`, `TradeType`,
  `OrderStatus`, `CipherText`, `TradePair`, `CashOutput`, …
- [orderbook.rs](../lib/chain/src/orderbook.rs) — off-chain helpers:
  `compute_order_id` (sha256 of inputs, mirrors
  [chain/core/order.go](../chain/core/order.go)), `encrypt_amount`
  (Poseidon on desktop, SHA-256 on Android), `sort_orders`,
  `sample_orders` (used as initial UI state).
- [chain.rs](../lib/chain/src/chain.rs) — `ChainClient` wrapping
  `yu-sdk::YuClient`. Thin typed wrappers for `SendOrder`, `SettleOrder`,
  `QueryOrders`.
- [command.rs](../lib/chain/src/command.rs) — higher-level flows that
  combine multiple RPCs.

## 3. Business-Scenario Walkthroughs

### 3.1 Placing a buy order (desktop)

User picks `Buy`, pair `ETH / USDT`, price `3500`, amount `10`.

```
 TradeForm              app state                lib/chain                 chain
 ─────────              ─────────                ─────────                 ─────
 on_submit
  │
  ├─ validate price=3500, amount=10
  ├─ ciphertext = encrypt_amount("10")
  │     └─ Poseidon(10, 256-bit rand)  (Sha256 fallback on Android)
  ├─ cash_ids = [local cash ids selected by user]
  ├─ id = compute_order_id(cash_ids)
  ├─ orders.push(Order{id, Buy, ETH/USDT,
  │            price=3500, amount=CT, status=Pending, …})
  ├─ own_order_ids.insert(id → "10")
  └─ ChainClient.send_order(&order)
                              │
                              └─ yu-sdk write_chain("orderbook","SendOrder",…)
                                                                                ▶ orderbook.SendOrder
                                                                                   (match / lock / insert)
  message ← "Order submitted"
```

Then in `OrderBook`, the row for `id` shows `10 ETH` in plaintext to
*this* user. Every other node rendering the same order sees
`CT(poseidon(10, r))` — a 64-hex blob.

### 3.2 Seeing someone else's order

A second device fetches orders via `ChainClient.query_orders(...)`. The
returned list is merged into the `orders` signal. Because this device did
not originate those orders, `own_order_ids` lookups miss and the
`OrderBook` component renders the ciphertext — so amount privacy is
preserved even though everything else (pair, price, status, owner address)
is public.

### 3.3 Mobile tab switch

The mobile crate keeps the same `orders` / `own_order_ids` signals but
renders only one of `OrderBook` or `TradeForm` at a time, selected via the
bottom tab bar. Because both components share the same signal handles,
placing an order in the Trade tab and then switching to the Order Book tab
shows the new order instantly without any refresh.

### 3.4 Matching & settlement visibility

The app never runs matching logic — that is authoritative on-chain
(`orderbook.matchOrder`). The app learns about matches by re-running
`query_orders(status=Matched)` and updating the signal; a row whose status
flips to `Matched` / `Done` gets restyled. Settlement is initiated by an
off-chain relayer holding the zk-proof of `sum(inputs)==sum(outputs)`, not
by the app.

## 4. Reference: Definitions & Tools

### 4.1 Source map

| Path | Purpose |
|---|---|
| [app/desktop/src/main.rs](../app/desktop/src/main.rs) | Desktop launcher + `App` root |
| [app/desktop/Dioxus.toml](../app/desktop/Dioxus.toml) | Desktop Dioxus config |
| [app/mobile/src/main.rs](../app/mobile/src/main.rs) | Mobile launcher + tab navigation |
| [app/mobile/Dioxus.toml](../app/mobile/Dioxus.toml) | Mobile Dioxus config |
| [app/ui/src/lib.rs](../app/ui/src/lib.rs) | re-exports `components`, `constants`, `style`, `style_mobile` |
| [app/ui/src/components/header.rs](../app/ui/src/components/header.rs) | `Header` component |
| [app/ui/src/components/orderbook.rs](../app/ui/src/components/orderbook.rs) | `OrderBook` component |
| [app/ui/src/components/trade_form.rs](../app/ui/src/components/trade_form.rs) | `TradeForm` component |
| [app/ui/src/components/toast.rs](../app/ui/src/components/toast.rs) | `Toast` component |
| [app/ui/src/constants.rs](../app/ui/src/constants.rs) | `TOKENS` list |
| [app/ui/src/style.rs](../app/ui/src/style.rs) | Desktop CSS |
| [app/ui/src/style_mobile.rs](../app/ui/src/style_mobile.rs) | Mobile CSS |

### 4.2 Shared state handles

```rust
let orders:        Signal<Vec<Order>>                  = use_signal(…);
let own_order_ids: Signal<HashMap<OrderID, String>>    = use_signal(…);
let selected:      Signal<Option<usize>>               = use_signal(|| None);
let expanded:      Signal<Option<usize>>               = use_signal(|| None);
let message:       Signal<Option<(String, bool)>>      = use_signal(|| None);
```

The `(String, bool)` shape for `message` is `(text, is_error)`.

### 4.3 Privacy helpers

| Function | Where | Meaning |
|---|---|---|
| `encrypt_amount(&str) -> CipherText` | [lib/chain/src/orderbook.rs](../lib/chain/src/orderbook.rs) | Poseidon-BN254 hash of `(amount, random)` on desktop; SHA-256 fallback on Android. Never reversible on chain. |
| `compute_order_id(&[String]) -> OrderID` | same | SHA-256 of concatenated input cash IDs. Must match `ComputeOrderID` in [chain/core/order.go](../chain/core/order.go). |
| `sort_orders(&mut [Order])` | same | Descending price, `None` prices last. |
| `short_id(&str) -> &str` | same | Truncate to 7 chars for display. |
| `sample_orders()` | same | Seed data for the initial UI state. |

### 4.4 External tools & dependencies

- **[Dioxus 0.6](https://dioxuslabs.com/)** — the UI framework. Desktop
  target uses the Dioxus native desktop renderer; mobile uses
  `dx serve --platform ios | android` (see project `README`).
- **[Dioxus CLI (`dx`)](https://dioxuslabs.com/learn/0.6/CLI/installation)** —
  required only for mobile builds.
- **[yu-sdk (Rust)](https://github.com/yu-org/yu-sdk)** — RPC client to the
  yu chain; wrapped by `ChainClient`.
- **[light-poseidon](https://crates.io/crates/light-poseidon) / ark-bn254** —
  Poseidon hash used by `encrypt_amount` on non-Android targets.
- **[sha2](https://crates.io/crates/sha2)** — order-ID hashing and the
  Android fallback for `encrypt_amount`.
- **iOS build** — macOS + Xcode + `dx serve --platform ios`.
- **Android build** — Android SDK + NDK + `dx serve --platform android`.
  Note: Poseidon is skipped on Android (cfg-gated), so amount ciphertext
  there is SHA-256 of `(amount ‖ random)`.
