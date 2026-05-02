# Chain Design

## 1. Overview

The `chain/` component is Invisibook's L2 chain. It is built on the
[yu](https://github.com/yu-org/yu) framework and runs as a standalone Go
binary. Its goal is to host a **privacy-preserving order book** whose on-chain
state reveals *who* is trading *which* pair at *what* price, but never the
plaintext *amount*: every amount stored on-chain is a ciphertext committed at
creation time and can only be consumed by supplying a ZK proof that the
ciphertext-preserving arithmetic (deposit = mint, inputs = outputs,
balance ≥ withdraw) is correct.

The chain exposes its functionality through two yu *tripods* — `orderbook`
and `account` — plus a pluggable consensus tripod. A tripod is yu's unit of
business logic: it bundles persistent state, writing entry points (txs), and
reading entry points (read-only RPCs). Clients interact with the chain via
the standard yu endpoints:

- **HTTP** `localhost:7999` — RPC reading / writing
- **WebSocket** `localhost:8999` — subscriptions
- **P2P** `localhost:8887` — inter-node gossip

Two TOML files under [chain/cfg/](../chain/cfg/) drive startup:
[`chain.toml`](../chain/cfg/chain.toml) configures the yu kernel (ports,
consensus, chain_id); [`core.toml`](../chain/cfg/core.toml) configures the
tripods (DB paths, genesis accounts).

Design invariants:

1. **Amount privacy** — `Cash.Amount` is always a `CipherText`. The chain
   never reads or compares plaintext amounts.
2. **UTXO-style cash** — balances are not scalars but sets of `Cash` outputs,
   each tracked by a lifecycle (`Active → Locked → Spent`). Spending always
   consumes whole cash records; residual value is returned as a change output.
3. **Deterministic order IDs** — an order ID is `SHA-256(input_cash_ids)`
   and is checked on `SendOrder`, so a client cannot forge IDs that collide
   with unrelated orders.
4. **Matching is authoritative on-chain** — matching happens inside
   `SendOrder`; settlement is a *separate* transaction that requires a ZK
   proof of value conservation.

## 2. Main Components

```
┌────────────────────────────────────── chain/ ──────────────────────────────────────┐
│                                                                                    │
│   cfg/chain.toml  cfg/core.toml                                                    │
│         │               │                                                          │
│         ▼               ▼                                                          │
│   ┌─────────────────────────────┐                                                  │
│   │          main.go            │  InitKernel → WithTripods(...) → Startup        │
│   └──────────────┬──────────────┘                                                  │
│                  │                                                                 │
│         ┌────────┴────────────────────────────────────────────┐                    │
│         ▼                       ▼                             ▼                    │
│   ┌───────────┐        ┌────────────────┐            ┌──────────────────┐          │
│   │consensus/ │        │ core/orderbook │            │  core/account    │          │
│   │ PoA       │        │  tripod        │◀──────────▶│  tripod          │          │
│   │ (yu poa)  │        │                │   uses     │                  │          │
│   │ (VDF /    │        │ SendOrder      │            │ Deposit          │          │
│   │  PoBuy    │        │ SettleOrder    │            │ Withdraw         │          │
│   │  stubs)   │        │ QueryOrders    │            │ GetAccount       │          │
│   └───────────┘        │                │            │                  │          │
│                        │ matchOrder     │            │ LockCash         │          │
│                        │ InsertOrder    │            │ SpendCash        │          │
│                        │ UpdateStatus   │            │ CreateCash       │          │
│                        └──────┬─────────┘            │ FindActiveCash   │          │
│                               │ GORM                 └────────┬─────────┘          │
│                               ▼                               ▼ GORM               │
│                        ┌─────────────┐                  ┌─────────────┐            │
│                        │ orders.db   │                  │ accounts.db │            │
│                        │ (SQLite)    │                  │ (SQLite)    │            │
│                        └─────────────┘                  └─────────────┘            │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 `main.go`

Loads both config files, builds the PoA consensus tripod and the two core
tripods, then registers them with the yu kernel. See
[chain/main.go](../chain/main.go).

### 2.2 `core/orderbook` tripod — see [chain/core/orderbook.go](../chain/core/orderbook.go)

The order book owns order state and matching. It declares an `Account`
dependency via yu's tripod tag (`Account *Account `tripod:"account"``) and
calls it for cash lifecycle operations.

**Writings**

- `SendOrder` — accepts a `SendOrderRequest`, verifies `id == SHA-256(input_cash_ids)`,
  checks each input cash (exists / `Active` / owner / correct token for
  Buy-vs-Sell side), locks the cash against the order ID, persists the order
  as `Pending`, then calls `matchOrder` which flips compatible orders to
  `Matched` and writes the counter-party link.
- `SettleOrder` — accepts an `order_ids` pair plus a list of `CashOutput`s
  and a ZK proof. It verifies the two orders are actually matched with each
  other, spends the locked input cash of both orders under a single
  `settleTxID`, mints the output cash records, and flips both orders to
  `Done`. *The ZK proof verification is currently a TODO*; the intended
  semantics is that the proof shows `sum(inputs) == sum(outputs)` in
  ciphertext space.

**Readings**

- `QueryOrders` — filtered/paginated read; all fields of `QueryOrdersRequest`
  are optional pointers.

### 2.3 `core/account` tripod — see [chain/core/account.go](../chain/core/account.go)

The account tripod owns the `Cash` UTXO set. It offers three public entry
points plus internal helpers (`LockCash`, `SpendCash`, `CreateCash`,
`FindActiveCash`) used by the order-book tripod.

**Writings**

- `Deposit` — *TODO: verifies a bridge proof* that the user locked assets
  in the Invisibook bridge contract on some other chain; on success mints a
  new `Active` cash record.
- `Withdraw` — *TODO: verifies a range proof* that `sum(inputs) >= amount`
  and that the optional change commitment is correct; spends the inputs and
  mints change if supplied.

**Reading**

- `GetAccount` — returns every `Active` cash for a given `(address, token)`.
  No aggregate balance is computed because amounts are ciphertext.

**InitChain** — seeds `cfg.GenesisAccounts` at block 0 (currently pre-funds
`alice` and `bob` with ETH and USDT, see
[chain/cfg/core.toml](../chain/cfg/core.toml)).

### 2.4 Shared domain types — [chain/core/order.go](../chain/core/order.go), [chain/core/cash.go](../chain/core/cash.go), [chain/core/udt.go](../chain/core/udt.go)

- `OrderID = string` (sha256 hex)
- `TradeType` = `Buy (0) | Sell (1)`
- `OrderStat` = `Pending | Matched | Done | Cancelled | Frozen`
- `CashStatus` = `Active | Locked | Spent`
- `TokenID = string`, with `NativeToken = "invis"`
- `CipherText = string` — opaque hex blob produced by the client (poseidon
  on desktop / sha256 on Android, see `lib/chain/src/orderbook.rs::encrypt_amount`).
- The shared `Validator` is a `go-playground/validator` instance.

### 2.5 Consensus — [chain/consensus/](../chain/consensus/)

Currently the chain runs under yu's single-node PoA for development
(`poa.SingleNodeCfg()`). Two future tripods are stubbed:

- [`proof_of_buying.go`](../chain/consensus/proof_of_buying.go) — a custom
  consensus hook keyed off order-book activity (stub).
- [`vdf.go`](../chain/consensus/vdf.go) — verifiable-delay-function step
  (stub, used to resist front-running in the matching phase).

Swapping from PoA to PoBuy is a one-line change in `main.go`.

## 3. Business-Scenario Walkthroughs

### 3.1 First deposit → place order → match → settle

Assume `alice` wants to buy 10 ETH paying in USDT at price 3500.

```
Client (lib/chain)                       chain (orderbook + account)
───────────────────────                  ──────────────────────────────
encrypt_amount(10)   ──Deposit(USDT)──▶  Account.Deposit
                                          └ verify bridge proof (TODO)
                                          └ Cash{id=c1, owner=alice,
                                                  token=USDT, amount=CT,
                                                  status=Active}

compute_order_id([c1])
encrypt_amount(10)   ──SendOrder(...)──▶ OrderBook.SendOrder
                                          ├ verify id == sha256([c1])
                                          ├ Account.LockCash([c1], oid)
                                          ├ InsertOrder(status=Pending)
                                          └ matchOrder
                                            └ finds bob's Sell order o2
                                              at price 3500 → both → Matched

(relayer detects Matched pair,
 generates zk proof of
 sum(inputs)==sum(outputs))

                     ──SettleOrder────▶  OrderBook.SettleOrder
                                          ├ check o1.MatchOrder==o2 & vice-versa
                                          ├ verify zk_proof (TODO)
                                          ├ Account.SpendCash([c1,c_bob], tx)
                                          ├ CreateCash(alice: ETH, CT)
                                          ├ CreateCash(bob:   USDT, CT)
                                          └ status(o1)=status(o2)=Done
```

**What the chain reveals** — `(alice, bob, ETH/USDT, price=3500, matched)`.
**What it hides** — the 10 ETH amount, across every intermediate state.

### 3.2 Browsing the market

A UI on mobile wants the top 20 pending ETH/USDT buys:

```
Client ──read QueryOrders {type:Buy, token1:ETH, token2:USDT,
                           status:Pending, limit:20, offset:0}
                                                           ──▶ OrderBook.QueryOrders
                                                               └ FindOrdersByFilter(...)
```

This is a pure read; no tx is produced, no cash state changes.

### 3.3 Partial-fill and withdraw with change

`bob` wants to withdraw 3 ETH out of a 5 ETH active cash `c5`:

```
Client                                    chain
──────                                    ─────
encrypt_amount(2)  (change)
zk_proof_range(c5 - 3 = 2)
──Withdraw({inputs:[c5],
             change:{owner:bob,amount:CT(2)},
             zk_proof})─────────────────▶ Account.Withdraw
                                           ├ verify zk_proof (TODO)
                                           ├ SpendCash([c5], tx)
                                           └ CreateCash(bob: ETH, CT(2))
```

The bridge-side release of the 3 ETH is handled off-chain by the withdraw
relayer, gated on the same `zk_proof`.

## 4. Reference: Definitions & Tools

### 4.1 Source map

| Path | Purpose |
|---|---|
| [chain/main.go](../chain/main.go) | kernel bootstrap, tripod wiring |
| [chain/cfg/chain.toml](../chain/cfg/chain.toml) | yu kernel config (ports, consensus, chain_id) |
| [chain/cfg/core.toml](../chain/cfg/core.toml) | tripod config (DB paths, genesis accounts) |
| [chain/core/orderbook.go](../chain/core/orderbook.go) | `OrderBook` tripod: `SendOrder`, `SettleOrder`, `QueryOrders`, `matchOrder` |
| [chain/core/order_scheme.go](../chain/core/order_scheme.go) | GORM schema + CRUD for orders |
| [chain/core/order.go](../chain/core/order.go) | `Order`, `OrderID`, `TradeType`, `OrderStat`, `TradePair`, `ComputeOrderID` |
| [chain/core/account.go](../chain/core/account.go) | `Account` tripod: `Deposit`, `Withdraw`, `GetAccount`, `InitChain` |
| [chain/core/cash_scheme.go](../chain/core/cash_scheme.go) | GORM schema + CRUD for cash (incl. `LockCash`, `SpendCash`) |
| [chain/core/cash.go](../chain/core/cash.go) | `Cash`, `CashStatus`, `AccountRecord`, `ChangeOutput`, `generateCashID`, `verifyProof` (TODO) |
| [chain/core/config.go](../chain/core/config.go) | TOML loader + `DefaultConfig` |
| [chain/core/udt.go](../chain/core/udt.go) | `TokenID`, `UDT`, `NativeToken` |
| [chain/consensus/proof_of_buying.go](../chain/consensus/proof_of_buying.go) | PoBuy tripod stub |
| [chain/consensus/vdf.go](../chain/consensus/vdf.go) | VDF tripod stub |

### 4.2 Core types cheat sheet

```go
// Order
type Order struct {
    ID           OrderID    // sha256(input_cash_ids)
    Type         TradeType  // Buy=0, Sell=1
    Subject      TradePair  // {Token1, Token2}
    Price        *big.Int   // clear text; nil = market order
    Amount       CipherText // encrypted
    Owner        string
    InputCashIDs []string
    MatchOrder   OrderID    // set once Matched
    Status       OrderStat  // Pending | Matched | Done | Cancelled | Frozen
}

// Cash (UTXO)
type Cash struct {
    ID      string
    Owner   string
    Token   TokenID
    Amount  CipherText
    ZkProof string     // committed at creation, checked before consumption
    Status  CashStatus // Active | Locked | Spent
    By      string     // Locked→order ID; Spent→tx/cash ID
}
```

### 4.3 Writings / Readings reference

| Tripod | Kind | Name | Request |
|---|---|---|---|
| orderbook | writing | `SendOrder` | `SendOrderRequest{ID, Type, Subject, Price, Amount, Owner, InputCashIDs, HandlingFee}` |
| orderbook | writing | `SettleOrder` | `SettleOrderRequest{OrderIDs[2], Outputs[], ZkProof}` |
| orderbook | reading | `QueryOrders` | `QueryOrdersRequest{ID?, Type?, Token1?, Token2?, Status?, Limit, Offset}` |
| account | writing | `Deposit` | `DepositRequest{Address, Token, Amount, ZkProof}` |
| account | writing | `Withdraw` | `WithdrawRequest{Token, Inputs[], Change?, ZkProof}` |
| account | reading | `GetAccount` | `GetAccountRequest{Address, Token}` → `AccountRecord{Address, Token, Cash[]}` |

### 4.4 External tools & dependencies

- **[yu](https://github.com/yu-org/yu)** — Go blockchain framework; provides the kernel, tripod abstraction, P2P, PoA consensus, HTTP/WS endpoints.
- **[yu-sdk (Rust)](https://github.com/yu-org/yu-sdk)** — Rust client SDK used by [lib/chain/src/chain.rs](../lib/chain/src/chain.rs) to drive `SendOrder` / `SettleOrder` / `QueryOrders`.
- **[GORM](https://gorm.io/)** + **SQLite** — persistence for orders and cash (`chain/data/*.db`, paths in `core.toml`).
- **[go-playground/validator](https://github.com/go-playground/validator)** — struct-tag validation on all request types.
- **Related client-side crypto** — amount ciphertext is produced off-chain in [lib/chain/src/orderbook.rs](../lib/chain/src/orderbook.rs) via Poseidon (BN254) on desktop, SHA-256 on Android; ZK proofs for deposit / settle / withdraw are produced in [lib/zk/](../lib/zk/) and verified by the three TODOs in `Deposit`, `SettleOrder`, `Withdraw`.
