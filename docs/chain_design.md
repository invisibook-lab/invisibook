# Chain Design

> **Status:** Current (2026-08-17, locked-only model). For every place
> this design differs from the paper, see
> [paper_deviations.md](paper_deviations.md).

## 1. Overview

The `chain/` component is Invisibook's L2 chain. It is built on the
[yu](https://github.com/yu-org/yu) framework and runs as one Go binary.
It hosts a **privacy-preserving order book**: the chain publishes each
order's trading pair, side, limit price, and fee in plaintext, and never
publishes a quantity or a balance. Value exists only in a shielded note
pool; an order carries its collateral as one Poseidon commitment, and
its hidden quantity is implied by that commitment; every state
transition that touches hidden value must come with a Groth16 or PLONK
proof that the chain verifies.

The chain exposes two yu *tripods* — `orderbook` and `account` — plus a
pluggable consensus tripod. A tripod bundles persistent state, writings
(transactions), and readings (read-only RPCs). Standard yu endpoints:

- **HTTP** `localhost:7999` — RPC reading / writing
- **WebSocket** `localhost:8999` — subscriptions
- **P2P** `localhost:8887` — inter-node gossip

Startup reads two TOML files under [chain/cfg/](../chain/cfg/):
[`chain.toml`](../chain/cfg/chain.toml) configures the yu kernel (ports,
consensus, chain id); [`core.toml`](../chain/cfg/core.toml) configures
the tripods (DB paths, verifying keys, genesis pool notes).

Design invariants:

1. **No plaintext value.** An order carries its collateral as ONE
   Poseidon commitment (`Order.LockedCommitment`); the hidden quantity
   is implied by the side-dependent collateral equation
   `needed = q·price + side·(q − q·price)`
   ([paper_deviations.md](paper_deviations.md) D17). Balances are pool
   notes: only commitments and nullifiers appear on chain.
2. **Full collateral at admission.** `SendOrder` verifies the
   `send_order` proof, which shows the spent notes cover
   `collateral + fee + change`. The book never holds an
   uncollateralized order.
3. **Deterministic order ids.** `order_id = SHA-256(nf_0 ‖ nf_1)` over
   the two input nullifiers; the chain recomputes and rejects mismatches.
4. **Matching is public, on-chain, and EQUAL-PRICE only.** Prices are
   plaintext, so `matchOrder` runs a deterministic rule with no
   cryptography: it pairs only orders with exactly equal prices (the
   settle circuits require the execution price to equal the collateral
   price, and a Matched pair has no cancel path), then block height →
   fee → intra-block index. Crossing but unequal orders stay Pending.
   Matching is strictly pairwise; all quantity work is deferred to
   settlement.
5. **Anchored disclosure (F1).** The smaller trader's quantity is
   revealed to the counterparty only after the pair is `Settling` on
   chain — the compare writing is the anchor.
6. **Atomic settlement (F2).** The main settle path is one `SettlePair`
   writing: both legs verify and both payout notes mint together, or
   nothing changes.

## 2. Main Components

```
┌──────────────────────────────── chain/ ────────────────────────────────┐
│  cfg/chain.toml   cfg/core.toml                                        │
│        │                │                                              │
│        ▼                ▼                                              │
│  ┌───────────────────────────┐                                         │
│  │         main.go           │ InitKernel → WithTripods(...) → Startup │
│  └─────────────┬─────────────┘                                         │
│                │                                                       │
│      ┌─────────┴──────────────────────────────┐                        │
│      ▼                  ▼                     ▼                        │
│ ┌──────────┐  ┌──────────────────┐  ┌────────────────────┐             │
│ │consensus/│  │ core/orderbook   │  │ core/account       │             │
│ │ PoA      │  │ SendOrder        │  │ (shielded pool)    │             │
│ │ (VDF /   │  │ SubmitCompare*   │  │ NoteDeposit        │             │
│ │  PoBuy   │  │ SettleSmall/Large│  │ NoteWithdraw       │             │
│ │  stubs)  │  │ SettlePair       │  │ GetNotes/PoolInfo  │             │
│ └──────────┘  │ ClaimFees        │  │ GetNullifiers      │             │
│               │ RegisterSettleAddr│ │ GetNoteByCm        │             │
│               │ QueryOrders/Fees │  │ ApplyPoolMutation  │             │
│               └──────┬───────────┘  └─────────┬──────────┘             │
│                      │ GORM                   │ GORM                   │
│                      ▼                        ▼                        │
│               ┌────────────┐          ┌──────────────┐                 │
│               │ orders.db  │          │ accounts.db  │                 │
│               └────────────┘          └──────────────┘                 │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 `core/account` — the shielded pool

The account tripod owns the note pool: an append-only Poseidon Merkle
tree (depth 20) of note commitments, a nullifier set, and the anchor
history. All value on the chain lives here. See
[pool.go](../chain/core/pool.go), [pool_scheme.go](../chain/core/pool_scheme.go),
[account_pool.go](../chain/core/account_pool.go).

- `cm = P2(P2(P2(P2(TAG_CM, npk), assetID), v), r)` — the note
  commitment chain (spec pinned by `spec/golden.json` across Go, Rust,
  and circom).
- `nf = P2(P2(TAG_NF, nk), rho)` with `rho` bound to the leaf index —
  one note, one nullifier, unlinkable to the commitment.
- Every mutation goes through `ApplyPoolMutation` (spend nullifiers +
  append commitments + record the new anchor, atomically).
- Spends may reference **any** historical anchor.

**Writings:** `NoteDeposit` (bridge in, gated by an operator signature
until real bridge proofs land), `NoteWithdraw` (spend 2 slots, bridge
out, mint change).
**Readings:** `GetNotes`, `GetPoolInfo`, `GetNullifiers`, `GetNoteByCm`.
**InitChain:** seeds `[[account.genesis_note]]` leaves idempotently
(dev/test funding; regenerate with
`cargo run -p invisibook-lib --example dump_dev_notes`).

### 2.2 `core/orderbook` — orders, matching, settlement

**`SendOrder`** ([orderbook.go](../chain/core/orderbook.go)) — spends
two pool note slots by nullifier (anchor must be known, nullifiers
unspent), verifies the `send_order` proof against the rebuilt publics
`[anchor, nf_0, nf_1, lock_asset, locked_commitment, fee, cm_change,
price, side, bind]`, checks the owner's ed25519 signature over the
whole request, mints the change note, accrues the plaintext fee to the
block producer, stores the order (its single `LockedCommitment`), and
runs `matchOrder`.

**Matching** — equal price required, then block height, then fee, then
intra-block index ([paper_deviations.md](paper_deviations.md) D6). A
match links exactly two orders and sets both to `Matched`. Matched pairs
are locked (no cancel path).

**`SubmitCompareCoZk2p`** ([orderbook_cozk.go](../chain/core/orderbook_cozk.go),
[orderbook_cozk2p.go](../chain/core/orderbook_cozk2p.go)) — records the
2-party comparison: verifies both traders' ed25519 signatures over the
canonical compare message and the collaborative PLONK π_cmp (5 publics:
`cmp`, the two collateral commitments, `price`, `a_is_seller`; verifier
linked via cgo behind the `cozk2p` build tag), stores `cmp`, and moves
both orders to `Settling`.
`SubmitCompareCoZk` is the Groth16 single-prover variant of the same
gate (fixtures/tests).

**`SettlePair`** — the ONLY settlement writing (F2; the unilateral
`SettleSmall`/`SettleLarge` writings are not registered, so one signed
leg alone can never pay out — [paper_deviations.md](paper_deviations.md)
D3). It verifies BOTH legs before touching state: each leg's owner
signature plus its `settle_small` (π_A) or `settle_large` (π_B) proof,
with publics rebuilt from the order rows (the single `LockedCommitment`,
price, side, pay asset, outputs, bind; π_B additionally opens the
counterparty's `LockedCommitment`). The pipeline is journaled for
crash consistency across the two
databases: a settlement-journal row (orders.db) records the intent, the
payout mint is idempotent per settlement id (accounts.db, one
transaction with a settlement-seen row), and the order-side transitions
commit in one orders.db transaction with the journal — a crash between
the databases is completed exactly once by a retry or by the boot-time
recovery (`recoverPendingSettlements`). The fully filled side closes;
the larger side relists **in place**: same order id, `LockedCommitment`
swapped to the residual collateral commitment, match link cleared,
status back to `Pending`, block height (time priority) retained,
immediate re-match attempted.

**`ClaimFees`** ([fees.go](../chain/core/fees.go)) — a block producer
mints its accrued plaintext fees as a pool note with a `claim_fees`
proof.

**`RegisterSettleAddr` / `QuerySettleAddr`** — plaintext QUIC
rendezvous for the settlement session (dev only; production requires an
anonymous overlay, see [paper_deviations.md](paper_deviations.md) D9).

**Readings:** `QueryOrders` (filtered, paginated), `QueryFees`.

### 2.3 Proof verification

[zkverify.go](../chain/core/zkverify.go) wraps `go-rapidsnark` for the
Groth16 circuits; [plonkverify.go](../chain/core/plonkverify.go) calls
the cozk2p Rust staticlib over cgo for π_cmp. Every VK path comes from
`core.toml`. The posture is FAIL-CLOSED: `require_proofs` defaults to
true, so a missing VK path refuses to boot; dev/test configs must opt
out explicitly with `require_proofs = false`. A missing or malformed
core.toml is fatal (no default fallback), and a binary built without
the cozk2p verifier refuses to boot on a config that sets
`settle_cozk2p_vk_path`.

### 2.4 Consensus — [chain/consensus/](../chain/consensus/)

Single-node PoA for development. `proof_of_buying.go` and `vdf.go` are
stubs for later work (front-running resistance in matching).

## 3. Trade Lifecycle

Alice sells 2 ETH at price 3; Bob buys 1 ETH at price 3 (the
`settle_e2e` scenario).

```
wallet (lib + app)                         chain
──────────────────                         ─────
prove send_order        ──SendOrder──────▶ verify sig + proof, spend nfs,
(spend notes,                              mint change note, store order,
 locked_commitment)                        match → both orders Matched

⟨2-party MPC compare session over QUIC (cozk2p)⟩
π_cmp + dual signatures ──SubmitCompareCoZk2p──▶ verify sigs + π_cmp,
                                           record cmp, both → Settling
⟨session blocks until Settling is confirmed — F1 gate⟩
⟨smaller side reveals (q, r_locked) to the larger side, P2P⟩
⟨each side proves its own settle circuit; legs exchanged P2P⟩

either party            ──SettlePair─────▶ verify BOTH legs, mint BOTH
                                           payout notes atomically,
                                           Bob's order → Done,
                                           Alice's order relisted in
                                           place with the residual
                                           collateral commitment
                                           (Pending)
```

What the chain reveals: pair, side, price, fee, the match, `cmp`, and
the fact of a fill. What it hides: every quantity, every balance, and
the residual (fresh blindings).

## 4. Reference

### 4.1 Order row

```go
type Order struct {
    ID               OrderID    // SHA-256(nf_0 ‖ nf_1)
    Type             TradeType  // Buy=0, Sell=1
    Subject          TradePair  // {Token1, Token2}
    Price            *big.Int   // plaintext; must fit u64
    Pubkey           string     // owner ed25519, authenticates updates
    LockedCommitment string     // the order's ONLY commitment: P2(needed, r)
    Fee              uint64     // plaintext, accrues to the producer
    BlockHeight      uint32     // time priority (kept across relist)
    IntraBlockIndex  uint32
    Status           OrderStat  // Pending|Matched|Done|Cancelled|Frozen|Settling
    MatchOrder       OrderID
}
```

There is no `Amount` field: the hidden quantity has no commitment of
its own. `LockedCommitment` pins it through the collateral equation
(D17).

### 4.2 Writings / readings

| Tripod | Kind | Name | Purpose |
|---|---|---|---|
| orderbook | writing | `SendOrder` | admit + match an order (spends pool notes) |
| orderbook | writing | `SubmitCompareCoZk2p` | record the dual-signed 2-party comparison (PLONK) |
| orderbook | writing | `SubmitCompareCoZk` | Groth16 variant of the compare gate |
| orderbook | writing | `SettlePair` | **atomic** two-leg settlement (the ONLY settle writing) |
| orderbook | writing | `ClaimFees` | producer mints accrued fees as a note |
| orderbook | writing | `RegisterSettleAddr` | QUIC rendezvous (dev) |
| orderbook | reading | `QueryOrders`, `QuerySettleAddr`, `QueryFees` | |
| account | writing | `NoteDeposit` / `NoteWithdraw` | bridge in / out of the pool |
| account | reading | `GetNotes`, `GetPoolInfo`, `GetNullifiers`, `GetNoteByCm` | |

### 4.3 Source map

| Path | Purpose |
|---|---|
| [chain/main.go](../chain/main.go) | kernel bootstrap, tripod wiring |
| [chain/core/orderbook.go](../chain/core/orderbook.go) | `SendOrder`, matching, rendezvous, `QueryOrders` |
| [chain/core/orderbook_cozk.go](../chain/core/orderbook_cozk.go) | compare + settle writings incl. `SettlePair` |
| [chain/core/orderbook_cozk2p.go](../chain/core/orderbook_cozk2p.go) | PLONK compare gate (`-tags cozk2p`) |
| [chain/core/order.go](../chain/core/order.go), [order_scheme.go](../chain/core/order_scheme.go) | order model + GORM CRUD |
| [chain/core/order_sign.go](../chain/core/order_sign.go) | canonical SendOrder signing message |
| [chain/core/account.go](../chain/core/account.go) | Account tripod (pool only) |
| [chain/core/pool.go](../chain/core/pool.go), [pool_scheme.go](../chain/core/pool_scheme.go), [account_pool.go](../chain/core/account_pool.go) | note tree, nullifiers, anchors, pool writings |
| [chain/core/fees.go](../chain/core/fees.go) | fee accrual + `ClaimFees` |
| [chain/core/zkverify.go](../chain/core/zkverify.go), [plonkverify.go](../chain/core/plonkverify.go) | Groth16 / PLONK verification |
| [chain/core/config.go](../chain/core/config.go) | TOML config, VK paths, genesis notes |
| [chain/vk/](../chain/vk/) | committed verifying keys |

### 4.4 Binds and signing messages

Every Groth16 proof carries a `bind` public input:
`SHA-256(domain ‖ chain_id ‖ writing ‖ version ‖ request fields)`
reduced into Fr (Go `BindHash`, Rust `note::bind_hash`, pinned by
`spec/golden.json`). This welds a proof to one exact request on one
chain. Signing messages (`SendOrderSigningMessage`, the compare and
settle messages) are length-prefixed and domain-separated; the Rust
twins in [lib/chain/src/chain.rs](../lib/chain/src/chain.rs) are kept in
lockstep by tests on both sides.

### 4.5 External dependencies

- **[yu](https://github.com/yu-org/yu)** — kernel, tripods, PoA, endpoints.
- **[GORM](https://gorm.io/) + SQLite** — orders and pool state.
- **[go-rapidsnark](https://github.com/iden3/go-rapidsnark)** — Groth16
  verification.
- **cozk2p staticlib (cgo, `-tags cozk2p`)** — PLONK π_cmp verification.
- **[go-playground/validator](https://github.com/go-playground/validator)** —
  request validation.
