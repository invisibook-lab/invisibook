# Chain Design

> **Status:** Current (2026-08-19, crossing prices + native fees +
> identity-bound proof submissions). For every place
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
   collateral-asset conservation and native-`invis` fee conservation
   independently. The book never holds an
   uncollateralized order.
3. **Deterministic order ids.** `order_id = SHA-256(coll_nf_0 ‖ coll_nf_1
   ‖ fee_nf_0 ‖ fee_nf_1)`; the chain recomputes and rejects mismatches.
4. **Matching is public, on-chain, and crossing-price.** `matchOrder`
   applies market flag → best price → block height → fee → intra-block
   index → id, persists one common execution price, and never pairs two
   market orders because neither supplies an execution price.
   Matching is strictly pairwise. Every match/rematch refreshes a per-round
   `MatchHeight`; the original `BlockHeight` stays unchanged for time
   priority. All quantity work is deferred to settlement.
5. **Anchored disclosure.** Each owner uploads its identity-, round-, and
   deadline-bound comparison proof payload: the same canonical
   Fiat–Shamir-common template
   plus its own native SPDZ value shares of the two final KZG G1 points. The
   smaller opening is released only after Rust checks template equality,
   group-adds those two point-share pairs, constructs the standard proof, and
   verifies π_cmp on chain. Comparison shares must arrive by
   `MatchHeight + 10`. An incomplete comparison round releases both orders
   without punishment.
6. **Independent proof submission, atomic settlement.** Each owner uploads
   only its own settlement proof. Comparison verification itself creates the
   absolute settlement deadline `verification_height + 10`, before payout
   keys or quantities are exchanged. The second leg triggers one atomic
   payout/update. At expiry, only a non-equal round with a lone valid
   large-side leg is punitive: the proof requires the smaller opening, so the
   missing small owner is frozen. Zero-leg, only-small, and incomplete
   `cmp = 0` rounds release both without blame. This is conservative but
   asymmetric attribution.

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
│ │  stubs)  │  │ SubmitSettleLeg │  │ GetNotes/PoolInfo  │             │
│ └──────────┘  │ ClaimFees        │  │ GetNullifiers      │             │
│               │ Share/Leg expiry  │ │ GetNoteByCm        │             │
│               │ RegisterSettleAddr│ │                    │             │
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
two collateral slots plus two native-fee slots (anchor known, nullifiers
unspent), verifies the 14-public `send_order` proof, checks the owner's
ed25519 signature over the whole request, mints both change commitments,
and accrues the plaintext native fee to the
block producer, stores the order (its single `LockedCommitment`), and
runs `matchOrder`.

**Matching** — crossing predicate, then market flag, best price, block
height, fee, intra-block index, and id. The resting limit price is the
execution price; if the resting order is market, the incoming limit is.
A
match links exactly two orders and sets both to `Matched`. Matched pairs
are locked (no cancel path).

**`SubmitCompareCoZk2pShare`**
([orderbook_compare_share.go](../chain/core/orderbook_compare_share.go)) —
accepts exactly one share from each canonical order owner. Each signature
binds chain id, pair, owner, match round, `cmp`, the chain-derived absolute
deadline, and share digest under `invisibook-cozk2p-proof-share-v3`. The
deadline is exactly this round's `MatchHeight + 10`, not an order's original
`BlockHeight` and not a first-uploader-selected window. Each versioned payload repeats
the same canonical template for components already public in the
Fiat–Shamir transcript and carries that party's native value share for only
`opening_proof` and `shifted_opening_proof`. The SPDZ MAC shares are not
uploaded. On the second submission, the Rust bridge requires template
equality (common components are not re-shared or added), group-adds the two
pairs of final G1 shares, constructs the standard proof, and verifies
collaborative PLONK π_cmp (6 publics:
`cmp`, the two collateral commitments, both own public prices,
`a_is_seller`; verifier
linked via cgo behind the `cozk2p` build tag), stores `cmp`, and moves
both orders to `Settling`. In the same transaction it creates the
settlement-leg row with absolute deadline `verification_height + 10`, before
the parties exchange payout-note keys or reveal a quantity.
`ExpireCompareCoZk2pShares` releases both sides
without a freeze because no smaller quantity opening was disclosed.
The Groth16 twin remains as an internal fixture/test helper but is not a
registered writing; production comparison accepts only owner-bound share
submissions.

**`SubmitSettleLeg` / `FinalizeSettleLegs`** — the owner submission writing
accepts only the submitting order owner's leg and verifies its outer identity/round
signature, inner owner signature, and `settle_small` (π_A) or
`settle_large` (π_B) proof. Its submission neither starts nor extends a
deadline: the absolute window was created when comparison verification
succeeded. Public inputs are
rebuilt from the order rows (the single `LockedCommitment`,
own and execution prices, side, pay asset, payout/refund outputs, bind;
π_B additionally opens the
counterparty's `LockedCommitment`). The current payout opening
`(npk_ctr, r_note)` is private and is not bound to an owner-signed on-chain
pre-reveal key commitment. Thus a malicious payer can redirect its output
while satisfying the circuit; until the key choice is owner-signed, anchored,
and added as a public circuit binding, this path assumes compliant clients.
The pipeline is journaled for crash consistency across the two
databases once both verified owner legs are present: a settlement-journal row (orders.db) records the intent, the
payout mint is idempotent per settlement id (accounts.db, one
transaction with a settlement-seen row), and the order-side transitions
commit in one orders.db transaction with the journal — a crash between
the databases is completed exactly once by a retry or by the boot-time
recovery (`recoverPendingSettlements`). If both legs landed but the inline
executor returned before completion, the
permissionless `FinalizeSettleLegs` writing reuses only the stored verified
legs and resumes the same idempotent journal. Its caller cannot replace any
proof, output, or signature.
The fully filled side closes;
the larger side relists **in place**: same order id, `LockedCommitment`
swapped to the residual collateral commitment, match link cleared,
status back to `Pending`, block height (time priority) retained,
immediate re-match attempted. At the comparison-created deadline, zero legs
release both owners without blame. If `cmp != 0` and only the large-side leg
exists, `ExpireSettleLegs` releases its owner and freezes the missing small
owner: the valid large proof requires knowledge of the smaller opening. If
only the small-side leg exists, both are released because that proof can be
generated without delivering the opening. Every incomplete `cmp = 0` round
also releases both. This is conservative but asymmetric; symmetric
Byzantine attribution requires verifiable encrypted reveal or an equivalent
chain-checkable artifact. A receiver-withholdable signed receipt does not
solve fair exchange.

**`ClaimFees`** ([fees.go](../chain/core/fees.go)) — a block producer
mints its accrued plaintext fees as a pool note with a `claim_fees`
proof.

**`RegisterSettleAddr` / `QuerySettleAddr`** — owner-signed QUIC address,
match round, and X25519 key rendezvous. Addresses remain public (dev only),
while the smaller opening is ChaCha20-Poly1305 encrypted end-to-end.

**Readings:** `QueryOrders` (filtered, paginated), `QueryFees`,
`QueryCompareCoZk2pShares`, and `QuerySettleLegs` (owner presence and
chain-assigned deadlines).

### 2.3 Proof verification

[zkverify.go](../chain/core/zkverify.go) wraps `go-rapidsnark` for the
Groth16 circuits; [plonkverify.go](../chain/core/plonkverify.go) calls
the cozk2p Rust staticlib over cgo for π_cmp. Go treats the two native
payloads as opaque canonical bytes; Rust validates their version/party tags,
matches the common template, reconstructs the final two KZG points with G1
addition, and verifies the resulting standard proof. Every VK path comes from
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
same common template +    ──SubmitCompareCoZk2pShare──▶ match template; add only
each owner's 2 G1 shares                                  final G1 shares; verify π_cmp,
                                           record cmp, both → Settling;
                                           create leg deadline H_verify+10
⟨session blocks until both shares verify and Settling is confirmed⟩
⟨both sides exchange + persist BOTH payout-note key pairs⟩
⟨smaller side reveals (q, r_locked) to the larger side, P2P⟩
⟨no peer/MPC dependency remains after reveal⟩
⟨each side proves its own settle circuit⟩

each owner              ──SubmitSettleLeg──▶ verify/store own leg; after both,
                                           mint BOTH
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
    MatchRound       uint64     // increments on every match/rematch
    MatchHeight      uint64     // current round height; deadline source
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
| orderbook | writing | `SubmitCompareCoZk2pShare` | submit one identity-bound PLONK proof share |
| orderbook | writing | `ExpireCompareCoZk2pShares` | release an incomplete pre-reveal share round |
| orderbook | writing | `SubmitSettleLeg` | submit one owner's verified settlement proof |
| orderbook | writing | `FinalizeSettleLegs` | permissionlessly resume atomic execution once both in-deadline legs are stored |
| orderbook | writing | `ExpireSettleLegs` | after the comparison-created deadline: freeze missing small only for `cmp != 0` + only-large; otherwise release both without blame |
| orderbook | writing | `ClaimFees` | producer mints accrued fees as a note |
| orderbook | writing | `RegisterSettleAddr` | QUIC rendezvous (dev) |
| orderbook | reading | `QueryOrders`, `QuerySettleAddr`, `QueryFees`, `QueryCompareCoZk2pShares`, `QuerySettleLegs` | |
| account | writing | `NoteDeposit` / `NoteWithdraw` | bridge in / out of the pool |
| account | reading | `GetNotes`, `GetPoolInfo`, `GetNullifiers`, `GetNoteByCm` | |

### 4.3 Source map

| Path | Purpose |
|---|---|
| [chain/main.go](../chain/main.go) | kernel bootstrap, tripod wiring |
| [chain/core/orderbook.go](../chain/core/orderbook.go) | `SendOrder`, matching, rendezvous, `QueryOrders` |
| [chain/core/orderbook_cozk.go](../chain/core/orderbook_cozk.go) | legacy Groth16 compare + internal atomic settlement executor |
| [chain/core/orderbook_compare_share.go](../chain/core/orderbook_compare_share.go) | owner-bound PLONK proof shares + pre-reveal expiry |
| [chain/core/orderbook_settle_leg.go](../chain/core/orderbook_settle_leg.go) | owner-bound settlement legs + post-reveal expiry |
| [chain/core/orderbook_cozk2p.go](../chain/core/orderbook_cozk2p.go) | PLONK public-statement builder (`-tags cozk2p` verifier) |
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
