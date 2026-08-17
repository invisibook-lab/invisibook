# App Design

> **Status:** Current (2026-08-16, note model + two-phase settlement).
> For every place this design differs from the paper, see
> [paper_deviations.md](paper_deviations.md).

## 1. Overview

The `app/` component is Invisibook's end-user trading client: a
cross-platform Rust application built on [Dioxus](https://dioxuslabs.com/),
sharing one set of RSX components across desktop and mobile. The app:

1. Renders the order book and a trade form.
2. Places orders through the real shielded path: it selects pool notes,
   proves the `send_order` circuit with rapidsnark, and persists the
   wallet records **before** it submits (persist-before-publish).
3. Drives the full hardened settlement for its own matched orders: the
   2-party MPC compare (in the `settle2p_session` subprocess), the
   on-chain compare confirmation (F1), this side's settle proof, the
   settle-leg exchange, and the atomic `SettlePair` (F2).
4. Keeps the wallet's money files: `notes.json` (note openings — this
   file IS the money) and `orders.json` (order openings).

The app links no MPC cryptography. The collaborative proof runs in the
pre-built `settle2p_session` subprocess (the `cozk2p/` workspace pins an
older nightly and cannot be linked directly); the app drives it over
piped stdio. Groth16 proving (rapidsnark) is linked via `lib/zk`.

## 2. Main Components

```
┌───────────────────────────────── app/ ─────────────────────────────────┐
│  app/desktop (entry, window, settle coroutines)   app/mobile (entry,   │
│                                                    tabs; no settle)    │
│                    │                                    │              │
│                    └───────────────┬────────────────────┘              │
│                                    ▼                                   │
│  app/ui (shared)                                                       │
│    components/: Header  OrderBook  TradeForm  KeyImport  Toast         │
│    settle.rs:   run_settle — the two-phase settlement driver           │
│    tests/settle_e2e.rs: full-path e2e + per-step benchmark             │
│                                    │                                   │
│                                    ▼                                   │
│  lib/chain (invisibook-lib)                    lib/zk                  │
│    chain.rs      ChainClient (yu-sdk)            circom templates      │
│    note_store.rs NoteStore   (notes.json)        snarkjs/rapidsnark    │
│    order_store.rs OrderStore (orders.json)       drivers               │
│    note_prover.rs witness builders + provers                           │
│    note_tree.rs  Merkle tree (paths, anchor)                           │
│                                    │                                   │
│           ┌────────────────────────┼──────────────────────────┐        │
│           ▼                        ▼                          ▼        │
│    chain (yu node :7999)   settle2p_session (subprocess)   rapidsnark  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Wallet state (the money files)

| File | Store | Content | Rule |
|---|---|---|---|
| `notes.json` | [`NoteStore`](../lib/chain/src/note_store.rs) | every owned note's full opening (cm, token, amount, r, sk, leaf index, status) | fsync + atomic rename; write BEFORE any note-creating tx is submitted |
| `orders.json` | [`OrderStore`](../lib/chain/src/order_store.rs) | every open order's opening (q, r_q, locked_amount, r_locked, lock token) | write BEFORE `SendOrder`; a relist replaces the opening with the residual one |

Note lifecycle: `UNSPENT → PENDING_SPEND → SPENT` and
`PENDING_MINT → UNSPENT` (the poller resolves pending states against the
chain via `GetNoteByCm` / `GetNullifiers`).

### 2.2 Order placement (`TradeForm` → `prepare_order`)

[trade_form.rs](../app/ui/src/components/trade_form.rs). On submit:

1. Compute the collateral: `q` token1 for a sell, `q·price` token2 for
   a buy, plus the plaintext fee.
2. Select at most two unspent notes covering it
   (`NoteStore::select_unspent` — the circuits have a fixed 2-slot
   shape; a missing slot becomes an Orchard-style dummy).
3. Sync the pool tree (`ChainClient::fetch_note_tree`) for the anchor
   and Merkle paths; the client re-checks the root against the chain
   head.
4. `prepare_order` (pure CPU, also used verbatim by the e2e test):
   derive the nullifiers → `order_id = SHA-256(nf_0 ‖ nf_1)` → draw
   fresh blindings and a fresh change-note key → compute the `bind` →
   prove `send_order` with rapidsnark.
5. Persist FIRST: inputs → `PENDING_SPEND` (with their nullifiers), the
   change note → `PENDING_MINT`, the order opening into `orders.json`.
6. Submit `SendOrder`. On rejection, roll the wallet records back.

Android: on-device proving is not wired; the submit handler reports it
as unsupported.

### 2.3 Settlement (`settle.rs` — the two-phase driver)

[settle.rs](../app/ui/src/settle.rs) drives one matched pair end to end.
The desktop settle coroutine is strictly serial and feeds it one order
id at a time.

```
run_settle
  ├─ role assignment: maker = trader-a (lower block height, tie → id)
  ├─ equal-price check (cross-price pairs are rejected — paper D6)
  ├─ SessionInput: chain publics (cm_q ×2, [LockedCommitment, zero-pad] ×2,
  │    price, side) + MY OrderOpening (q, r_q, locked, r_locked)
  ├─ rendezvous: RegisterSettleAddr / QuerySettleAddr (QUIC addrs, dev)
  └─ settle2p_session subprocess over stdio:
       "need_sig"       → sign the canonical compare message
       "compare_ready"  → cross-check the proven statement + both sigs,
                          submit SubmitCompareCoZk2p, block until BOTH
                          orders are Settling, reply compare_confirmed
                          ── the F1 gate: no reveal before this anchor
       (subprocess: smaller side reveals; payout-note keys exchanged;
        witness.json WAL written before secrets leave the process)
       "result_ready"   → read result.json, prove MY settle circuit
                          (settle_small if fully filled, else
                          settle_large), sign the leg, hand it back
       "pair_ready"     → both legs, exchanged in-fabric; either party
                          submits the ATOMIC SettlePair (F2)
  ├─ confirm on chain: my order Done, or relisted under the residual cm
  └─ persist: recv note → notes.json (PENDING_MINT); remainder →
       orders.json (residual opening) or opening removed when Done
```

Error classes: `CrossPrice` / `SelfMatch` / `Unrecoverable` are
permanent (never retried); `Transient` / `OnChainRejected` retry after a
backoff.

**Crash recovery** (`recover_all_sessions`): on startup the app scans
session dirs; a `witness.json` whose payout note is in the pool tree is
materialized into the wallet stores (the note key is re-derived from the
wallet seed + order id), a session that never landed is deleted, and a
mid-flight one is left alone.

### 2.4 Desktop main loop

[main.rs](../app/desktop/src/main.rs): a 3-second poller (order list +
auto-settle dispatch + pending-note resolution), a WebSocket
subscription for order events, a startup coroutine that warms the
subprocess proving keys (~1 min cold) and runs crash recovery, and the
serial settle coroutine. Mobile renders the same components but has no
settlement flow.

### 2.5 Key import

[key_import.rs](../app/ui/src/components/key_import.rs): BIP-39
mnemonic → SLIP-0010 ed25519 seed (m/44'/60'/0'/0'/0'), persisted to
`data_dir/mnemonic`; optional `notes.json` import (upsert by
commitment). Dev wallets for Alice/Bob come from
`chain/cfg/tests/{alice,bob}_notes.json`
(`scripts/dev-dual.sh` seeds them).

## 3. Walkthrough: the e2e scenario

Alice sells 2 ETH @ 3, Bob buys 1 ETH @ 3
([settle_e2e.rs](../app/ui/tests/settle_e2e.rs) drives exactly this
against a live chain with two real subprocess provers and prints a
per-step wall-clock table; numbers in
[cozk_experiments.md](cozk_experiments.md)).

1. Both wallets prove `send_order` (~220 ms each) and submit; the chain
   matches the pair.
2. Both apps auto-settle: QUIC rendezvous, MPC compare (π_cmp ~4 s
   wall-clock), `compare_ready` → either app lands
   `SubmitCompareCoZk2p`; both wait for `Settling` (~2 blocks) and
   confirm.
3. The subprocess reveals Bob's (smaller) opening to Alice only now;
   payout-note keys are exchanged; each app proves its own settle
   circuit (~0.1 s) and the legs cross in-fabric.
4. Either app submits `SettlePair`: Bob's order → `Done`, Alice's order
   relists in place with residual commitments, exactly two payout notes
   mint. Each wallet persists its incoming note and Alice's wallet
   replaces her order opening with the residual one.

## 4. Reference

### 4.1 Source map

| Path | Purpose |
|---|---|
| [app/desktop/src/main.rs](../app/desktop/src/main.rs) | desktop entry, pollers, settle coroutine, recovery |
| [app/mobile/src/main.rs](../app/mobile/src/main.rs) | mobile entry (no settlement) |
| [app/ui/src/settle.rs](../app/ui/src/settle.rs) | two-phase settlement driver + crash recovery |
| [app/ui/src/components/trade_form.rs](../app/ui/src/components/trade_form.rs) | note-based order placement (`prepare_order`) |
| [app/ui/src/components/key_import.rs](../app/ui/src/components/key_import.rs) | mnemonic + notes import |
| [app/ui/tests/settle_e2e.rs](../app/ui/tests/settle_e2e.rs) | full-path e2e + benchmark (run with `--ignored`) |
| [lib/chain/src/note_store.rs](../lib/chain/src/note_store.rs) | note ledger (`notes.json`) |
| [lib/chain/src/order_store.rs](../lib/chain/src/order_store.rs) | order-opening ledger (`orders.json`) |
| [lib/chain/src/note_prover.rs](../lib/chain/src/note_prover.rs) | witness builders + rapidsnark drivers |
| [lib/chain/src/chain.rs](../lib/chain/src/chain.rs) | `ChainClient` + signing messages (Go lockstep) |
| [cozk2p/src/bin/settle2p_session.rs](../cozk2p/src/bin/settle2p_session.rs) | the settlement subprocess (stdio protocol) |

### 4.2 Subprocess stdio protocol

| Direction | Line | Meaning |
|---|---|---|
| out | `{"event":"phase",...}` | progress |
| out | `{"event":"need_sig","cmp":b}` | request the compare signature |
| in | `{"sig":"<128-hex>"}` | the signature |
| out | `{"event":"compare_ready","ready":{...}}` | π_cmp + both sigs; host must land the compare on chain |
| in | `{"compare_confirmed":true\|false}` | F1 gate; `false` aborts before any reveal |
| out | `{"event":"result_ready"}` | result.json is on disk; host proves its settle leg |
| in | `{"settle_leg":{...}}` | the signed leg |
| out | `{"event":"pair_ready","a":{...},"b":{...}}` | both legs (exchanged over the session fabric) |
| out | `{"event":"done"}` | end |

### 4.3 Configuration

`ClientConfig` ([lib/chain/src/config.rs](../lib/chain/src/config.rs)):
chain URLs + chain id, `data_dir` (mnemonic, `notes.json`,
`orders.json`, session dirs), and the `settle2p_session` binary path
(config field, `INVISIBOOK_SETTLE2P_BIN`, or exe-adjacent lookup).
Dual-instance dev testing: `scripts/dev-dual.sh` (isolated data dirs for
Alice and Bob).
