# Privacy-Preserving Settlement via Collaborative ZK (co-zk)

## 1. Motivation

The existing settlement path (`CompareOrders` + `SettleOrders`) has three privacy /
consistency gaps that this design closes:

1. **Plaintext amount leak** — the smaller party sends its locked amount to the
   larger party over a TCP side channel (`app/ui/src/settle.rs` phase 3.5) so the
   larger party can build the `settle_larger` proof alone.
2. **Asymmetric trust** — only the larger party proves; the smaller party's fill
   and the counterparty receive commitment are not verified in any circuit.
3. **No partial-fill order book semantics** — both orders always end `Done`; the
   remainder is re-posted client-side as a brand-new order (losing time priority),
   instead of the book updating the larger order's hidden amount in place.

In the co-zk design, the two matched traders **jointly generate one Groth16
proof** over a circuit that opens both order-amount commitments, compares them,
and proves every updated commitment (order remainders, updated locked collateral,
receive UTXOs) — without either trader revealing its amount to the other. The
chain verifies the single proof, removes the fully-filled (smaller) order from the
book, and updates the larger order's amount commitment in place.

## 2. Threat model

All adversaries are **honest-but-curious** (semi-honest): the DEX operator,
counterparties, and observers follow the protocol but try to infer hidden
amounts. Signatures ensure integrity of on-chain messages; the order book logic
is executed deterministically by the chain, so a malicious-deviation model is out
of scope here (see §7 for the known leakage of invalid-witness runs and the
mitigation we apply).

## 3. Protocol (PPS based on mpc-co-zk, Protocol 1)

### 3.1 Party topology

[co-snarks](https://github.com/invisibook-lab/co-snarks) (our fork of
TaceoLabs/co-snarks) implements collaborative Groth16 proving in the
Ozdemir–Boneh model (USENIX Sec'22) with **REP3** replicated secret sharing:
exactly 3 MPC nodes, semi-honest, tolerating 1 corruption. We map the two
traders onto it as:

- node 0 = trader A (the party whose order was placed first — the maker),
- node 1 = trader B (the taker),
- node 2 = a **helper** node.

Each trader REP3-splits its private inputs into 3 share maps and sends one map
to each node (`co_circom::split_input` / `merge_input_shares`). The security
assumption is that **the helper colludes with neither trader** — collusion of
A with B is vacuous (they would only learn each other's inputs, which collusion
gives them anyway). The helper can be any neutral service (e.g. the DEX
operator, who per the threat model is already honest-but-curious and never sees
plaintext amounts — it only handles shares).

### 3.2 Flow

1. Orders are matched on-chain with the public price-time-fee priority rules
   (unchanged; prices are public, amounts are Poseidon commitments).
2. The two traders discover each other's MPC endpoint (existing
   `RegisterSettleAddr`/`QuerySettleAddr` rendezvous) and connect to the helper.
3. Both traders split their private witness inputs; each node merges its two
   share maps, runs **MPC witness extension** (co-circom VM) for the
   `settle_cozk` circuit, and then **collaborative Groth16 proving**
   (`Rep3CoGroth16`) against the standard snarkjs zkey.
4. Every node locally **verifies the resulting proof before releasing it**
   (mitigation for invalid-witness leakage, see §7). The public outputs of the
   circuit include `cmp = sign(a − b) ∈ {−1, 0, 1}`.
5. Both traders **ed25519-sign** the canonical settlement message
   (public info) and one of them submits
   `(public info, sig_A, sig_B, proof)` to the chain (writing
   `SettleOrdersCoZk`).
6. The chain rebuilds the public-input vector from on-chain state + the request,
   verifies both signatures and the Groth16 proof, then:
   - spends both orders' locked cashes,
   - mints both receive cashes,
   - fully-filled side(s) (per `cmp`): order → `Done` (removed from the book;
     matching only ever scans `Pending`),
   - surviving larger side: `Order.Amount` ← new order commitment, a new Locked
     collateral cash is minted, and the order returns to `Pending` **keeping its
     original block height** (time priority preserved).
7. Off-chain, the smaller party reveals its plaintext fill to the larger party
   (inherent: the larger party receives exactly the smaller's amount and must be
   able to open its receive UTXO; this mirrors Protocol 1's final share-reveal
   step). Receive blindings are chosen by the *receiving* party, so each party
   can always open its own new UTXO — fixing gap (2) above.

### 3.3 Amount denomination

`Order.Amount` always commits the **token1 quantity** for both sides (the buy
side additionally commits its token2 collateral in the locked cash). Therefore
`a` and `b` are directly comparable and all cross-token arithmetic goes through
the public `price` (execution price = maker's price, as today).

### 3.4 Equal-price requirement (current limitation)

The `settle_cozk` circuit constrains each side's locked collateral to *exactly*
back its order at the execution price, and — unlike `settle_larger` — provides
**no buyer-change output**. A buyer locks `amount × its own limit price` at
order-creation time, so the constraint `locked_b == amount × exec_price` only
holds when `exec_price == buyer_price`. That is guaranteed exactly when both
matched orders quote the **same price**. The chain therefore rejects a co-zk
settlement of a cross-price (marketable) match (`SettleOrdersCoZk` requires
`orderA.Price == orderB.Price`); such matches settle via the legacy
change-producing path instead. Adding a buyer-change output to the circuit
(mirroring `settle_larger`) to lift this restriction is follow-up work.

## 4. The `settle_cozk` circuit

`lib/zk/templates/settle_cozk.circom`, `SettleCoZk(N)` with `N = 2` locked-cash
slots per party. Commitments are `Poseidon(2)([amount, random])` as everywhere
else.

A key structural point: the updated commitments depend on **both** parties'
secrets (e.g. the remainder `a' = a − min(a, b)`), so neither trader can supply
them as inputs — they are **public outputs** computed inside the MPC; only the
fresh blinding factors are (per-party) private inputs. The Groth16 public
vector is therefore `[outputs..., public inputs...]`:

| # | signal | class | source for on-chain verification |
|---|---|---|---|
| 1 | `cmp` (−1/0/1 as field element) | output | request (`cmp`) |
| 2 | `new_order_a_commitment` | output | request; ignored by chain if A fully fills |
| 3 | `new_order_b_commitment` | output | request; ignored if B fully fills |
| 4 | `new_locked_a_commitment` | output | request; ignored if A fully fills |
| 5 | `new_locked_b_commitment` | output | request; ignored if B fully fills |
| 6 | `recv_a_commitment` | output | request |
| 7 | `recv_b_commitment` | output | request |
| 8 | `order_a_commitment` | public input | `orderA.Amount` |
| 9 | `order_b_commitment` | public input | `orderB.Amount` |
| 10 | `price` | public input | maker price (chain-computed) |
| 11 | `a_is_seller` (0/1) | public input | `orderA.Type == Sell` |
| 12–13 | `locked_a_hashes[2]` | public input | A's locked `Cash.Amount` (zero-commit padded) |
| 14–15 | `locked_b_hashes[2]` | public input | B's locked `Cash.Amount` (zero-commit padded) |

Private inputs: per party X ∈ {a, b}: `x` (order token1 qty), `r_x` (order
blinding), `r_x_new` (fresh blinding for the remainder order commitment),
`locked_x_amounts[2]`, `locked_x_randomness[2]`, `r_locked_x_new`, `r_recv_x`.
Trader A owns the a-side private signals, trader B the b-side; public inputs
are supplied by both (must agree at share-merge time).

Constraints (mapping to the protocol document's constraint list):

1. `Poseidon(a, r_a) === order_a_commitment`, 64-bit range check on `a`
   (document: *commitment verify(commitment A, A)*), same for B.
2. Three-way comparison: `lt = a <?_64 b`, `eq = (a == b)`, `gt = 1 − lt − eq`,
   `cmp === gt − lt` (document: *A < B = [A < B?] (−1, 0, 1)*).
3. `fill_t1 = b + lt·(a − b)` (= `min(a, b)`),
   `a' = a − fill_t1`, `b' = b − fill_t1`
   (document: *A' = (A < B) ? 0 : A − B*, *B' = (B < A) ? 0 : B − A*).
4. `Poseidon(a', r_a_new) === new_order_a_commitment`, same for B
   (document: *commitment verify(commitment A', A')*).
5. Collateral opening: `VerifyAmounts(2)` over each party's locked hashes
   (Poseidon open + 64-bit range per slot); the sum must equal the order's
   collateral: `locked_sum_x === x_is_seller ? x : x·price`.
6. UTXO updates with `fill_t2 = fill_t1 · price`:
   - new locked collateral: `x_is_seller ? x' : x'·price` opens
     `new_locked_x_commitment`,
   - receive amount: `x_is_seller ? fill_t2 : fill_t1` opens
     `recv_x_commitment`.

**Zero-remainder handling**: when a side fully fills (`x' = 0`), its "new"
commitments still appear in the public vector (committing to 0 under a fresh
blinding — indistinguishable from any other commitment), but the chain simply
does not mint them: `cmp` alone decides which side leaves the book.

## 5. Chain changes

- `OrderBookConfig.SettleCoZkVKPath` + `chain/vk/settle_cozk_vk.json`
  (snarkjs vk, loaded like the others; empty path ⇒ verification skipped in
  test mode).
- New writing **`SettleOrdersCoZk`** on the `orderbook` tripod. Request:

```json
{
  "order_a_id": "...", "order_b_id": "...",
  "cmp": -1 | 0 | 1,
  "new_order_a_commitment": "64-hex", "new_order_b_commitment": "64-hex",
  "new_locked_a_commitment": "64-hex", "new_locked_b_commitment": "64-hex",
  "recv_a_commitment": "64-hex", "recv_b_commitment": "64-hex",
  "sig_a": "128-hex", "sig_b": "128-hex",
  "zk_proof": "<snarkjs proof.json>"
}
```

  Both signatures are ed25519 over `SHA256("cozk-settle:" ‖ order_a_id ‖
  order_b_id ‖ cmp ‖ the six commitment hexes)`, verified against each order's
  pubkey. Order A is the **maker** (lower block height; ties broken by order ID)
  so the roles are deterministic for any observer.
- Verification: both orders `Matched` and mutually referenced → rebuild the
  15-signal public vector (§4 table) → `VerifyGroth16(settleCoZkVK, ...)`.
- State transition (single atomic writing): spend both orders' locked cashes,
  mint `recv_a`/`recv_b` (Active, owned by the respective trader, token =
  what that side receives), then per `cmp`: fully-filled side(s) → `Done`;
  surviving side → mint new Locked collateral cash (`By = order ID`), update
  `Order.Amount` and `InputCashIDs`, clear `MatchOrder`, status back to
  `Pending` (original `BlockHeight` retained).

The legacy `CompareOrders`/`SettleOrders` writings remain untouched (the Dioxus
app still drives them); `SettleOrdersCoZk` is the replacement path and the app
migration is follow-up work.

## 6. Implementation layout

```
lib/zk/templates/settle_cozk.circom   # the joint circuit (reuses commitments.circom, utils/)
lib/zk/src/wallet.rs                  # SettleCoZkWitness + witness JSON builder + plain prover (baseline)
lib/cozk/                             # NEW crate: collaborative proving via co-snarks
├── src/lib.rs                        # public API: roles, config
├── src/input.rs                      # per-trader private input JSON + split/merge
├── src/prover.rs                     # REP3 witness extension + Rep3CoGroth16 prove + verify-before-release
├── src/net.rs                        # LocalNetwork (tests/bench) + TcpNetwork (3-process runs)
├── src/bin/settle_cozk_party.rs      # one MPC node (trader-a | trader-b | helper) over TCP
├── src/bin/bench_settle_cozk.rs      # experiments harness (time / memory / proof size / comm)
└── examples/dump_settle_cozk_fixture.rs  # emits fixture for chain Go verifier tests
chain/core/orderbook.go               # SettleOrdersCoZk writing
chain/core/config.go, cfg/*.toml, vk/ # VK wiring
lib/chain/src/chain.rs                # ChainClient::settle_orders_cozk + digest helper
```

co-snarks is consumed as git dependencies on the fork
(`co-groth16`, `circom-mpc-compiler`, `circom-mpc-vm`, `co-circom-types`,
`mpc-core`, `mpc-net`), pinned to a commit. Note that `circom-mpc-compiler`
links the GPL-3.0 circom compiler fork — it is confined to the `cozk` crate.

## 7. Security notes

- **Indistinguishability argument** (protocol document §Security Properties):
  the on-chain view is (hidden-amount order book + UTXO set, settlement
  messages {(commitments, proof, cmp)}). By Groth16 zero-knowledge the proof is
  simulatable; by Poseidon commitment hiding each commitment is replaceable by
  a commitment to any amount; `cmp` reveals only the order relation that the
  book update itself makes public (which order left the book). Hence states
  differing only in amounts are indistinguishable, so amount-targeted
  front-running (hunting large orders/UTXOs) is prevented.
- **Invalid-witness leakage** (ePrint 2025/1026): a Groth16 "proof" over an
  *invalid* witness is a deterministic function of the constraint error vector
  and can leak the honest trader's amount. Mitigation implemented: every node
  verifies the finished proof against the vk and **never releases a
  non-verifying proof**; in-circuit 64-bit range checks stop field-wraparound
  witnesses. (Under REP3 honest-majority, share mauling merely invalidates the
  sharing; the Groth16 prove phase itself is degree-2 non-reactive and is
  malicious-secure "for free" per 2025/1026 — the semi-honest assumption is
  load-bearing only for witness extension.)
- **What the parties learn**: trader A/B learn `cmp` plus their own values;
  the larger party additionally learns the smaller's fill after settlement
  (inherent — it must open its receive UTXO). The helper learns only `cmp` and
  the public commitments. Observers learn the public info only.
- The dev trusted setup (`snarkjs`, single contributor) remains testnet-only,
  as with all existing circuits.

## 8. Experiments

`bench_settle_cozk` measures, for the `settle_cozk` circuit (~4.3k R1CS
constraints):

- wall-clock time per phase (input split, witness extension, proving) for the
  3-party collaborative flow, vs the single-prover baseline (rapidsnark and
  ark-groth16) on the same circuit,
- peak memory (max RSS) per party process,
- proof size (snarkjs JSON and compressed ark-serialize form) and on-chain
  request size,
- MPC network traffic per party (bytes sent/received per phase).

Results are recorded in `docs/cozk_experiments.md`.
