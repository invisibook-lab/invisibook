# Implementation vs. the Paper

> **Status:** Current (2026-08-18). Compares the code on this branch with
> [papers/invisibook.pdf](../papers/invisibook.pdf) ("A Privacy-Preserving,
> Censorship-Resistant, Decentralized Order Book", NDSS 2026 submission).
> Update this file when either side changes.

The implementation follows the paper's architecture: public price
discovery, hidden quantities, a maliciously secure 2-party comparison
between the matched traders, and per-side settlement proofs that the chain
verifies. This file lists every point where the code deviates from the
paper, why, and what the deviation changes.

Legend for the **Effect** column:

- **Stronger** — the code gives a guarantee the paper does not require.
- **Equal** — different mechanism, same guarantee.
- **Weaker** — the code gives less than the paper specifies.
- **Missing** — the paper mechanism is not implemented yet.
- **Dev-only** — a placeholder that voids the guarantee until replaced.

## 1. Summary table

| # | Topic | Paper (§) | Implementation | Effect |
|---|---|---|---|---|
| D1 | Compare submission | Two-step on-chain share assembly of π_cmp and `b` (§VI-B) | One `SubmitCompareCoZk2p` writing: the MPC opens the full π_cmp (MAC-checked), both traders sign `(order_a, order_b, cmp)`, either submits | Equal for integrity; **Weaker** for the `cmp` trit timing (see D1) |
| D2 | Reveal ordering | Reveal after the chain publishes `b` (§VI-C) | Reveal only after `SubmitCompareCoZk2p` is confirmed and both orders are `Settling` (F1 gate) | Equal |
| D3 | Settlement updates | Two independent per-side updates (§V-C, §VI-C) | One atomic `SettlePair` writing verifies both legs and mints both payout notes together (F2). The unilateral `SettleSmall`/`SettleLarge` writings are NOT registered — a party holding only the counterparty's signed leg cannot collect alone | **Stronger** (fair exchange) |
| D4 | Liveness / challenge | Per-submission deadlines and encrypted on-chain reveal challenge with temporary freeze (§VI-D) | A durable pre-open checkpoint is required from both traders after compare confirmation and before reveal. After 10 blocks, a sole uploader can requeue itself and freeze the non-uploader. The paper's later encrypted on-chain reveal/adjudication and timed unfreeze are not implemented | Partial: same pre-open attribution goal; paper challenge still missing |
| D5 | Collateral shape | Order spends shielded value `p·q + f`; `f` is the native-token miner fee (§V-B) | Side-dependent collateral (`q` token1 for a sell, `q·p` token2 for a buy) is `LockedCommitment`; separate note banks conserve the collateral asset and native `invis` fee independently (or one combined bank when collateral is `invis`) | Equal (concretization) |
| D6 | Execution price | Crossing prices match; the executed price is not pinned (§V-C) | Crossing orders match. The maker's limit price is persisted as a common execution price; if the maker is market, the taker's limit is used. Settle proofs pay at execution price and return buy-side price improvement as a shielded refund note | Stronger/different (deterministic execution price) |
| D7 | Partial-fill relist | The residual becomes a **new** order `o'_B` (§V-C) | The chain relists the **same** order id in place with the residual collateral commitment; block height (time priority) is retained | **Stronger** (keeps priority; same privacy: fresh blinding) |
| D8 | Matching rule | Price → block height → fee → intra-block index; pairwise (§V-C); order price may be a market flag (§V-B) | Pairwise crossing; market candidates first, then best price → block height → fee → intra-block index → order id. Market/market cannot establish an execution price. A market order carries a public protection price for locked-only collateral and slippage bounds | Equal for limit priority; protection price is an implementation addition |
| D9 | P2P transport | Anonymous network (Tor) required (§III-A) | Direct QUIC; signed X25519 keys and peer addresses are exchanged on chain. The smaller opening is additionally X25519/ChaCha20-Poly1305 encrypted end-to-end, but network metadata remains public | **Dev-only** for anonymity; encrypted reveal implemented |
| D10 | MPC offline phase | SPDZ with a real preprocessing phase (§VI-A) | `PartyIDBeaverSource` mock triples: predictable masks, **no input privacy, no proof zero-knowledge** | **Dev-only** |
| D11 | SNARK setup | Black-box collaborative zk-SNARK (§IV-B) | mpc-jellyfish TurboPlonk over a **fixed-seed dev SRS**: anyone can forge proofs | **Dev-only** |
| D12 | Shielded layer | Assumed from the chain (assumption (iv), §III-A) | Built in-repo: Poseidon note pool, depth-20 tree, nullifiers, 2-slot spends, Orchard-style dummies | Equal (self-hosted) |
| D13 | Bridge proofs | Out of scope | `NoteDeposit` trusts an operator signature (or nothing, in dev); no inclusion/release proofs | **Dev-only** |
| D14 | Fee payout | Fee paid to the miner like a Zcash fee (§V-B) | Plaintext fee accrues per block producer; `ClaimFees` mints it as a pool note | Equal |
| D15 | Settle proof strength | π_B opens the counterparty commitment and proves the residual (§VI-C) | `settle_large` also range-proves `q ≥ q_ctr` (64-bit) and re-commits collateral; `settle_small` does **not** self-prove "I am smaller" (chain `cmp` gate decides) | Mixed: π_B **Stronger**, π_A **Weaker** (F3, open) |
| D16 | Order identity | `oid` is an opaque unique id | `order_id = SHA-256(coll_nf_0 ‖ coll_nf_1 ‖ fee_nf_0 ‖ fee_nf_1)` | Equal (concretization) |
| D17 | Order commitments | The order commits its quantity; settlement opens `cm(q)` (§V-B, §VI) | The order commits ONLY its collateral: `LockedCommitment = P2(needed(q, own_public_price, side), r_locked)`; compare/settle statements carry each order's own limit/protection price, so unequal public prices do not require a quantity commitment | Equal for priced orders; market protection price is required |

## 2. Details

### D1 — One-shot compare submission instead of two-step share assembly

The paper (§VI-B) keeps `b` and π_cmp in **additive shares** after the
MPC. Each party submits its proof share plus a commitment to its result
share; the chain assembles and verifies π_cmp first, then collects the
result shares (each with a binding proof) and only then publishes `b`.
This defeats a party that forges its share to corrupt the public result
while reconstructing the true result locally.

The implementation collapses this into one writing. Inside the MPC the
proof is opened with a SPDZ MAC check (`open_authenticated`), so both
parties hold the **same, verified** π_cmp or the protocol aborts. `cmp`
is a public input of the proof (6 public signals: `cmp`, the two
collateral commitments, both own prices, `a_is_seller` — D17), both traders
ed25519-sign the canonical message
`(order_a, order_b, cmp)`, and either party submits
`SubmitCompareCoZk2p`. The chain verifies both signatures and the proof.
Unilateral corruption of the public result is impossible: a forged `cmp`
fails the proof, and a forged submission fails the dual-signature check.

**What is lost:** in the paper, neither party knows `b` before the chain
publishes it, so aborting before Step 2 yields zero information. In the
implementation both parties learn `cmp` when the MPC opens it — before
anything is on chain. A malicious party can abort at that point and keep
the one trit "my order is larger/smaller than yours" with no on-chain
trace. The F1 gate (D2) anchors the *amount* reveal, not the `cmp` trit.
The paper itself argues this trit is what order-book semantics disclose
anyway (§III-C, "Publishing b … carries no magnitude"), so the leak is
bounded, but the timing is strictly earlier than in the paper.

### D2 — Reveal ordering (F1)

The paper orders settlement as: verify π_cmp on chain → publish `b` →
smaller party reveals `(q, r)` to the larger party. The first
implementation revealed **before** the compare landed on chain; a
malicious larger party could learn the smaller quantity and abort with
no trace. The rev.4 hardening (F1) restored the paper's ordering and the
current pre-open barrier strengthens it: the session blocks until both
orders are `Settling` and both signed round checkpoints are on chain, and
only then releases an authenticated-encrypted reveal. Session-level test:
`compare_abort_precedes_any_reveal` (cozk2p).

### D3 — Atomic SettlePair (F2)

In the paper each side submits its own update, so one leg can land while
the other never does ("collected the payment, withheld its own"). The
implementation adds a `SettlePair` writing that verifies both legs and
applies both state changes together: both payout notes mint in a single
pool mutation, or nothing changes. The unilateral `SettleSmall`/
`SettleLarge` writings are not registered on the chain, so a party
holding only the counterparty's signed leg cannot collect its payout
alone. The traders exchange their single-prover legs over the still-open
session channel, so either party can submit the pair. Because the order
book and the note pool live in different databases, the writing is
journaled: the payout mint is idempotent per settlement id, and the
order-side updates commit in one transaction with the journal, so a
crash between the two databases is completed exactly once by a retry or
by the startup recovery. This closes the fair-exchange gap the paper
leaves between the two independent updates; a party that withholds its
leg only griefs symmetrically (both orders stay `Settling`), which is
exactly the case D4's freeze mechanism is designed to price.

### D4 — Pre-open checkpoint liveness

After compare confirmation, the chain derives a commitment to the exact
pre-open state: canonical pair ids, match round, both locked commitments,
order kinds and own public prices, common execution price, side, `cmp`, and
both signed transport keys. Each owner uploads a signed checkpoint for that
round. The host does not release `(q, r_locked)` until both uploads exist.
If exactly one upload exists after 10 blocks, its owner can call
`AbortSettleRound`: the compliant order returns to `Pending` and may rematch;
the silent order becomes `Frozen`. This makes failure at the reveal boundary
publicly attributable without publishing the opening.

This does not yet implement the paper's later encrypted on-chain reveal
challenge/re-encryption adjudication, nor its 72-hour automatic unfreeze.

### D5/D6 — Native fees and crossing-price settlement

The paper collateralizes every order with `p·q + f` from shielded funds,
with `f` denominated in the chain's native token. The implementation makes
collateral side-dependent — a sell locks `q` token1, a buy locks `q·p`
token2 — and materializes it as a Poseidon commitment
(`Order.LockedCommitment`) on the order row. The `send_order` circuit
uses separate collateral and native-`invis` input banks and proves each
asset's conservation at admission. When collateral is itself `invis`, one
combined equation conserves lock, fee, and both change outputs. Thus the
book never holds an uncollateralized order and the chain's native fee accrual
matches the value actually destroyed by the proof.
The settle circuits open this single commitment directly (D17; the old
2-slot pad `[LockedCommitment, Poseidon(0,0)]` is gone).

Crossing orders now settle at one immutable price selected by the matcher.
Each locked commitment is opened with its order's own public limit or
protection price, while transfer notes use the execution price. Excess
buy-side collateral becomes a separate shielded refund note; residual
collateral stays priced at that order's own public price. Unequal prices
therefore no longer weaken the locked-only binding and do not require a
second quantity commitment.

### D7 — In-place relist

The paper destroys the larger order and admits a fresh residual order
`o'_B`. The implementation keeps the same order id and rewrites its one
commitment (`LockedCommitment` → `cm_locked_residual`) under a fresh
blinding, then re-enters matching with the original block height.
Privacy is the same — fresh randomness makes the residual commitment
unlinkable to the old value — and the trader keeps its time priority,
which the paper's
new-order formulation would forfeit. The public linkage "this order was
partially filled" exists in both designs (the paper's destruction marking
is equally public).

### D9–D11, D13 — Dev placeholders that void guarantees

These four are not design deviations but **unfinished substitutions**.
Each one voids a paper guarantee until replaced:

- **QUIC + on-chain rendezvous (D9):** network metadata links trader
  identity to on-chain pseudonyms; the paper requires Tor-class
  anonymity for exactly this reason.
- **Mock Beaver triples (D10):** input masks are predictable constants —
  the counterparty can read the other trader's inputs off the shares,
  and the opened proof has no zero-knowledge.
- **Dev SRS (D11):** the KZG toxic waste is recomputable from a public
  seed, so on-chain soundness of π_cmp is zero.
- **Blind bridge (D13):** `NoteDeposit` mints on an operator signature
  (or, with an empty config, on nothing).

See [cozk2p_design.md](cozk2p_design.md) §5 for the full trust-caveat
table.

### D15 — Asymmetric settle-proof strength (F3, open)

The paper's π_B proves the residual arithmetic and that the revealed
`q_A` opens `cm_qA`. The implementation's `settle_large` proves more: a
64-bit range check on `q - q_ctr` (self-proving "I am the larger side"),
collateral conservation at the execution price, and a `bind` public
input that welds the proof to the exact signed request (chain id, order
ids, output commitments). The implementation's `settle_small`, however,
proves only its own opening and payout — it does not self-prove
`q ≤ q_ctr`. The chain's recorded `cmp` gates which circuit each side
may use, so correctness holds, but the symmetry the paper implies
(each proof self-contained) is not there. Tracked as F3 in the
hardening plan (optional Phase B item).

### D17 — Locked-only order commitments

The paper commits each order's quantity and opens that commitment in
the comparison and settlement statements. The implementation commits
ONLY the collateral: `LockedCommitment = P2(needed, r_locked)` with
`needed = q·price + side·(q − q·price)` (a sell locks `q` token1, a
buy locks `q·price` token2). The hidden quantity `q` never gets a
commitment of its own. It is a pure witness: for `price > 0` the
collateral equation is injective in `q`, so opening `LockedCommitment`
against the in-circuit `needed` also fixes `q`. Every statement that
used to open `cm(q)` now opens the collateral through this equation,
which is why both own prices and the side flag are public inputs of the
compare statement (`[cmp, locked_a, locked_b, price_a, price_b, a_is_seller]`)
and of both settle circuits.

**Consequence — each order's own public price is load-bearing.** The
equation pins `q` when the price in its opening statement equals the price
used at admission. The two prices need not equal one another. Execution
price is used only for transfer/refund arithmetic. Because a price-free
market buy cannot pin quantity from quote-asset collateral in this model,
the implementation requires a public protection price for every market
order; it is a collateral/slippage bound, not a limit-book price.

**What it buys:** one commitment per order instead of two; compare has 6
publics, `settle_small` 8, and `settle_large` 11; a relist rewrites only the
collateral commitment — no quantity residual exists.

- §VI-B share commitments `cm_b_A`, `cm_b_B` and binding proofs π_bind
  (subsumed by D1's dual-signature design).
- §VI-D encrypted on-chain reveal/re-encryption adjudication and automatic
  freeze expiry (D4); the pre-open checkpoint freeze is implemented.
- §III-A anonymous communication network (D9).

## 4. Code mechanisms with no paper counterpart

- The `bind` public input in every Groth16 circuit (domain, chain id,
  request fields) — replay protection across chains and requests.
- The order-opening ledger (`orders.json`) and note ledger
  (`notes.json`) wallet files with persist-before-publish rules.
- The session witness WAL (`witness.json`) for crash recovery.
- `ClaimFees` (D14) and the fee-accrual table.
- The grep-gate test (`lib/chain/tests/model_gate.rs`) that keeps the
  deleted legacy cash model from resurfacing.
