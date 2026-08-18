# Implementation vs. the Paper

> **Status:** Current (2026-08-17). Compares the code on this branch with
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
| D4 | Liveness / challenge | Deadlines, freeze penalty, encrypted on-chain reveal challenge, adjudication (§VI-D) | Not implemented. Design only (hardening plan Phase C). `Frozen`/`Cancelled` states exist but are not wired | **Missing** |
| D5 | Collateral shape | Order spends notes worth `p·q + f`; collateral stays in the shielded layer (§V-B) | Side-dependent collateral (`q` of token1 for a sell, `q·p` of token2 for a buy) carried as a `LockedCommitment` on the order row; fee paid from the same notes | Equal (concretization) |
| D6 | Execution price | Crossing prices match; the executed price is not pinned (§V-C) | The MATCHER only pairs equal-price orders (crossing-but-unequal orders stay Pending), because the settle circuits require the execution price to equal the collateral price and a Matched pair has no cancel path | **Weaker** (scope restriction; load-bearing for soundness since D17) |
| D7 | Partial-fill relist | The residual becomes a **new** order `o'_B` (§V-C) | The chain relists the **same** order id in place with the residual collateral commitment; block height (time priority) is retained | **Stronger** (keeps priority; same privacy: fresh blinding) |
| D8 | Matching rule | Price → block height → fee → intra-block index; pairwise (§V-C) | Same priority chain, but the price dimension is an EQUALITY filter (D6): only equal-price candidates compete on height → fee → index | Equal (within D6's scope) |
| D9 | P2P transport | Anonymous network (Tor) required (§III-A) | Direct QUIC; peer addresses exchanged in plaintext on chain (`RegisterSettleAddr`) | **Dev-only** |
| D10 | MPC offline phase | SPDZ with a real preprocessing phase (§VI-A) | `PartyIDBeaverSource` mock triples: predictable masks, **no input privacy, no proof zero-knowledge** | **Dev-only** |
| D11 | SNARK setup | Black-box collaborative zk-SNARK (§IV-B) | mpc-jellyfish TurboPlonk over a **fixed-seed dev SRS**: anyone can forge proofs | **Dev-only** |
| D12 | Shielded layer | Assumed from the chain (assumption (iv), §III-A) | Built in-repo: Poseidon note pool, depth-20 tree, nullifiers, 2-slot spends, Orchard-style dummies | Equal (self-hosted) |
| D13 | Bridge proofs | Out of scope | `NoteDeposit` trusts an operator signature (or nothing, in dev); no inclusion/release proofs | **Dev-only** |
| D14 | Fee payout | Fee paid to the miner like a Zcash fee (§V-B) | Plaintext fee accrues per block producer; `ClaimFees` mints it as a pool note | Equal |
| D15 | Settle proof strength | π_B opens the counterparty commitment and proves the residual (§VI-C) | `settle_large` also range-proves `q ≥ q_ctr` (64-bit) and re-commits collateral; `settle_small` does **not** self-prove "I am smaller" (chain `cmp` gate decides) | Mixed: π_B **Stronger**, π_A **Weaker** (F3, open) |
| D16 | Order identity | `oid` is an opaque unique id | `order_id = SHA-256(nf_0 ‖ nf_1)` over the spent input nullifiers | Equal (concretization) |
| D17 | Order commitments | The order commits its quantity; settlement opens `cm(q)` (§V-B, §VI) | The order commits ONLY its collateral: `LockedCommitment = P2(needed, r_locked)` with `needed = q·price + side·(q − q·price)`; the hidden `q` is a pure witness pinned by this equation | Equal **within D6's scope**; the equal-price rule becomes load-bearing (see D17) |

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
is a public input of the proof (5 public signals: `cmp`, the two
collateral commitments, `price`, `a_is_seller` — D17), both traders
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
no trace. The rev.4 hardening (F1) restored the paper's ordering: the
session blocks in `confirm_compare_onchain` until both orders are
`Settling` on chain, and only then reveals. Session-level test:
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

### D4 — Liveness and the challenge mechanism (not implemented)

The paper's §VI-D specifies: per-step submission deadlines (Δ_sub = 10
blocks), a 72-hour freeze of the staller with release of the compliant
party, an encrypted on-chain reveal challenge
(`Enc_pkB(q_A, r_A)` + re-encryption adjudication), and no slashing.
None of this exists on chain yet. What exists is attributability: after
F1/F2, a stalled settlement leaves the pair visibly `Settling` on chain,
which is the anchor the freeze mechanism needs. The design is tracked as
Phase C in
[settlement_hardening_plan_zh.md](settlement_hardening_plan_zh.md).

### D5/D6 — Collateral and the equal-price restriction

The paper collateralizes every order with `p·q + f` from shielded funds
and keeps the collateral in the shielded layer. The implementation makes
collateral side-dependent — a sell locks `q` token1, a buy locks `q·p`
token2 — and materializes it as a Poseidon commitment
(`Order.LockedCommitment`) on the order row. The `send_order` circuit
proves conservation (`inputs = collateral + fee + change`) at admission,
so the book never holds an uncollateralized order (same §V-B invariant).
The settle circuits open this single commitment directly (D17; the old
2-slot pad `[LockedCommitment, Poseidon(0,0)]` is gone).

Because collateral is locked at the order's own price and the settle
circuits equate that price with the execution price, only equal-price
pairs can settle today — so the MATCHER itself only pairs orders with
exactly equal prices. Crossing but unequal orders stay Pending (a
Matched pair has no cancel path; matching it would lock both sides
forever). The paper's model (any crossing pair matches) needs a
price-improvement change output in the settle circuits first — and,
under the locked-only model, a quantity commitment again or a
redesigned statement (D17).

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
which is why `price` and the side flag are public inputs of the
compare statement (`[cmp, locked_a, locked_b, price, a_is_seller]`)
and of both settle circuits.

**Consequence — the equal-price rule is load-bearing.** The equation
pins `q` only when the price in the statement equals the price the
collateral was locked at, which the matcher's equal-price rule (D6)
guarantees. D6 was a scope restriction; D17 turns it into a soundness
precondition. Price improvement or cross-price settlement would need
the quantity commitment back, or a redesigned statement.

**What it buys:** one commitment per order instead of two; smaller
statements (compare 5 publics instead of a commitment pair per order;
`settle_small` 6, `settle_large` 8); a relist rewrites only the
collateral commitment — no quantity residual exists.

- §VI-B share commitments `cm_b_A`, `cm_b_B` and binding proofs π_bind
  (subsumed by D1's dual-signature design).
- §VI-D enforcement requests, encrypted reveal, re-encryption
  adjudication, freeze timers (D4).
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
