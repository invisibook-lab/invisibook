# Implementation vs. the Paper

> **Status:** Current (2026-08-19). Compares the code on this branch with
> [papers/invisibook.pdf](../papers/invisibook.pdf) ("A Privacy-Preserving,
> Censorship-Resistant, Decentralized Order Book", NDSS 2026 submission).
> Update this file when either side changes.

The implementation follows the paper's architecture: public price discovery,
hidden quantities, a 2-party SPDZ-based comparison between the matched
traders, and per-side settlement proofs that the chain verifies. The intended
comparison design is maliciously secure, but the currently configured
`PartyIDBeaverSource` voids production privacy and zero knowledge (D10). This
prototype also lacks a cryptographic binding from the counterparty's
pre-reveal payout-key choice to the settle proof (D18), so the overall
end-to-end claim is only compliant-until-fail-stop. This file lists every
point where the code deviates from the paper, why, and what the deviation
changes.

Legend for the **Effect** column:

- **Stronger** — the code gives a guarantee the paper does not require.
- **Equal** — different mechanism, same guarantee.
- **Weaker** — the code gives less than the paper specifies.
- **Missing** — the paper mechanism is not implemented yet.
- **Dev-only** — a placeholder that voids the guarantee until replaced.

## 1. Summary table

| # | Topic | Paper (§) | Implementation | Effect |
|---|---|---|---|---|
| D1 | Compare submission | Two-step on-chain share assembly of π_cmp and `b` (§VI-B) | Each owner signs and submits the same Fiat–Shamir-common canonical template plus its native SPDZ value shares of the two final KZG G1 points. The chain checks template equality, group-adds only those points, and verifies the constructed proof after both identity/round/deadline-bound submissions arrive | Equal for proof assembly/integrity; **Weaker** for `cmp` timing (see D1) |
| D2 | Reveal ordering | Reveal after the chain publishes `b` (§VI-C) | After comparison verification, both owners exchange and durably record both payout-note key pairs; only then may the smaller opening be revealed. There is no checkpoint and no peer/MPC dependency after disclosure | Equal for ordering; payout authorization is **Weaker** (D18) |
| D3 | Settlement updates | Two independent per-side updates (§V-C, §VI-C) | Each owner independently submits only its own proof. The chain buffers the first and atomically mints/updates after the second verifies | **Stronger** for atomicity; intended-recipient binding is **Weaker** (D18) |
| D4 | Liveness / challenge | Per-submission deadlines and encrypted on-chain reveal challenge with temporary freeze (§VI-D) | Comparison expires at the current round's `MatchHeight + 10`. Verification creates the absolute settlement deadline. At expiry, only `cmp != 0` plus a lone valid large-side leg freezes the missing small owner; zero-leg, only-small, and incomplete `cmp = 0` rounds release both. Attribution is conservative but asymmetric; encrypted adjudication and timed unfreeze remain missing (planned challenge mechanism: settlement_protocol.md §2.4, not implemented) | **Weaker / Partial** |
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
| D18 | Payout-recipient authorization | Settlement pays the counterparty's shielded recipient (§V-C, §VI-C) | Payout-key pairs are exchanged and WAL-persisted before reveal but are not owner-signed or committed on chain; private settle witnesses `npk_ctr, r_note` are not publicly bound to the counterparty's choice | **Weaker / security-critical missing binding** |

## 2. Details

### D1 — Owner-bound comparison proof shares

The paper (§VI-B) keeps `b` and π_cmp in **additive shares** after the
MPC. Each party submits its proof share plus a commitment to its result
share; the chain assembles and verifies π_cmp first, then collects the
result shares (each with a binding proof) and only then publishes `b`.
This defeats a party that forges its share to corrupt the public result
while reconstructing the true result locally.

The concrete TurboPlonk prover must disclose wire, permutation and quotient
commitments plus polynomial evaluations while building its Fiat–Shamir
transcript. Those components are therefore public to both MPC sessions. Each
host submits the SAME canonical template for them; they are checked for
equality and are neither re-shared nor added. The final
`opening_proof` and `shifted_opening_proof` KZG G1 points remain authenticated
additive values. Each host exports only its local `PointShare::share()` for
those two points—the native SPDZ value shares—and does not upload the SPDZ MAC
shares.

`SubmitCompareCoZk2pShare` binds each canonical payload to its owner with an
ed25519 signature over chain id, canonical pair, owner order id, match round,
`cmp`, and the payload digest. After both arrive, chain-side Rust checks their
version and PARTY0/PARTY1 tags, requires all common components to match,
group-adds only the two final G1 share pairs, constructs the standard proof,
and PLONK-verifies it. Neither trader holds or locally verifies the complete
standard proof before this chain step, and neither can submit on behalf of the
other. Every match/rematch refreshes `MatchHeight` and fixes the comparison
deadline at `MatchHeight + 10`; original `BlockHeight` remains the order's
time-priority field. The absolute deadline is included in both owner
signatures, so a submitter cannot choose or extend it.

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
current pre-open barrier blocks until both identity-bound proof shares have
been assembled and verified on chain and both orders are `Settling`; only
then do both sessions exchange and persist both payout-note key pairs. The
authenticated-encrypted reveal follows that bilateral WAL barrier. Its
receiver checks the opening locally against the proof-bound on-chain
commitment, and no peer/MPC operation remains afterward. Session-level test:
`compare_abort_precedes_any_reveal` (cozk2p).

### D3 — Independent proof submission, atomic execution

In the paper each side submits its own update, so one leg can land while
the other never does ("collected the payment, withheld its own"). The
implementation's only owner-leg submission is `SubmitSettleLeg`: each order
owner submits its own proof under an outer identity/pair/round signature. The chain
created the absolute leg deadline when comparison verification succeeded;
submitting a leg cannot reset or extend it. The chain verifies and stores one
leg without changing balances. The second
valid owner leg invokes an internal atomic pair executor: both payout notes
mint in a single pool mutation, or nothing changes. Neither party receives
the other's proof off chain and neither can submit for the other. Because the order
book and the note pool live in different databases, the writing is
journaled: the payout mint is idempotent per settlement id, and the
order-side updates commit in one transaction with the journal, so a
crash between the two databases is completed exactly once by a retry or
by the startup recovery. Once both in-deadline legs are stored, the
permissionless `FinalizeSettleLegs` writing may also resume that same
idempotent journal without changing either leg. This closes the atomicity gap
the paper leaves between the two independent updates while retaining per-owner
accountability through D4's deadline.

### D4 — Phase-specific submission deadlines

There is no checkpoint writing. Every match/rematch stores a fresh
`MatchHeight`, and the exact comparison-share deadline is
`MatchHeight + 10`; original `BlockHeight` is intentionally unchanged for
time priority. Each submission carries and signs that absolute height. If
either share is absent after it, `ExpireCompareCoZk2pShares` returns both
orders to `Pending`: no opening was released, so the chain records a missing
id only for audit and does not punish it.

When the second share reconstructs and verifies π_cmp, that same transaction
creates the settlement-leg row with deadline `verification_height + 10`.
This happens before payout-key exchange and reveal; the first leg neither
starts nor extends the window. Under the intended state machine, where both
clients follow the protocol until one fail-stops, zero legs classify the round
as pre-reveal and either owner can release both without blame. More generally,
for `cmp != 0` a lone valid **large-side** leg proves its owner knew the
smaller opening: `ExpireSettleLegs` returns that owner to `Pending` and
freezes the missing small owner. A lone small-side leg is non-punitive because
it does not prove that the opening reached the large owner. When `cmp = 0`, no
smaller opening was revealed, so every incomplete round releases both.

This is a **conservative but asymmetric attribution rule**. The large-side
circuit opens the counterparty's locked commitment, so a valid large leg
supplies objective knowledge evidence for the punitive direction. The
small-side settlement circuit depends only on the small owner's own opening
and payout data; a Byzantine small owner can construct its leg without
demonstrating that `(q, r_locked)` reached the large owner. Fully symmetric
accountability against arbitrary clients needs verifiable encrypted reveal or
another objective, chain-checkable delivery artifact. A plain signed receipt
does not solve fair exchange: the receiver can learn the opening and then
refuse to release the receipt. This missing mechanism is why D4 remains
weaker than the paper despite the phase-specific deadlines.

This does not yet implement the paper's later encrypted on-chain reveal
challenge/re-encryption adjudication, nor its 72-hour automatic unfreeze.

**Planned repair (TODO, design only).** The large owner sends a signed
on-chain challenge with a fresh encryption public key. The small owner must
answer with a ciphertext and a zero-knowledge proof. The proof shows that the
ciphertext encrypts `(q, r_locked)` under that key, and that the same opening
matches the locked commitment which π_cmp already bound. An answer gives the
large owner the opening and clears the small owner. No answer before the
challenge deadline is objective evidence, so the chain can then release the
large owner and freeze the small owner. An honest small owner always holds
the opening, so a false challenge cannot frame it. The full design and its
open points are in
[settlement_protocol.md](settlement_protocol.md) §2.4.

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
- **Mock Beaver triples (D10):** `PartyIDBeaverSource` supplies predictable
  constant masks — the counterparty can read the other trader's inputs off
  the shares, so the collaborative proof protocol provides no input privacy
  or zero-knowledge guarantee. It is test infrastructure, not a production
  offline phase.
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

### D18 — Payout-key choice is not cryptographically authorized

Before reveal, each session exchanges and WAL-persists both payout-note key
pairs. That makes the inputs available after a fail-stop, but it does not
authenticate the recipient's choice: the pair has no order-owner signature
and no on-chain commitment. In both settle circuits, `npk_ctr` and `r_note`
remain private witness values. The public `cm_note_out` and request `bind`
commit to whichever output the payer chose, but do not prove that its opening
matches the counterparty's pre-reveal pair.

Consequently, a malicious payer can substitute a payout key it controls,
generate a valid settle proof and sign that output request. Atomic pair
execution still prevents one leg from executing alone, but it does not ensure
that either minted payment belongs to the intended counterparty. This is why
the current end-to-end protocol claims only compliant-until-fail-stop
behavior, not Byzantine security.

The planned repair has two linked parts: each recipient owner signs a
round-bound payout-key commitment before reveal and that commitment is stored
or otherwise anchored on chain; both settle circuits then expose a public
binding to the peer commitment, which the chain rebuilds and verifies. A WAL
entry alone is not a substitute for either part.

- §VI-B share commitments `cm_b_A`, `cm_b_B` and binding proofs π_bind
  (subsumed by D1's dual-signature design).
- §VI-D encrypted on-chain reveal/re-encryption adjudication and automatic
  freeze expiry (D4); phase-specific submission deadlines are implemented.
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
