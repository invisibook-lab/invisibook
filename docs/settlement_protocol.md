# Settlement Protocol Reference

> **Status:** Current (2026-08-19, note model + locked-only orders,
> branch `cozk-split`).
> This document is the step-by-step reference for the settlement
> protocol. It names every step trader A and trader B perform, every
> payload they submit, and every constraint each MPC sub-protocol and
> ZK relation enforces. Component overviews:
> [cozk2p_design.md](cozk2p_design.md), [zk_design.md](zk_design.md),
> [chain_design.md](chain_design.md).

## 1. Cast, channels, and notation

Roles are fixed when the pair matches:

| role | who | MPC party | QUIC role |
|---|---|---|---|
| **Trader A** | the maker: lower block height; then intra-block index; then order id | `PARTY0` | dialer |
| **Trader B** | the taker | `PARTY1` | listener |

The **larger / smaller** roles are decided later by
`cmp = sign(q_A − q_B)`. They are orthogonal to A/B.

Three channels carry the protocol:

1. **The chain** — writings and readings (each writing is public).
2. **The QUIC fabric** — the 2-party SPDZ channel (`ark-mpc`). Every
   value on it is either an authenticated share or a deliberate broadcast.
   The amount opening additionally uses an application-layer
   X25519/ChaCha20-Poly1305 channel bound to signed per-round keys.
3. **stdio** — each trader's host app drives its local
   `settle2p_session` subprocess (not a network channel).

Each trader starts with: its order opening `(q, r_locked)` and the
chain-read public rows of both orders. LOCKED-ONLY MODEL: an order commits
ONLY its collateral, `locked = P2(needed, r_locked)` with

```
needed(q, s) = q·price + s·(q − q·price)      (s = 1 sells, s = 0 buys)
```

so a seller locks `q` token1 and a buyer `q·price` token2. The equation is
injective in `q` for `price > 0`, so opening `locked` against an in-circuit
`needed` also pins the hidden quantity; there is no quantity commitment and
no residual-quantity commitment anywhere. Notation: `P2(x, y)` is the
2-input circom Poseidon over BN254 Fr; `[x]` is an authenticated SPDZ share
of `x`; `Com(v, r) = P2(v, r)`.

## 2. The protocol

The MPC proves the comparison (π_cmp). Fiat–Shamir already makes the
proof's common transcript components public to both sessions; each order
owner submits that same canonical template plus its native SPDZ value shares
of the two final KZG G1 points. Only after both payloads arrive, the templates
match, the two point pairs are group-added, and the reconstructed standard
proof verifies may the parties enter the pre-reveal payout-key barrier and
then disclose the smaller opening. Each side subsequently proves and submits
its OWN settle circuit alone. Both payout-note key pairs are exchanged and
durably recorded before reveal, so no peer or MPC dependency remains
afterward. Comparison verification creates the
absolute settlement-leg deadline; the chain buffers owner legs and executes
the pair atomically after the second verifies.

> **Current security scope: compliant-until-fail-stop.** The pre-reveal
> payout-key pairs are exchanged and WAL-persisted, but are not owner-signed
> or committed on chain. In both settle circuits, `npk_ctr` and `r_note` are
> private witness values with no public binding to the counterparty's
> pre-reveal choice. A malicious payer can therefore choose another payout
> opening and generate an otherwise valid proof that redirects the payment.
> The required fix is an owner-signed, pre-reveal payout-key commitment plus a
> public binding to that commitment in both settle circuits and chain checks.
> Until then, atomic execution and timeout attribution do not make the overall
> protocol Byzantine-safe. Independently, the configured
> `PartyIDBeaverSource` uses predictable mock preprocessing: it provides no
> production input privacy or proof zero knowledge and must be replaced by a
> real SPDZ offline phase.

### 2.1 Sequence diagram

```
 Trader A (maker, PARTY0)      chain                Trader B (taker, PARTY1)
 ────────────────────────      ─────                ────────────────────────
     │ RegisterSettleAddr(addr_A,key_A,round) / same for B       │
     ├────────────────────────────▶│◀────────────────────────────┤
     │  QuerySettleAddr ──────────▶│◀────────── QuerySettleAddr  │
     │                             │                             │
     │◀═══════════ QUIC connect: one SPDZ fabric ═══════════════▶│
     │                                                           │
 (1) │ fingerprint(publics) ◀──────plaintext──────▶ fingerprint  │  abort on mismatch
 (2) │ share [q_A],[r_A] ─────────shares──────── [q_B],[r_B]     │
     │ open(P2(needed([q_A]),[r_A]) − locked_A) == 0 (same for B)│  collateral binding
 (3) │ MPC three-way compare ──────────▶ open cmp ∈ {−1,0,1}     │
 (4) │ sign(compare msg) ◀──sig limbs, plaintext──▶ sign(...)    │  host signs cmp
 (5) │ collaborative prove π_cmp; witness-validity gate;         │
     │ open common FS components; retain final G1 value shares    │
     │                             │                             │
 (6) │ SubmitCompareShare(A,round,deadline,cmp,payload_A,outer_sig_A)│
     ├────────────────────────────▶│◀────────────────────────────┤
     │ SubmitCompareShare(B,round,deadline,cmp,payload_B,outer_sig_B)│
     │ chain: require same template; add 2 G1-share pairs;        │
     │        construct + verify π_cmp → both orders Settling   │
     │        create settlement deadline = verify height + 10   │
     │ ...hosts BLOCK until verification (pre-reveal gate)...   │
     │                             │                             │
 (7) │ derive my payout key; WAL own pair                        │
     │◀───────── exchange (npk, r_recv) pairs ──────────────────▶│
     │ WAL peer pair too — BOTH local payout-key WALs durable    │
 (8) │◀── X25519/ChaCha20-Poly1305 Enc(q, r_locked) ────────────▶│
     │ receiver locally checks the proof-bound commitment        │
     │ ...no peer/MPC dependency remains after disclosure...     │
 (9) │ complete witness; rapidsnark π_B │ complete witness; π_A  │  each proves alone
     │ sign own leg                │              sign own leg   │
(10) │ SubmitSettleLeg(owner=A,round,leg_A,outer_sig_A)        │
     ├────────────────────────────▶│◀────────────────────────────┤
     │ SubmitSettleLeg(owner=B,round,leg_B,outer_sig_B)        │
     │   chain: verify BOTH legs → mint BOTH payout notes in one │
     │   pool mutation; small side Done; large side relisted     │
     │  ...both hosts confirm on chain, persist note + residual  │
```

(The diagram shows cmp = 1: A is larger and proves π_B; B is smaller
and proves π_A. When cmp = 0 there is no reveal and BOTH sides prove
π_A with no residuals.)

### 2.2 Steps, actor by actor

| # | Trader A does | Trader B does | Channel | Check that gates progress |
|---|---|---|---|---|
| 0 | `SendOrder`; book matches the pair | same | chain | both orders `Matched`, mutual links |
| R | signed `RegisterSettleAddr(addr, X25519 key, round)`; poll `QuerySettleAddr` | same | chain | peer address/key found for this match round |
| 1 | broadcast Poseidon fingerprint of the chain-read publics | same | fabric (plaintext) | fingerprints equal — stale chain reads abort here |
| 2 | input `[q_A], [r_A]` | input `[q_B], [r_B]` | fabric (shares) | `open(P2(needed([q]), [r]) − locked) == 0` for BOTH orders |
| 3 | run the compare protocol (§3.3) | same | fabric | opened `cmp ∈ {−1,0,1}` |
| 4 | host signs `compare msg(ids, cmp)`; limbs exchanged | same | stdio + fabric | own signature round-trips unchanged |
| 5 | collaborative prove π_cmp; export common canonical template + PARTY0's two final G1 value shares | same template + PARTY1's two final G1 value shares | fabric then local export | witness-validity gate (§3.5) passes; common Fiat–Shamir components are opened as required, but neither session opens or locally verifies a complete standard proof |
| 6 | submit A's identity/round/deadline-bound π_cmp payload | submit B's identity/round/deadline-bound π_cmp payload | chain | this round's `MatchHeight + 10` is the comparison deadline; Rust matches templates, group-adds only the final point-share pairs, and PLONK-verifies before moving both orders to `Settling`. The same transaction creates the settlement deadline `verification_height + 10` |
| 7 | persist own payout `(npk, r_recv)`, exchange both pairs, persist peer pair | same | fabric + local `payout_keys.json` | own pair round-trips unchanged; BOTH local WALs contain both pairs before reveal |
| 8 | (larger) decrypts and locally checks the reveal | (smaller) sends `Enc(q, r)` | fabric (X25519 + ChaCha20-Poly1305) | AEAD authenticates pair/prices/side; the receiver recomputes the proof-bound collateral commitment locally; no later peer/MPC operation |
| 9 | complete `witness.json`; prove `settle_large` (π_B), sign | complete `witness.json`; prove `settle_small` (π_A), sign | local (rapidsnark) | every peer-supplied payout-key input was durable before reveal |
| 10 | submit only A's owner-bound leg | submit only B's owner-bound leg | chain | submissions use the already-open absolute deadline; second valid leg triggers atomic mint/update. At expiry, only `cmp != 0` plus a lone valid large-side leg is punitive: release large and freeze missing small. Zero-leg, only-small, and incomplete `cmp = 0` rounds release both without blame |

Who knows what, and when: `cmp` becomes public at step 3 (in-session)
and on-chain at step 6. Before step 6 neither trader holds the complete
standard PLONK proof: both know the transcript-common template and each
knows only its own two final G1 value shares. The smaller side's
`(q, r_locked)` reaches ONLY the larger side, at step 8, strictly after the
on-chain anchor and the bilateral payout-key WAL barrier. At step 7 each side
first persists its own pair, then persists the peer pair; therefore both
owners already have every peer-supplied payout input before reveal. After
step 8 each can finish locally even if the peer disconnects.

### 2.3 Exact on-chain submissions

**`SubmitCompareCoZk2pShare`** (once per owner):

```json
{"chain_id","order_a_id","order_b_id","owner_order_id",
 "match_round","cmp","deadline_height","proof_share","signature"}
```

The chain verifies `signature` against `owner_order_id`'s order key. It
binds chain id, canonical pair, owner, match round, `cmp`, the exact
chain-derived `deadline_height`, and the SHA-256 digest of `proof_share`
under `invisibook-cozk2p-proof-share-v3`.
`proof_share` is lowercase hex of a versioned, party-tagged canonical Rust
payload. Logically it contains:

- the standard proof's Fiat–Shamir common components (wire, permutation and
  split-quotient commitments, polynomial evaluations, and the Plookup
  option). Both owners submit the SAME canonical template. These public
  components are submitted verbatim and compared for equality; they are
  neither re-shared nor added;
- this party's native additive SPDZ **value share** of each of the final
  `opening_proof` and `shifted_opening_proof` KZG G1 points. The SPDZ MAC
  shares are intentionally not serialized or uploaded because the chain
  does not possess the MPC MAC-key shares.

Every match/rematch writes the same fresh `MatchHeight` to both rows and fixes
`deadline_height = MatchHeight + 10`; original `BlockHeight` is retained only
for time priority. A submitter cannot choose or extend the deadline, and both
payloads must arrive by it. Rust validates version and PARTY0/PARTY1 tags,
requires the common templates to match, performs G1 group addition on only
the two final point-share pairs, constructs the standard PLONK proof, and
verifies it against the chain-rebuilt public statement. No byte-wise share
operation is used.

**`SubmitSettleLeg`** (once per owner):

```json
{"chain_id","order_a_id","order_b_id","owner_order_id","match_round",
 "leg":{"cm_note_out","cm_refund_out","signature","zk_proof",
        "cm_locked_residual"},
 "submission_signature"}
```

The outer `submission_signature` binds identity, canonical pair, round,
all leg outputs, the inner signature, and the proof digest. The leg also
carries its owner's inner signature over a length-prefixed
message: small `["invisibook-settle-small-v2", order_id,
match_order_id, cm_note_out, cm_refund_out]`; large
`["invisibook-settle-large-v2", order_id, match_order_id,
cm_locked_residual, cm_note_out, cm_refund_out]`. Each leg's
Groth16 proof carries a `bind` public input over the same fields plus the
chain id (§4.0).

This request does not choose a deadline. When comparison verification moved
the pair to `Settling`, the chain already created the settlement-leg row with
`deadline_height = verification_height + 10`. A zero-leg expiry is treated as
pre-reveal failure and releases both owners without blame. For `cmp != 0`, a
lone valid large-side leg proves that the large owner knew the smaller
opening; the large owner is released and the missing small owner is frozen.
A lone small-side leg does not prove delivery to the large owner, so the
chain releases both without blame. For `cmp = 0`, no smaller opening exists,
so every incomplete round is also non-punitive.

> **Attribution limit (current threat model).** Proof presence is not
> uniformly objective delivery evidence. The large-side circuit opens the
> counterparty's locked commitment, so a valid large leg supplies evidence
> that its owner knew `(q, r_locked)` and safely supports freezing a missing
> small owner. The small-side circuit uses only that owner's witness, so a
> malicious small owner can generate its leg without proving that the opening
> reached the large owner. The chain therefore does **not** punish an
> only-small timeout. Fully Byzantine symmetric attribution needs a verifiable
> encrypted reveal or another chain-checkable delivery artifact. An ordinary
> signed receipt is insufficient: a receiver may obtain the opening and then
> withhold the receipt, recreating the fair-exchange problem. §2.4 gives the
> planned repair, which is not implemented.

### 2.4 TODO — on-chain reveal challenge (planned, not implemented)

> **Status: design only.** No code, request type, or circuit for this
> section exists. The rules of §2.3 are what the chain does today.

The limit above has one cause: the chain never sees the quantity
disclosure. The disclosure happens off chain, so the chain cannot know
if the round entered the post-disclosure phase. A penalty before that
proof is unsafe, and an owner who did the correct work can get the blame.
The planned repair makes the disclosure itself a chain-checkable step.

**The mechanism.** The large owner starts it only when the small owner
does not send the opening off chain.

1. The large owner sends a signed `ChallengeReveal` writing for the pair
   and the match round. The writing includes one fresh encryption public
   key of the large owner. Only the large owner of a `Settling` pair with
   `cmp != 0` can send it, and only one challenge stays open in a round.
2. The chain records the challenge and starts a second absolute deadline.
   The settlement-leg deadline of §2.3 waits for the result of the
   challenge.
3. The small owner answers with an `AnswerReveal` writing. The writing
   has a ciphertext and a zero-knowledge proof. The proof shows two
   facts together:
   - the ciphertext is an encryption of `(q, r_locked)` under the public
     key from the challenge, and
   - the same `(q, r_locked)` opens the locked commitment of the small
     order, which π_cmp already bound on chain.
4. If the chain accepts the answer, the large owner decrypts the
   ciphertext with its private key, makes its leg, and submits it in a
   new leg window. No owner gets the blame, because the small owner
   delivered the opening.
5. If no valid answer comes before the challenge deadline, the missing
   disclosure is now objective and on chain. The chain releases the large
   owner and freezes the small owner.

**Why this closes the gap.** The chain gets the delivery evidence that a
signed receipt cannot give. An honest small owner always holds
`(q, r_locked)`, so it can always answer and clear itself. A false
challenge therefore costs the large owner one more round, but it cannot
frame an honest owner. The chain punishes only after it sees a failure to
answer. The state machine therefore proves entry into the post-disclosure
phase before any penalty.

**Open points before implementation.**

- Select the encryption scheme. It must be efficient in a circuit and
  must use the field of the settlement proof system.
- Set the challenge window, and decide if a challenge is permitted
  before the leg deadline or only at it.
- Add the paper's automatic unfreeze (§VI-D, 72 hours) so a freeze
  cannot stay forever.
- This mechanism does not repair the payout-recipient binding of §3.4.
  The two gaps are independent.

### 2.5 Measured latency, step by step

Medians of 5 `settle_e2e_relist` trades (24-core box, 3 s blocks, 2 s
polling, dev SRS and mock Beaver triples), trader A's column; B differs
only where noted. Rows are the steps of §2.2. Reproduce with
`./experiments/rq3_end_to_end.sh --runs 5`; the full record is in
[cozk_experiments.md](cozk_experiments.md) §RQ3.

| step | ms |
|---|---|
| 0 `SendOrder` prove (rapidsnark) | 192 |
| 0 `SendOrder` submit → `Pending` (block wait) | 4 007 (A) / 6 010 (B) |
| 0 matching → both `Matched` (block wait) | 4 006 |
| 1 preamble fingerprint | 2 |
| 2 share inputs + collateral binding (2 Poseidon over shares) | 43 |
| 3 three-way compare | 14 |
| 4 signature ferry + exchange | 1 |
| 5 collaborative prove π_cmp (historical baseline) | 3 646 |
| 6 on-chain compare wait (historical baseline) | 6 010 |
| 7 smaller-side reveal | 2 |
| 8 payout-note keys + WAL | 1 |
| **session subprocess total** | **10 034** |
| 9 own settle leg + R rendezvous + 10 settlement confirm (historical baseline) | 10 110 |
| **`run_settle` total** | **20 144** (p95 22 094) |
| **full trade, both orders** | **34 553** (p95 36 507) |

Step 5 is 18 % of the settlement, and every other cryptographic step
together is under 100 ms. The block waits — steps 6 and 10 and the
rendezvous — are 80 %.

The same historical run reported 12.4 ms for chain-side π_cmp verification,
4.4–4.6 ms for each Groth16 settlement leg, and 7 264 B on chain: 1 522 B per
`SendOrder`, 1 999 B for the then-current comparison writing, and 2 221 B for
the then-current atomic settlement writing. These figures predate the
two-submission redesign. They remain a cryptographic baseline but are not
current transaction-count or wire-size measurements; RQ3 must be rerun for
those values.


## 3. MPC sub-protocols and their checks

All building blocks run on the SPDZ fabric: every in-fabric share carries an
information-theoretic MAC, and `open_authenticated` MAC-checks values opened
through that API. The chain payload is a deliberate boundary: it exports only
the two final points' local value shares, never their MAC shares. Final
validity comes from PLONK verification after algebraic reconstruction. Both parties
enqueue fabric operations in identical canonical order (A's values
first) so the dataflow op-ids align.

### 3.1 Statement fingerprint (twice)

Each party folds its chain-read public inputs with Poseidon
(`h ← P2(h, x_i)`, seeded with the field count) and broadcasts the
digest in plaintext. Check: the two digests are equal. Run once at
session start and once again inside the prover. Purpose: a stale chain
read fails with a clear error instead of a MAC failure deep inside
proving.

### 3.2 Collateral binding

Each order's collateral commitment is its ONLY on-chain commitment. For
`locked` with shared opening
`[q], [r_locked]`: scale the quantity share into its collateral
denomination — `needed([q]) = [q]` (seller) or `[q]·price` (buyer); the
side flags and price are public, so the scaling is share-local and costs
no Beaver triple — then compute `P2(needed([q]), [r_locked])` over shares
(243 Beaver multiplications per hash: the x^5 S-box costs 3, ARK/MDS are
linear) and check `open(P2(...) − locked) == 0`. Purpose: a party whose
witness does not open its ON-CHAIN commitment is caught before any
expensive phase; because the equation is injective in `q`, this also
pins the quantity that goes into the comparison.

### 3.3 Three-way comparison (`compare_geq` × 2)

For each direction (`a ≥ b`, then `b ≥ a`):

1. `[d] = [v1] − [v2] + 2^64`. Bit 64 of `d` is 1 iff `v1 ≥ v2`
   (inputs are < 2^64, guaranteed by §3.2).
2. Draw 105 random shared bits (65 comparison bits + 40 statistical
   masking bits) and compose `[m] = Σ m_i 2^i`.
3. Open `c = d + m` (safe: 40 extra masking bits).
4. Recompute bit 64 of `d = c − m` with a shared ripple-borrow circuit
   over the public bits of `c` and the shared bits of `m`
   (~64 Beaver multiplications), then
   `d_64 = c_64 XOR m_64 XOR borrow`.

Open both direction bits. Checks: each opened value must be exactly 0
or 1, and the pair `(0, 0)` (impossible for honest inputs) aborts.
Map `(1,1) → 0`, `(1,0) → +1`, `(0,1) → −1`. Leakage: `cmp` only.

### 3.4 Pre-reveal payout-key barrier and encrypted reveal

Signatures and payout `(npk, r)` pairs use
`share_plaintext(payload, sender)` inside the authenticated fabric. The
sender echo-checks the result, so transport corruption aborts. Before any
quantity opening, each side writes its own payout pair to
`payout_keys.json`, exchanges both pairs, and rewrites the WAL with the peer
pair. The reveal barrier is crossed only after BOTH local WALs contain both
pairs. This is an operational barrier, not recipient authorization: the
pairs carry no owner signature and have no on-chain commitment, and the
settle proof does not expose a public value that binds its private
`(npk_ctr, r_note)` to the peer's WAL choice. A Byzantine payer can substitute
another note opening while still producing a valid proof. The planned repair
is to owner-sign and commit each payout-key choice before reveal, then add and
verify that commitment as a settle-circuit public binding.

The quantity opening is different: the smaller party encrypts `(q,
r_locked)` with ChaCha20-Poly1305 under a per-match-round X25519 shared key
whose public keys are signed and included in the comparison state
commitment. Only ciphertext traverses the fabric. After decryption, the
receiver locally recomputes `needed(q, price, side)` and its Poseidon
commitment and requires it to equal the on-chain commitment already bound by
π_cmp. There is deliberately no authenticated opening or other MPC round
after plaintext disclosure. A lying reveal aborts locally, while a malicious
peer that disconnects after disclosure cannot prevent the honest owner from
finishing its witness and proof.

### 3.5 Witness-validity gate (before ANY proof element is revealed)

SPDZ gives correct-or-abort computation on the GIVEN shares; it does
not stop a party from inputting shares that make the joint witness
unsatisfiable, and a proof over an invalid witness is outside the
zk-SNARK's zero-knowledge guarantee (eprint 2025/1026, Pitfall 1). So,
before proving:

1. Collect one residual per relation constraint: `lhs − rhs` for every
   equality, `b² − b` for every booleanity (squares batched into one
   round).
2. Draw a fresh MAC-opened random challenge `γ` (after inputs are
   committed, so residuals cannot be chosen to cancel).
3. Form `S = Σ γ^i · r_i`, mask it with a fresh shared random `m`, and
   open `S · m` once.
4. Require 0. By Schwartz–Zippel a nonzero residual survives except
   with negligible probability; the mask makes a rejection leak
   nothing beyond "invalid".

### 3.6 Collaborative prove and native-share export

`MultiproverPlonkKzgSnark::prove` runs the TurboPlonk rounds with every wire
an SPDZ share. Fiat–Shamir requires the wire, permutation and quotient
commitments plus polynomial evaluations to be disclosed while deriving later
challenges. Those already-public values form an identical canonical template
in both sessions; they are not secret-shared again.

The last round leaves `opening_proof` and `shifted_opening_proof` as
`AuthenticatedPointResult`s. Each session awaits its local handle directly,
which yields its own `PointShare`, and places only `PointShare::share()` in
the two corresponding G1 fields. It does **not** call
`open_authenticated` on those final points and does not serialize
`PointShare::mac()`. Consequently neither trader constructs or locally
verifies the complete standard proof. The chain-side Rust bridge checks the
two templates for equality, group-adds the PARTY0/PARTY1 value shares for the
two final points, constructs the standard proof, and runs the ordinary PLONK
verifier before allowing reveal.

## 4. ZK relations: complete constraint lists

### 4.0 Shared notation

- **[RANGE(x)]** — 64-bit range check. In circom: `Num2Bits(64)`. In
  the PLONK relations: the value ENTERS as 64 owner-supplied LE bits;
  every bit gets a booleanity constraint `b·(b−1) = 0` and the value is
  the recomposition `Σ b_i 2^i` (the MPC circuit cannot bit-decompose a
  share, so decomposition is replaced by owner supply + booleanity).
  Purpose: field arithmetic is mod p; without the range check, wrap-
  around mints value or fools the comparison.
- **[OPEN(c; v, r)]** — `P2(v, r) === c`: the prover knows an opening
  of the public commitment `c`.
- **[BIND]** — Groth16 circuits only: a public input
  `bind = SHA-256(domain ‖ chain_id ‖ writing ‖ version ‖ request
  fields) mod r`, welding the proof to one exact request on one chain.
  In-circuit it is only kept alive (`bind·bind`); the Groth16
  verification equation binds its value. The PLONK relations have no
  bind: the dual ed25519 signatures over the full statement play that
  role.
- **NoteCommit(npk, asset, v, r)** — the pool note chain
  `P2(P2(P2(P2(3, npk), asset), v), r)`.

Every count below is MEASURED, not estimated:

- PLONK relations: the real circuit builders carry a step tracer that
  reads `num_gates()` after each constraint group
  (`cargo test -p cozk2p --test gate_census -- --nocapture`). The unit
  is TurboPlonk gates; `finalize_for_arithmetization` pads the total to
  the next power-of-two evaluation domain.
- Groth16 circuits: `scripts/circom_step_census.py` compiles CUMULATIVE
  variants of each circuit (the body truncated after each step) with
  circom 2.2.3 and takes the per-step delta of NON-LINEAR R1CS
  constraints (the Groth16 cost metric). The final variant is
  cross-checked against compiling the pristine file — the script fails
  on any drift.

### 4.1 π_cmp — the compare relation (collaborative PLONK; Groth16 twin `settle_cozk.circom`)

Publics (6): `[cmp, locked_a, locked_b, price_a, price_b, a_is_seller]`.
Private (per side, supplied by its owner): `q` as 64 LE bits, `r_locked`.
Both own prices and `a_is_seller` are PUBLIC wires the chain builds from
the order rows, so they cannot be substituted by a prover.

| # | Constraint | Purpose | gates |
|---|---|---|---|
| 1 | booleanity of all 128 amount bits | [RANGE] for both quantities | 128 |
| 2 | `q_a = Σ bits·2^i`, `q_b = Σ bits·2^i` | recomposition | 44 |
| 3 | `needed_a = q_a·price_a + s_a·(q_a − q_a·price_a)`; [OPEN(locked_a; needed_a, r_a)] | the compared value backs A's on-chain collateral (input legitimacy) | 477 |
| 4 | same for B with `s_b = 1 − s_a` | B is always the opposite side | 476 |
| 5 | MSB-first scan, per bit: `m = a_i·b_i`; `xnor = 1 − a_i − b_i + 2m`; `lt += eq_prefix·(b_i − m)`; `eq_prefix ·= xnor` | strict-less and equal flags | 384 |
| 6 | `gt = 1 − lt − eq`; `cmp === gt − lt` | the public claim is exactly `sign(q_a − q_b)` | 3 |

Measured total: 8 (allocation) + 1 512 = **1 520 gates**, padded to
**2 048** by finalization. The Groth16 twin (`settle_cozk.circom`)
proves the identical statement with `LessThan(64)` comparators —
measured **742 non-linear R1CS constraints**; the chain accepts either.

### 4.2 `settle_small` — π_A, the fully filled side (Groth16)

Publics (8): `[locked, collateral_price, execution_price, side, pay_asset,
cm_note_out, cm_refund_out, bind]`. Private: `q, r_locked, npk_ctr,
r_note, npk_refund, r_refund`.

| # | Constraint | Purpose | constraints |
|---|---|---|---|
| 1 | `side·(1 − side) === 0` | side flag is boolean | 1 |
| 2 | [RANGE(q)], [RANGE(collateral_price)], [RANGE(execution_price)] | all price products are integer-exact | — |
| 3 | `needed = needed(q, collateral_price, side)`; [OPEN(locked; needed, r_locked)] | the order's own public price pins its quantity | — |
| 4 | `payment = needed(q, execution_price, side)`; `refund = needed − payment`; range-check both | crossing-price conservation | — |
| 5 | payout and refund `NoteCommit` checks | commits payment to the prover-supplied private `npk_ctr`; a compliant host uses the peer WAL choice, but the circuit lacks a public owner binding; price improvement returns shielded to the owner | — |
| 6 | [BIND] over both output commitments | anti-replay weld | 1 |

The complete circuit measures **2 608 non-linear R1CS constraints** with
circom 2.2.3 at `--O2`.

Note the deliberate asymmetry: π_A does NOT self-prove `q ≤ q_ctr`.
The chain's recorded `cmp` decides which circuit each side may use
(F3; [paper_deviations.md](paper_deviations.md) D15).

### 4.3 `settle_large` — π_B, the surviving side (Groth16)

Publics (11): `[locked, locked_ctr, collateral_price,
ctr_collateral_price, execution_price, side, cm_locked_residual, pay_asset,
cm_note_out, cm_refund_out, bind]`. Private also includes both locked
openings, the residual opening, and payout/refund note openings.

| # | Constraint | Purpose | constraints |
|---|---|---|---|
| 1 | `side·(1 − side) === 0` | boolean side flag | 1 |
| 2 | [RANGE(q)], [RANGE(q_ctr)], and all three prices | every product is 64-bit | — |
| 3 | `needed = needed(q, collateral_price, side)`; [OPEN(locked; needed, r_locked)] | own collateral opens at its own price | — |
| 4 | `needed_ctr = needed(q_ctr, ctr_collateral_price, 1 − side)`; [OPEN(locked_ctr; needed_ctr, r_locked_ctr)] | the encrypted/revealed counterparty opening matches its on-chain collateral | — |
| 5 | `q_res = q − q_ctr`; [RANGE(q_res)] | the 64-bit range of the difference IS the `q ≥ q_ctr` proof (a wrap-around would exceed 64 bits) | 64 |
| 6 | `locked_res = needed(q_res, collateral_price, side)`; residual commitment check | residual stays collateralized at its order's own price | — |
| 7 | payment at `execution_price`; `refund = needed − locked_res − payment`; range-check both | crossing-price conservation | — |
| 8 | payout and refund `NoteCommit` checks; [BIND] over all outputs | atomic shielded outputs + anti-replay weld, but no public binding from private `npk_ctr, r_note` to the peer's pre-reveal choice | — |

The complete circuit measures **3 284 non-linear R1CS constraints** with
circom 2.2.3 at `--O2`.

## 5. What the chain verifies, writing by writing

**`SubmitCompareCoZk2pShare`** — pair preconditions (`loadMatchedPair`):
both orders exist, both `Matched`, mutually linked, opposite sides,
order A is the maker, prices valid and crossing, and both rows carry the
same valid persisted execution price. Each owner signature binds its share,
identity, round, chain, and the `MatchHeight + 10` comparison deadline. Only
after both shares arrive does the chain
require the common canonical templates to match, group-add the two final KZG
point-share pairs, construct π_cmp, and verify it against the rebuilt statement
`{cmp, orderA.LockedCommitment, orderB.LockedCommitment, priceA, priceB,
orderA.Type == Sell}`. Effect: store `cmp`, both orders → `Settling`, and
create the settlement-leg round with absolute deadline
`verification_height + 10` in the same transaction.

**`SubmitSettleLeg` / `FinalizeSettleLegs` / `ExpireSettleLegs`** — both orders are `Settling`
and mutually linked; recorded `cmp` selects the submitting owner's circuit
(cmp = 0 → both π_A). The chain immediately verifies that owner's inner
signature and Groth16 proof against publics rebuilt from ORDER ROWS, then
records it inside the comparison-created window. The second valid leg invokes
the journaled pipeline: journal row →
idempotent mint of both payout notes in ONE pool mutation → close the
filled side(s) + relist the larger side in place (same id, same block
height, fresh commitments) + journal DONE in one transaction → re-match
+ cleanup. A crash anywhere is completed by a same-owner resubmission or
boot-time recovery. If both in-deadline legs are stored but execution is not
marked complete, either app (or any caller) may invoke permissionless
`FinalizeSettleLegs`; it cannot alter the stored proofs, outputs, or
signatures. Zero legs classify the round as pre-reveal and either
owner may release both without blame. For `cmp != 0`, a lone large-side leg
proves knowledge of the small opening; expiry returns the large owner to
`Pending` and freezes the missing small owner. A lone small-side leg can be
constructed independently and does not prove delivery, so it releases both
without blame. For `cmp = 0` no opening was revealed, so every incomplete
round also releases both.

## 6. Security-ordering summary

| property | how the protocol gets it |
|---|---|
| anchor before disclosure | reveal waits until both canonical share payloads reconstruct/verify π_cmp and the chain creates the absolute settlement window |
| durable pre-reveal inputs | both sides persist own and peer payout-note pairs before the smaller opening is sent; this is an operational WAL invariant, not cryptographic owner authorization |
| what the counterparty learns | `cmp`, then the smaller side's full opening `(q, r_locked)` |
| post-reveal independence | the reveal is checked locally; all later witness/proof work has no peer/MPC dependency |
| atomic execution | each owner uploads only its own proof; execution still mints both notes or nothing, but the current circuits do not guarantee that a malicious payer selected the peer-authorized recipient key |
| payout-recipient binding | **missing**: payout pairs are unsigned/off-chain and private `npk_ctr, r_note` are not bound to a public peer commitment; add owner-signed pre-reveal commitments and settle-circuit public bindings |
| circuit-role gating | F3: the chain's `cmp` decides who may use π_A/π_B |
| abort before comparison verification | the round deadline is `MatchHeight + 10`; an incomplete comparison-share round releases both without punishment |
| abort after verification but before reveal | comparison verification already started the settlement deadline; 0 legs at expiry release both without blame |
| abort after reveal | for `cmp != 0`, only a lone large-side leg proves knowledge of the opening and freezes the missing small owner; only-small remains unattributed and releases both |
| Byzantine attribution limit | the rule is conservative and asymmetric: a small leg alone does not prove delivery of `q`; symmetric Byzantine accountability requires verifiable encrypted reveal/objective delivery evidence, and a withholdable signed receipt is not enough |
| planned: on-chain reveal challenge | **TODO, design only (§2.4)**: the large owner challenges with a fresh encryption key; the small owner answers with a ciphertext plus a proof that it encrypts the opening of the commitment π_cmp bound; no answer before the challenge deadline gives objective, non-framing evidence for a freeze |
