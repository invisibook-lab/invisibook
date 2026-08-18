# Settlement Protocol Reference

> **Status:** Current (2026-08-18, note model + locked-only orders,
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
| **Trader A** | the maker: lower block height; tie → smaller order id | `PARTY0` | dialer |
| **Trader B** | the taker | `PARTY1` | listener |

The **larger / smaller** roles are decided later by
`cmp = sign(q_A − q_B)`. They are orthogonal to A/B.

Three channels carry the protocol:

1. **The chain** — writings and readings (each writing is public).
2. **The QUIC fabric** — the 2-party SPDZ channel (`ark-mpc`). Every
   value on it is either an authenticated share or a deliberate
   plaintext broadcast.
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

The MPC proves the comparison (π_cmp). After `cmp` is public and
anchored on chain, the smaller side reveals its opening; each side then
proves its OWN settle circuit alone, and one atomic writing settles
both legs.

### 2.1 Sequence diagram

```
 Trader A (maker, PARTY0)      chain                Trader B (taker, PARTY1)
 ────────────────────────      ─────                ────────────────────────
     │  RegisterSettleAddr(addr_A) │  RegisterSettleAddr(addr_B) │
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
     │ MAC-checked open; each side verifies π_cmp locally        │
     │                             │                             │
 (6) │ SubmitCompareCoZk2p{ids, cmp, sig_A, sig_B, π_cmp}        │  either party
     ├────────────────────────────▶│◀────────────(or)────────────┤
     │      chain: verify 2 sigs + π_cmp → both orders Settling  │
     │  ...both hosts BLOCK until Settling confirmed (F1)...     │
     │                             │                             │
 (7) │◀───── smaller side reveals (q, r_locked) in plaintext ───▶│
     │ open([q_small] − q) == 0, open([r_small] − r) == 0        │  lying reveal aborts
 (8) │ derive my payout (npk, r_recv); WAL v1;                   │
     │◀───────── exchange (npk, r_recv) pairs ──────────────────▶│  WAL v2
 (9) │ rapidsnark π_B (large)      │      rapidsnark π_A (small) │  each proves alone
     │ sign own leg                │              sign own leg   │
     │◀═══════════ exchange signed legs over the fabric ════════▶│
(10) │ SettlePair{ids, leg_A, leg_B}                             │  either party
     ├────────────────────────────▶│◀────────────(or)────────────┤
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
| R | `RegisterSettleAddr`; poll `QuerySettleAddr` | same | chain | peer address found |
| 1 | broadcast Poseidon fingerprint of the chain-read publics | same | fabric (plaintext) | fingerprints equal — stale chain reads abort here |
| 2 | input `[q_A], [r_A]` | input `[q_B], [r_B]` | fabric (shares) | `open(P2(needed([q]), [r]) − locked) == 0` for BOTH orders |
| 3 | run the compare protocol (§3.3) | same | fabric | opened `cmp ∈ {−1,0,1}` |
| 4 | host signs `compare msg(ids, cmp)`; limbs exchanged | same | stdio + fabric | own signature round-trips unchanged |
| 5 | collaborative prove π_cmp | same | fabric | witness-validity gate (§3.5) passes; local verify of the opened proof |
| 6 | either host submits `SubmitCompareCoZk2p`; both BLOCK until both orders are `Settling` | same | chain | the F1 anchor: nothing was revealed yet, so aborting here leaks nothing |
| 7 | (larger) receives the reveal | (smaller) broadcasts `(q, r)` | fabric (plaintext) | `open([q_small] − q) == 0` and same for `r` |
| 8 | derive own payout-note opening `(npk, r_recv)`; write WAL v1; exchange the pairs; write WAL v2 | same | fabric (plaintext) | own pair round-trips unchanged |
| 9 | prove `settle_large` (π_B), sign the leg | prove `settle_small` (π_A), sign the leg | local (rapidsnark) | — |
| 9' | exchange the signed legs | same | fabric (plaintext) | leg roles consistent (one A-leg, one B-leg) |
| 10 | either host submits `SettlePair`; both confirm on chain; persist the payout note (PENDING_MINT) and, for the larger side, the residual order opening | same | chain | small order `Done`; large order relisted `Pending` under its residual COLLATERAL commitment |

Who knows what, and when: `cmp` becomes public at step 3 (in-session)
and on-chain at step 6. The smaller side's `(q, r_locked)` reaches ONLY
the larger side, at step 7, strictly after the on-chain anchor.
Payout-note openings are on the RECEIVER's disk (WAL) before the payer
ever sees `(npk, r_recv)`.

### 2.3 Exact on-chain submissions

**`SubmitCompareCoZk2p`** (either party):

```json
{"order_a_id","order_b_id","cmp","sig_a","sig_b","zk_proof"}
```

`sig_a`/`sig_b` are both traders' ed25519 signatures over the SAME
message `"invisibook-cozk2p-compare-v2:{order_a_id}:{order_b_id}:{cmp}"`.
`zk_proof` is the hex ark-compressed collaborative PLONK π_cmp.

**`SettlePair`** (either party):

```json
{"order_a_id","order_b_id",
 "a":{"cm_note_out","signature","zk_proof"},                      // small leg
 "b":{"cm_note_out","signature","zk_proof",
      "cm_locked_residual"}}                                      // large leg
```

Each leg carries its OWN owner's signature over a length-prefixed
message: small `["invisibook-settle-small-v1", order_id,
match_order_id, cm_note_out]`; large `["invisibook-settle-large-v1",
order_id, match_order_id, cm_locked_residual, cm_note_out]`. Each leg's
Groth16 proof carries a `bind` public input over the same fields plus the
chain id (§4.0).

### 2.4 Measured latency, step by step

One `settle_e2e_relist` run (24-core box, 3 s blocks, dev SRS + mock
Beaver triples), trader A's column; B differs only where noted. Rows are
the steps of §2.2:

| step | ms |
|---|---|
| 0 `SendOrder` prove (rapidsnark) | 202 |
| 0 `SendOrder` submit → `Pending` (block wait) | 4 008 |
| 0 matching → both `Matched` (block wait) | 4 007 |
| 1 preamble fingerprint | 2 |
| 2 share inputs + collateral binding (2 Poseidon over shares) | 59 |
| 3 three-way compare | 20 |
| 4 signature ferry + exchange | 1 |
| 5 collaborative prove π_cmp + local verify | 3 716 |
| 6 on-chain compare anchor (host/chain wait) | 6 011 |
| 7 smaller-side reveal | 5 |
| 8 payout-note keys + WAL | 1 |
| **session subprocess total** | **10 206** |
| 9 own settle leg (rapidsnark) + 9' leg exchange | 1 (A) / 142 (B) |
| R + 10 rendezvous, `SettlePair` submit, confirm | 12 147 |
| **`run_settle` total** | **22 353** |
| **full trade, both orders** | **36 798** |

Step 5 is 36 % of the settlement and every other cryptographic step
together is under 100 ms. Steps 6 and 10 — pure block waits — are 81 %.


## 3. MPC sub-protocols and their checks

All building blocks run on the SPDZ fabric: every share carries an
information-theoretic MAC, every `open_authenticated` MAC-checks the
revealed value, and any deviation aborts the session. Both parties
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

### 3.4 Authenticated plaintext exchange (sigs, npk pairs, legs, reveals)

One-directional inputs use `share_plaintext(payload, sender)`: the
sender's value reaches both parties. Two integrity patterns apply:

- **Echo check** (signatures, npk pairs, settle legs): the sender
  compares the broadcast result with what it sent; any transport
  corruption aborts.
- **Share-binding check** (reveals): the revealed plaintext is
  subtracted from the MPC-verified share and the difference is opened:
  `open([x] − x_revealed) == 0`. A lying reveal aborts immediately —
  the revealed value is provably the one the MPC compared and proved.

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

### 3.6 Collaborative prove and MAC-checked open

`MultiproverPlonkKzgSnark::prove` runs the TurboPlonk rounds with
every wire an SPDZ share; the result opens to a STANDARD single-prover
PLONK proof (769 B compressed). The open is `open_authenticated`: every
revealed proof element is MAC-checked. Each party then verifies the
opened proof locally before releasing it to its host.

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

Publics (5): `[cmp, locked_a, locked_b, price, a_is_seller]`.
Private (per side, supplied by its owner): `q` as 64 LE bits, `r_locked`.
`price` and `a_is_seller` are PUBLIC wires the chain builds from the
order rows, so neither is re-range-checked in-circuit.

| # | Constraint | Purpose | gates |
|---|---|---|---|
| 1 | booleanity of all 128 amount bits | [RANGE] for both quantities | 128 |
| 2 | `q_a = Σ bits·2^i`, `q_b = Σ bits·2^i` | recomposition | 44 |
| 3 | `needed_a = q_a·price + s_a·(q_a − q_a·price)`; [OPEN(locked_a; needed_a, r_a)] | the compared value backs the on-chain collateral (input legitimacy) | 477 |
| 4 | same for B with `s_b = 1 − s_a` | B is always the opposite side | 476 |
| 5 | MSB-first scan, per bit: `m = a_i·b_i`; `xnor = 1 − a_i − b_i + 2m`; `lt += eq_prefix·(b_i − m)`; `eq_prefix ·= xnor` | strict-less and equal flags | 384 |
| 6 | `gt = 1 − lt − eq`; `cmp === gt − lt` | the public claim is exactly `sign(q_a − q_b)` | 3 |

Measured total: 7 (allocation) + 1 512 = **1 519 gates**, padded to
**2 048** by finalization. The Groth16 twin (`settle_cozk.circom`)
proves the identical statement with `LessThan(64)` comparators —
measured **748 non-linear R1CS constraints** (ranges 128, the two
collateral opens 245 each, the comparison 130); the chain accepts either.

### 4.2 `settle_small` — π_A, the fully filled side (Groth16)

Publics (6): `[locked, price, side, pay_asset, cm_note_out, bind]`.
Private: `q, r_locked, npk_ctr, r_note`.

| # | Constraint | Purpose | constraints |
|---|---|---|---|
| 1 | `side·(1 − side) === 0` | side flag is boolean | 1 |
| 2 | [RANGE(q)], [RANGE(price)] | both factors of the collateral product are 64-bit, so it is integer-exact | 128 |
| 3 | `needed = q·price + side·(q − q·price)`; [OPEN(locked; needed, r_locked)] | the collateral value is not a witness: the opening pins it — and, being injective in `q`, pins the quantity too | 245 |
| 4 | `NoteCommit(npk_ctr, pay_asset, needed, r_note) === cm_note_out` | the WHOLE collateral becomes the counterparty's payout note (its fresh `npk, r` arrive over the settlement channel) | 1 036 |
| 5 | [BIND] over `(chain_id, "settle_small", order_id, match_order_id, cm_note_out)` | anti-replay weld | 1 |

Measured total: **1 411 non-linear R1CS constraints**. (One `Poseidon(2)`
is 240; `NoteCommit` = 4 chained hashes + its internal `Num2Bits(64)` =
1 036.)

Note the deliberate asymmetry: π_A does NOT self-prove `q ≤ q_ctr`.
The chain's recorded `cmp` decides which circuit each side may use
(F3; [paper_deviations.md](paper_deviations.md) D15).

### 4.3 `settle_large` — π_B, the surviving side (Groth16)

Publics (8): `[locked, locked_ctr, price, side, cm_locked_residual,
pay_asset, cm_note_out, bind]`. Private: `q, r_locked, q_ctr,
r_locked_ctr, r_locked_res, npk_ctr, r_note`.

| # | Constraint | Purpose | constraints |
|---|---|---|---|
| 1 | `side·(1 − side) === 0` | boolean side flag | 1 |
| 2 | [RANGE(q)], [RANGE(q_ctr)], [RANGE(price)] | every factor of every product is 64-bit | 192 |
| 3 | `needed = q·price + side·(q − q·price)`; [OPEN(locked; needed, r_locked)] | own collateral opens | 245 |
| 4 | `needed_ctr = needed(q_ctr, 1 − side)`; [OPEN(locked_ctr; needed_ctr, r_locked_ctr)] | the REVEALED opening must match the COUNTERPARTY's on-chain collateral — the fill cannot be understated (paper clause (ii)) | 245 |
| 5 | `q_res = q − q_ctr`; [RANGE(q_res)] | the 64-bit range of the difference IS the `q ≥ q_ctr` proof (a wrap-around would exceed 64 bits) | 64 |
| 6 | `locked_res = needed(q_res, side)`; [OPEN(cm_locked_residual; locked_res, r_locked_res)] | residual collateral re-committed under a fresh blinding — the ONLY re-commitment the relisted order carries | 245 |
| 7 | `fill = needed − locked_res`; `NoteCommit(npk_ctr, pay_asset, fill, r_note) === cm_note_out` | exactly the filled value moves to the counterparty | 1 036 |
| 8 | [BIND] over `(chain_id, "settle_large", order_id, match_order_id, cm_locked_residual, cm_note_out)` | anti-replay weld | 1 |

Measured total: **2 029 non-linear R1CS constraints**.

## 5. What the chain verifies, writing by writing

**`SubmitCompareCoZk2p`** — pair preconditions (`loadMatchedPair`):
both orders exist, both `Matched`, mutually linked, opposite sides,
order A is the maker, prices valid and EQUAL. Then: both signatures
over the compare message, then π_cmp against the rebuilt statement
`{cmp, orderA.LockedCommitment, orderB.LockedCommitment, price,
orderA.Type == Sell}`. Effect: store `cmp`, both orders → `Settling`.

**`SettlePair`** — both orders `Settling` and mutually linked; a
recorded `cmp` exists and selects each leg's circuit (cmp = 0 → both
π_A, no residuals). Verify BOTH legs (owner signature + Groth16 proof
against publics rebuilt from the ORDER ROWS — never from the request)
before touching state. Then the journaled pipeline: journal row →
idempotent mint of both payout notes in ONE pool mutation → close the
filled side(s) + relist the larger side in place (same id, same block
height, fresh commitments) + journal DONE in one transaction → re-match
+ cleanup. A crash anywhere is completed by resubmission or by the
boot-time recovery.

## 6. Security-ordering summary

| property | how the protocol gets it |
|---|---|
| anchor before disclosure | F1: the reveal of `(q, r_locked)` waits for `Settling` on chain |
| what the counterparty learns | `cmp`, then the smaller side's full opening `(q, r_locked)` |
| fair exchange | F2: one atomic `SettlePair` — both notes or nothing |
| circuit-role gating | F3: the chain's `cmp` decides who may use π_A/π_B |
| abort after learning | the smaller side's opening is known to the larger side once revealed; the `Settling` anchor attributes the abort |
