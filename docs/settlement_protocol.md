# Settlement Protocol Reference

> **Status:** Current (2026-08-17, note model, branch `cozk-merged-settle`).
> This document is the step-by-step reference for BOTH settlement
> flavors: the **split** flow (production default) and the **merged**
> flow (benchmark twin). It names every step trader A and trader B
> perform, every payload they submit, and every constraint each MPC
> sub-protocol and ZK relation enforces. Component overviews:
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

Each trader starts with: its order opening `(q, r_q)`, its collateral
opening `(locked, r_locked)`, and the chain-read public rows of both
orders. Notation: `P2(x, y)` is the 2-input circom Poseidon over BN254
Fr; `[x]` is an authenticated SPDZ share of `x`; `Com(v, r) = P2(v, r)`.

## 2. The SPLIT protocol

The MPC proves ONLY the comparison (π_cmp). After `cmp` is public and
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
     │ open(P2([q_A],[r_A]) − cm_qA) == 0  (and same for B)      │  binding checks
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
 (7) │◀──────── smaller side reveals (q, r) in plaintext ───────▶│
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
| 2 | input `[q_A], [r_A]` | input `[q_B], [r_B]` | fabric (shares) | `open(P2([q],[r]) − cm_q) == 0` for BOTH orders |
| 3 | run the compare protocol (§4.3) | same | fabric | opened `cmp ∈ {−1,0,1}` |
| 4 | host signs `compare msg(ids, cmp)`; limbs exchanged | same | stdio + fabric | own signature round-trips unchanged |
| 5 | collaborative prove π_cmp | same | fabric | witness-validity gate (§4.5) passes; local verify of the opened proof |
| 6 | either host submits `SubmitCompareCoZk2p`; both BLOCK until both orders are `Settling` | same | chain | the F1 anchor: nothing was revealed yet, so aborting here leaks nothing |
| 7 | (larger) receives the reveal | (smaller) broadcasts `(q, r)` | fabric (plaintext) | `open([q_small] − q) == 0` and same for `r` |
| 8 | derive own payout-note opening `(npk, r_recv)`; write WAL v1; exchange the pairs; write WAL v2 | same | fabric (plaintext) | own pair round-trips unchanged |
| 9 | prove `settle_large` (π_B), sign the leg | prove `settle_small` (π_A), sign the leg | local (rapidsnark) | — |
| 9' | exchange the signed legs | same | fabric (plaintext) | leg roles consistent (one A-leg, one B-leg) |
| 10 | either host submits `SettlePair`; both confirm on chain; persist the payout note (PENDING_MINT) and, for the larger side, the residual order opening | same | chain | small order `Done`; large order relisted `Pending` under its residual commitments |

Who knows what, and when: `cmp` becomes public at step 3 (in-session)
and on-chain at step 6. The smaller side's `(q, r)` reaches ONLY the
larger side, at step 7, strictly after the on-chain anchor. Payout-note
openings are on the RECEIVER's disk (WAL) before the payer ever sees
`(npk, r_recv)`.

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
      "cm_q_residual","cm_locked_residual"}}                      // large leg
```

Each leg carries its OWN owner's signature over a length-prefixed
message: small `["invisibook-settle-small-v1", order_id,
match_order_id, cm_note_out]`; large `["invisibook-settle-large-v1",
order_id, match_order_id, cm_q_residual, cm_locked_residual,
cm_note_out]`. Each leg's Groth16 proof carries a `bind` public input
over the same fields plus the chain id (§5.0).

## 3. The MERGED protocol

ONE collaborative proof covers the comparison AND both settlement
legs. There are no solo settle proofs, no leg exchange, and no reveal
of any quantity before the settlement is FINAL on chain.

### 3.1 Sequence diagram

```
 Trader A (maker, PARTY0)      chain                Trader B (taker, PARTY1)
 ────────────────────────      ─────                ────────────────────────
     │   (rendezvous + QUIC connect: identical to split)         │
     │                                                           │
 (1) │ fingerprint(publics) ◀──────plaintext──────▶ fingerprint  │  abort on mismatch
 (2) │ share [q_A],[r_A],[r_lockedA],[r_qResA],[r_lockedResA],   │
     │       [npk_A],[r_noteA]  ──shares── (B: same 7 values)    │
     │ open(P2([q],[r]) − cm_q) == 0        for BOTH orders      │
     │ open(P2(needed([q]),[r_locked]) − locked) == 0, both sides│  collateral binding
 (3) │ MPC three-way compare ──────────▶ open cmp ∈ {−1,0,1}     │
 (4) │ compute OVER SHARES: fill = min, residuals, recv values,  │
     │ 2 residual-q cms, 2 residual-locked cms, 2 note chains;   │
     │ open the 6 output commitments (hiding — reveal nothing)   │
 (5) │ sign(full 15-signal statement) ◀─sig limbs─▶ sign(...)    │
 (6) │ collaborative prove of the MERGED relation;               │
     │ witness-validity gate; MAC-checked open; local verify     │
     │ WAL v1 (larger side's amounts still unknown)              │
     │                             │                             │
 (7) │ SettlePairCoZk2p{ids, cmp, 6 cms, sig_A, sig_B, proof}    │  either party
     ├────────────────────────────▶│◀────────────(or)────────────┤
     │   chain: verify 2 sigs + ONE proof → mint BOTH notes,     │
     │   small side Done, large side relisted — in one pipeline  │
     │  ...both hosts BLOCK until the settlement is FINAL...     │
     │                             │                             │
 (8) │◀────────── smaller side reveals the FILL value ──────────▶│
     │ open([fill] − fill) == 0                                  │  lying reveal aborts
     │ larger side now knows its payout + residual amounts;      │
     │ WAL v2; both hosts persist                                │
```

### 3.2 Steps, actor by actor

| # | Trader A does | Trader B does | Channel | Check that gates progress |
|---|---|---|---|---|
| 0/R | identical to split (match + rendezvous) | | chain | |
| 1 | fingerprint preamble | same | fabric (plaintext) | equal fingerprints |
| 2 | input 7 shares: `[q_A], [r_A], [r_lockedA], [r_qResA], [r_lockedResA], [npk_A], [r_noteA]` | same 7 for B | fabric (shares) | order binding AND collateral binding zero-opens (4 Poseidon over shares) |
| 3 | compare (§4.3) | same | fabric | `cmp ∈ {−1,0,1}` |
| 4 | jointly compute the 6 output commitments over shares; open them | same | fabric | MAC check on every open |
| 5 | host signs the FULL statement (ids + cmp + 6 output cms) | same | stdio + fabric | own signature round-trips |
| 6 | collaborative prove of the merged relation; local verify; WAL v1 | same | fabric | validity gate (§4.5) before any proof element is revealed |
| 7 | either host submits `SettlePairCoZk2p`; both BLOCK until finality (small side `Done`, large side relisted under the statement's residual cm) | same | chain | the anchor IS the settlement |
| 8 | (larger) learns the fill | (smaller) broadcasts the fill | fabric (plaintext) | `open([fill] − fill) == 0`; WAL v2 |

Who knows what, and when: `cmp` at step 3; the 6 commitments (hiding)
at step 4; the fill — the only value ever revealed — at step 8, strictly
AFTER on-chain finality. The reveal shrinks from split's `(q, r)` to
one integer, and note secrets `(npk, r_note)` never leave their owner.

Griefing caveat: a counterparty that vanishes between step 7 and step
8 leaves the larger side with a minted payout note of unknown amount.
The WAL keeps the session recoverable; the amount can be re-learned
only from the counterparty.

### 3.3 Exact on-chain submission

**`SettlePairCoZk2p`** (either party):

```json
{"order_a_id","order_b_id","cmp",
 "cm_note_out_a","cm_note_out_b",
 "cm_q_residual_a","cm_locked_residual_a",
 "cm_q_residual_b","cm_locked_residual_b",
 "sig_a","sig_b","zk_proof"}
```

All four residual commitments are ALWAYS present (the filled side's
commit to zero); the chain applies only the larger side's pair. Both
signatures cover the SAME length-prefixed message
`["invisibook-settle-pair-cozk2p-v1", order_a_id, order_b_id, cmp,
cm_note_out_a, cm_note_out_b, cm_q_residual_a, cm_locked_residual_a,
cm_q_residual_b, cm_locked_residual_b]`. `zk_proof` is the hex
ark-compressed merged PLONK proof.

## 4. MPC sub-protocols and their checks

All building blocks run on the SPDZ fabric: every share carries an
information-theoretic MAC, every `open_authenticated` MAC-checks the
revealed value, and any deviation aborts the session. Both parties
enqueue fabric operations in identical canonical order (A's values
first) so the dataflow op-ids align.

### 4.1 Statement fingerprint (both flavors, twice)

Each party folds its chain-read public inputs with Poseidon
(`h ← P2(h, x_i)`, seeded with the field count) and broadcasts the
digest in plaintext. Check: the two digests are equal. Run once at
session start and once again inside the prover. Purpose: a stale chain
read fails with a clear error instead of a MAC failure deep inside
proving.

### 4.2 Commitment binding (split: orders; merged: orders + collateral)

For a commitment `cm` with shared opening `[v], [r]`: compute
`P2([v], [r])` over shares (243 Beaver multiplications per hash: the
x^5 S-box costs 3, ARK/MDS are linear) and check
`open(P2([v],[r]) − cm) == 0`. Purpose: a party whose witness does not
open its ON-CHAIN commitment is caught before any expensive phase. In
the merged flavor the collateral check uses
`needed([q]) = [q]` (seller) or `[q]·price` (buyer) — price and side
are public, so the scaling is share-local.

### 4.3 Three-way comparison (`compare_geq` × 2)

For each direction (`a ≥ b`, then `b ≥ a`):

1. `[d] = [v1] − [v2] + 2^64`. Bit 64 of `d` is 1 iff `v1 ≥ v2`
   (inputs are < 2^64, guaranteed by §4.2).
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

### 4.4 Authenticated plaintext exchange (sigs, npk pairs, legs, reveals)

One-directional inputs use `share_plaintext(payload, sender)`: the
sender's value reaches both parties. Two integrity patterns apply:

- **Echo check** (signatures, npk pairs, settle legs): the sender
  compares the broadcast result with what it sent; any transport
  corruption aborts.
- **Share-binding check** (reveals): the revealed plaintext is
  subtracted from the MPC-verified share and the difference is opened:
  `open([x] − x_revealed) == 0`. A lying reveal aborts immediately —
  the revealed value is provably the one the MPC compared and proved.

### 4.5 Witness-validity gate (before ANY proof element is revealed)

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

### 4.6 Collaborative prove and MAC-checked open

`MultiproverPlonkKzgSnark::prove` runs the TurboPlonk rounds with
every wire an SPDZ share; the result opens to a STANDARD single-prover
PLONK proof (769 B compressed). The open is `open_authenticated`: every
revealed proof element is MAC-checked. Each party then verifies the
opened proof locally before releasing it to its host.

## 5. ZK relations: complete constraint lists

### 5.0 Shared notation

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

### 5.1 π_cmp — the compare relation (collaborative PLONK; Groth16 twin `settle_cozk.circom`)

Publics (3): `[cmp, cm_q_a, cm_q_b]`.
Private (per side, supplied by its owner): `q` as 64 LE bits, `r_q`.

| # | Constraint | Purpose | gates |
|---|---|---|---|
| 1 | booleanity of all 128 amount bits | [RANGE] for both quantities | 128 |
| 2 | `q_a = Σ bits·2^i`, `q_b = Σ bits·2^i` | recomposition | 44 |
| 3 | [OPEN(cm_q_a; q_a, r_a)] | compared value = the on-chain commitment (input legitimacy) | 472 |
| 4 | [OPEN(cm_q_b; q_b, r_b)] | same for B | 472 |
| 5 | MSB-first scan, per bit: `m = a_i·b_i`; `xnor = 1 − a_i − b_i + 2m`; `lt += eq_prefix·(b_i − m)`; `eq_prefix ·= xnor` | strict-less and equal flags | 384 |
| 6 | `gt = 1 − lt − eq`; `cmp === gt − lt` | the public claim is exactly `sign(q_a − q_b)` | 3 |

Measured total: 5 (allocation) + 1 503 = **1 508 gates**, padded to
**2 048** by finalization. The Groth16 twin (`settle_cozk.circom`)
proves the identical statement with `LessThan(64)` comparators —
measured **744 non-linear R1CS constraints** (ranges 128, the two opens
243 each, the comparison 130); the chain accepts either.

### 5.2 `settle_small` — π_A, the fully filled side (Groth16)

Publics (8): `[cm_q, locked_0, locked_1, price, side, pay_asset,
cm_note_out, bind]`. Private: `q, r_q, locked_v[2], locked_r[2],
npk_ctr, r_note`.

| # | Constraint | Purpose | constraints |
|---|---|---|---|
| 1 | `side·(1 − side) === 0` | side flag is boolean | 1 |
| 2 | [RANGE(q)], [OPEN(cm_q; q, r_q)] | own quantity opens the on-chain commitment | 307 |
| 3 | [RANGE(locked_v[i])], [OPEN(locked_i; locked_v[i], locked_r[i])] for i = 0, 1 | both collateral slots open (slot 1 is the `P2(0,0)` pad) | 614 |
| 4 | [RANGE(price)]; `locked_v[0] + locked_v[1] === q·price + side·(q − q·price)` | the collateral equals the FULL executed value at the execution price | 66 |
| 5 | `NoteCommit(npk_ctr, pay_asset, locked_sum, r_note) === cm_note_out` | the WHOLE collateral becomes the counterparty's payout note (its fresh `npk, r` arrive over the settlement channel) | 1 036 |
| 6 | [BIND] over `(chain_id, "settle_small", order_id, match_order_id, cm_note_out)` | anti-replay weld | 1 |

Measured total: **2 025 non-linear R1CS constraints**. (One `Poseidon(2)`
is 243; `NoteCommit` = 4 chained hashes + its internal `Num2Bits(64)` =
1 036.)

Note the deliberate asymmetry: π_A does NOT self-prove `q ≤ q_ctr`.
The chain's recorded `cmp` decides which circuit each side may use
(F3; [paper_deviations.md](paper_deviations.md) D15).

### 5.3 `settle_large` — π_B, the surviving side (Groth16)

Publics (11): `[cm_q, cm_q_ctr, locked_0, locked_1, price, side,
cm_q_residual, cm_locked_residual, pay_asset, cm_note_out, bind]`.
Private: `q, r_q, q_ctr, r_q_ctr, locked_v[2], locked_r[2],
r_q_residual, r_locked_residual, npk_ctr, r_note`.

| # | Constraint | Purpose | constraints |
|---|---|---|---|
| 1 | `side·(1 − side) === 0` | boolean side flag | 1 |
| 2 | [RANGE(q)], [RANGE(q_ctr)] | 64-bit ranges of both quantities | 128 |
| 3 | [OPEN(cm_q; q, r_q)], [OPEN(cm_q_ctr; q_ctr, r_q_ctr)] | own opening, and the REVEALED opening must match the COUNTERPARTY's on-chain commitment — the fill cannot be understated | 486 |
| 4 | `q_res = q − q_ctr`; [RANGE(q_res)]; [OPEN(cm_q_residual; q_res, r_q_residual)] | the 64-bit range of the difference IS the `q ≥ q_ctr` proof (a wrap-around would exceed 64 bits); residual re-committed under a fresh blinding | 307 |
| 5 | [RANGE(locked_v[i])], [OPEN(locked_i; ...)] for i = 0, 1 | collateral slots open | 614 |
| 6 | [RANGE(price)]; `locked_sum === q·price + side·(q − q·price)` | admission-time collateral equation | 66 |
| 7 | `locked_res = q_res·price + side·(q_res − q_res·price)`; [OPEN(cm_locked_residual; locked_res, r_locked_residual)] | residual collateral re-committed | 245 |
| 8 | `fill = locked_sum − locked_res`; `NoteCommit(npk_ctr, pay_asset, fill, r_note) === cm_note_out` | exactly the filled value moves to the counterparty | 1 036 |
| 9 | [BIND] over `(chain_id, "settle_large", order_id, match_order_id, cm_q_residual, cm_locked_residual, cm_note_out)` | anti-replay weld | 1 |

Measured total: **2 884 non-linear R1CS constraints**.

### 5.4 The merged relation (collaborative PLONK, `relation_pair.rs`)

Publics (15): `[cmp, cm_note_out_a, cm_note_out_b, cm_q_res_a,
cm_locked_res_a, cm_q_res_b, cm_locked_res_b, cm_q_a, cm_q_b,
locked_a, locked_b, price, a_is_seller, asset_recv_a, asset_recv_b]`.
Private per side (owner-supplied): `q` as 64 LE bits, `r_q`,
`r_locked`, `r_q_res`, `r_locked_res`, `npk` (own receiving key),
`r_note`. Extra: 64 price bits supplied by A.

| # | Constraint | Purpose | gates |
|---|---|---|---|
| 1 | booleanity of `q_a`, `q_b`, and price bits (3×64); `a_is_seller` boolean | [RANGE] for every multiplied value | 193 |
| 2 | recompositions; `Σ price_bits·2^i === price` (public wire) | A cannot supply wrong price bits | 67 |
| 3 | [OPEN(cm_q_a; q_a, r_q_a)], [OPEN(cm_q_b; q_b, r_q_b)] | both on-chain order commitments open | 944 |
| 4 | `needed_x = q_x·price + s_x·(q_x − q_x·price)` with `s_a = a_is_seller`, `s_b = 1 − s_a`; [OPEN(locked_x; needed_x, r_locked_x)] | the collateral value is NOT a witness: collision resistance pins it to the amount `send_order` range-checked at admission — which also bounds every derived product below 2^64 | 953 |
| 5 | MSB-first scan on the bit vectors (as §5.1); `cmp === gt − lt` | public comparison claim | 387 |
| 6 | `fill = q_b + lt·(q_a − q_b)` | `fill = min(q_a, q_b)` | 5 |
| 7 | `q_res_x = q_x − fill`; [OPEN(cm_q_res_x; q_res_x, r_q_res_x)] for both sides | residual quantities (the filled side commits 0) | 944 |
| 8 | `locked_res_x = needed(q_res_x, s_x)`; [OPEN(cm_locked_res_x; locked_res_x, r_locked_res_x)] | residual collateral, both sides | 952 |
| 9 | `fill_t2 = fill·price`; `recv_a = fill + s_a·(fill_t2 − fill)`; `recv_b = fill + s_b·(fill_t2 − fill)` | the seller receives the token2 leg, the buyer the token1 leg | 6 |
| 10 | `NoteCommit(npk_a, asset_recv_a, recv_a, r_note_a) === cm_note_out_a`; same for B | both payout notes, minted from the joint statement | 3 771 |

Measured total: 17 (allocation) + 8 222 = **8 239 gates**, padded to
**16 384** by finalization (16 Poseidon gadgets at 471/472 gates each
dominate). No [BIND]: the dual signatures over the full statement
(§3.3) are the anti-replay weld. Range safety of the
derived values (`fill_t2`, `locked_res`) follows from constraint 4 —
they are all bounded by the opened admission-time collateral.

## 6. What the chain verifies, writing by writing

**`SubmitCompareCoZk2p`** — pair preconditions (`loadMatchedPair`):
both orders exist, both `Matched`, mutually linked, opposite sides,
order A is the maker, prices valid and EQUAL. Then: both signatures
over the compare message, then π_cmp against the rebuilt statement
`{cmp, order_a.Amount, order_b.Amount}`. Effect: store `cmp`, both
orders → `Settling`.

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

**`SettlePairCoZk2p`** — canonical-form checks on the six
request-carried commitments; the SAME pair preconditions as the
compare writing (the pair is still `Matched`); both signatures over
the merged message; ONE PLONK proof against the 15-signal statement
(signals 0–6 from the request, 7–14 rebuilt from the order rows). Then
the SAME journaled pipeline as `SettlePair`, with `cmp` taken from the
proven statement instead of a recorded row.

## 7. Security-ordering summary

| property | split | merged |
|---|---|---|
| anchor before disclosure | F1: the reveal of `(q, r)` waits for `Settling` on chain | the anchor IS the final settlement; the fill reveal waits for finality |
| what the counterparty learns | `cmp`, then the smaller side's full opening `(q, r)` | `cmp`, then (larger side only) the fill value |
| fair exchange | F2: one atomic `SettlePair` — both notes or nothing | same pipeline, one writing |
| circuit-role gating | F3: the chain's `cmp` decides who may use π_A/π_B | not needed — one relation proves both legs and the comparison consistently |
| abort after learning | smaller's opening is known to the larger side once revealed; the `Settling` anchor attributes the abort | nothing to abort into: the trade is already final before anyone learns anything |
