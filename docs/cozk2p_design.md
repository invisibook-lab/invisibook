# 2-Party Collaborative-ZK Settlement (cozk2p)

> **Status:** Current (2026-08-17, locked-only model + two-phase
> session). For every place this design differs from the paper, see
> [paper_deviations.md](paper_deviations.md). The 3-party co-snarks
> experiment it replaced is described in
> [cozk_design.md](cozk_design.md) (historical).

The two matched traders jointly prove the quantity comparison with
**no helper node** — the exact application setting (a trade has two
counterparties). The MPC's ONLY job is the comparison proof π_cmp;
everything after `cmp` is public arithmetic each side proves alone with
the single-prover settle circuits ([zk_design.md](zk_design.md) §4.3).

Lives in the separate [`cozk2p/`](../cozk2p) workspace (own toolchain
pin, see §5).

## 1. Why 2 parties needs a different stack

Honest-majority MPC (REP3 at ~1× single-prover speed) is meaningless at
N=2: tolerating one corruption out of two IS dishonest majority. A
2-party collaborative prover needs a SPDZ-style protocol —
authenticated shares with MACs and Beaver-triple preprocessing
(Ozdemir–Boneh, USENIX Sec '22). That is what the renegade-fi stack
implements in production for a 2-party dark pool:

| layer | crate | role |
|---|---|---|
| MPC framework | [`ark-mpc`](https://github.com/invisibook-lab/ark-mpc-1) (fork, pinned) | malicious-secure 2-party SPDZ: authenticated `Scalar` shares + MACs, dataflow `MpcFabric`, QUIC transport |
| collaborative SNARK | [`mpc-jellyfish`](https://github.com/invisibook-lab/mpc-jellyfish) (fork, pinned) | TurboPlonk (KZG, BN254) with an `MpcPlonkCircuit` whose wires are SPDZ shares; the proof opens to a **standard single-prover PLONK proof** |

SPDZ MACs abort on any in-protocol deviation, and `open_authenticated`
MAC-checks every revealed value, including the proof itself.

## 2. The session protocol (`session.rs`)

Roles: trader A = maker = `PARTY0` (QUIC dialer), trader B = taker =
`PARTY1` (listener) — deterministic from the matched pair (block
height, tie → order id). Both parties run the identical program over
one `MpcFabric`; the host app drives the `settle2p_session` subprocess
over stdio ([app_design.md](app_design.md) §4.2).

1. **Preamble.** Exchange a Poseidon fingerprint of the chain-sourced
   statement (the two collateral commitments, price, side). Divergent
   chain reads abort before any secret flows.
2. **Bind.** Share both quantities and collateral blindings into the
   fabric; compute each side's `needed(q, side)` on shares (the side
   flags and price are public, so the scaling is share-local) and
   verify it opens that side's ON-CHAIN collateral commitment inside
   the MPC (Poseidon on shares). The collateral commitment is the
   order's ONLY commitment — there is no separate quantity commitment.
3. **Compare.** Three-way comparison over shares; only
   `cmp = sign(q_A − q_B)` is opened.
4. **Sign + prove.** The hosts' ed25519 signatures over
   `(order_a, order_b, cmp)` are ferried in and exchanged; the
   collaborative prove of π_cmp runs; the opened proof is verified
   locally before release.
5. **On-chain anchor (F1 gate).** The session hands
   `{cmp, π_cmp, sig_A, sig_B}` to the host
   (`confirm_compare_onchain`) and BLOCKS until the host confirms both
   orders are `Settling` on chain. Abort here leaks nothing and leaves
   no trace. **The reveal never precedes this anchor.**
6. **Reveal.** The smaller party reveals `(q, r_locked)` in plaintext;
   both sides open `share − revealed` and require zero, so a lying
   reveal aborts instantly. The larger side now holds its complete
   `settle_large` witness.
7. **Payout-note keys.** Each side derives its incoming note's opening,
   writes it to the `witness.json` WAL BEFORE the `(npk, r)` pair
   leaves the process, then the two pairs are exchanged.
8. **Settle-leg exchange.** The host proves ITS settle circuit
   (rapidsnark, outside the subprocess) and hands the signed leg back;
   the fabric exchanges the two legs, so **either** party can submit
   the atomic `SettlePair` (F2).

Phase timings are recorded per session (`stats.json`): the MPC/prove
phases separately from the host/chain waits (`compare_onchain_wait_ms`,
`leg_exchange_ms`), so chain latency never contaminates the
cryptographic numbers.

## 3. The relation (compare-only, 5 publics)

π_cmp proves exactly (with `needed(q, s) = q·price + s·(q − q·price)`
and `s_B = 1 − s_A`):

```
P2(needed(q_A, s_A), r_A) = locked_A
P2(needed(q_B, s_B), r_B) = locked_B
cmp = sign(q_A − q_B) ∈ {−1, 0, 1}
```

Publics: `[cmp, locked_a, locked_b, price, a_is_seller]` — the same
5-signal statement as the Groth16 twin `settle_cozk.circom`. In the
locked-only model an order commits ONLY its collateral, so the
compared quantities are pinned by opening each collateral against its
in-circuit `needed` (input legitimacy); `price` and `a_is_seller`
therefore enter the statement (the equation is injective in `q` for
`price > 0` — see [paper_deviations.md](paper_deviations.md) D17).

`MpcPlonkCircuit` has no gadget library and cannot bit-decompose a
shared value, so each quantity enters as 64 little-endian bits supplied
by its owner (boolean-constrained in-circuit — the PLONK mirror of the
circom twin's `Num2Bits(64)` range check). `price` and `a_is_seller` are
PUBLIC wires and are used as they are: the chain builds both from the
order rows (a u64 price, a 0-1 flag), a prover cannot lie about a public
input, so neither is re-checked in-circuit (88 constraints saved).
Comparison is an MSB-first equality-prefix scan; Poseidon is a
hand-written gadget matching the circom permutation (t=3, 8 full +
57 partial rounds, x^5 S-box), golden-tested against `Poseidon(0,0)`.
The relation is written once against the
generic `Circuit<F>` trait and instantiated on both `PlonkCircuit<Fr>`
(keygen, tests) and `MpcPlonkCircuit` (collaborative proving).
Circuit size: 2048 gates; proof 769 B compressed.

## 4. Chain verification

The opened proof is a standard jellyfish TurboPlonk proof and is NOT
snarkjs-compatible, so the chain links the `cozk2p` crate as a Rust
staticlib over cgo:

- `cozk2p/src/ffi.rs` exports `cozk2p_verify_settle(vk, public_json,
  proof)`.
- `chain/core/plonkverify.go` + the `SubmitCompareCoZk2p` writing
  rebuild the 5-signal statement from the order rows (collateral
  commitments, execution price, order A's side) and call the bridge.
  The dual-signed compare message is domain-separated
  (`invisibook-cozk2p-compare-v2`).
- The bridge compiles only with `go build -tags cozk2p`
  (`make build-chain-cozk2p`); without the tag the writing rejects
  PLONK compares at runtime.
- Artifacts: `chain/vk/settle_cozk2p_vk.bin` + the Go-test fixture,
  both from `dump_settle2p_fixture`. Accept/reject and layout lockstep:
  `chain/core/cozk2p_*_test.go`; full-depth e2e:
  `chain/test/cozk2p_real_proof_test.go` (`make test-e2e-cozk2p`).

## 5. Trust caveats (dev/testnet)

> **These rows are not "reduced security" — they are NO security.** The
> current binaries are a functional demo. Do not deploy against real
> value until the P0 rows are replaced.

| concern | status |
|---|---|
| KZG SRS | fixed-seed dev SRS (`setup.rs`) — the toxic tau is publicly recomputable, so **anyone can forge a π_cmp**: on-chain soundness is zero. Needs a ceremony SRS |
| Beaver triples | `PartyIDBeaverSource` mock — masks are predictable constants, so **a counterparty reads the other trader's inputs off the shares** and the opened proof has no zero-knowledge. Needs a real SPDZ offline phase (LowGear or an OT-based generator) |
| QUIC TLS | self-signed cert + pass-through verifier: transport encryption without peer authentication; peers authenticate at the application layer (dual ed25519 signatures) and SPDZ MACs abort on tampering |
| Rendezvous | peer addresses exchanged in plaintext on chain (`RegisterSettleAddr`) — production needs an anonymous overlay ([paper_deviations.md](paper_deviations.md) D9) |
| Toolchain | pinned `nightly-2025-02-20` (ark-mpc needs the unstable `inherent_associated_types` feature); `time`/`time-core` held back |
| `price` range | the circuits do not re-range-check `price`; the chain guarantees `price < 2^64` at admission |
| Upstream nit | mpc-jellyfish drops the MAC-check of the public-input opening feeding the transcript; tampering there still fails local verification (fail-safe but silent) |

## 6. Layout

```
cozk2p/
├── rust-toolchain.toml        # nightly pin (see §5)
├── src/
│   ├── constants.rs           # Poseidon ARK/MDS (golden-tested)
│   ├── poseidon.rs            # native permutation, commit, note_commit
│   ├── gadgets.rs             # bits→field, MSB-scan compare, Poseidon gadget
│   ├── mpc_poseidon.rs        # Poseidon over authenticated shares
│   ├── mpc_compare.rs         # three-way compare over shares
│   ├── relation.rs            # SidePrivate/SettlePublic, build_settle_relation
│   ├── session.rs             # THE session (§2): preamble → … → leg exchange
│   ├── setup.rs               # dev SRS + PK/VK cache
│   ├── prove.rs               # circuit builders, collaborative + single provers
│   ├── net.rs                 # QUIC connect with spawn-order tolerance
│   ├── ffi.rs                 # cgo verifier export (§4)
│   ├── stats.rs               # peak-RSS helper
│   └── bin/
│       ├── settle2p_session.rs    # the subprocess the app spawns (stdio protocol)
│       ├── settle2p_party.rs      # bare one-trader prover (no session)
│       ├── dump_settle2p_fixture.rs  # chain VK + Go-test fixture
│       └── bench_settle2p.rs      # benchmark harness
└── tests/
    ├── session_2p.rs          # happy path, abort-before-reveal (F1), leg exchange
    └── settle_2p.rs           # relation satisfiability, tamper, cmp branches
```

Numbers: [cozk_experiments.md](cozk_experiments.md).

## 7. Security status

The rev.4 review ([settlement_hardening_plan_zh.md](settlement_hardening_plan_zh.md))
re-audited this path. Standing of the previously known gaps:

- **Resolved — reveal-before-anchor (was P0).** The session now blocks
  on the on-chain compare confirmation before any reveal (F1, §2 step
  5). Test: `compare_abort_precedes_any_reveal`.
- **Resolved — pre-proof statement leak (was P0).** The old joint
  15-signal settle statement required pre-agreeing commitments that
  encode `min(a,b)`. The compare-only relation (§3) removed that
  channel: the only pre-anchor disclosure is `cmp` itself
  ([paper_deviations.md](paper_deviations.md) D1 documents the
  remaining 1-trit timing gap vs. the paper).
- **Resolved — settlement fair-exchange (was P1).** The atomic
  `SettlePair` (F2) mints both payout notes together or not at all.
- **Open — dev SRS + mock Beaver (P0).** §5. No soundness, no privacy
  until replaced.
- **Open — malicious-security wording (P0).** SPDZ MACs give
  correct-or-abort on shares, not `t`-zero-knowledge over an invalid
  joint witness (eprint 2025/1026, Pitfalls 1–2). Until an in-MPC
  witness-validity gate lands, describe the guarantee as
  **computational integrity + abort**.
- **Open — abort/timeout economics (P2).** A stalled pair now leaves an
  attributable `Settling` anchor, but the freeze/challenge mechanism of
  the paper's §VI-D is design-only (hardening plan Phase C;
  [paper_deviations.md](paper_deviations.md) D4).
- **Open — fail-open verification (P1).** An empty VK path skips
  verification; set `require_proofs = true` on production nodes.

## 8. The merged path (benchmark twin)

The `cozk-merged-settle` branch adds a SECOND settlement flavor next to
the split flow above. One collaborative TurboPlonk proof covers the
comparison AND both settlement legs — the note-model successor of the
old 15-signal joint statement (see [cozk_design.md](cozk_design.md)).
The split flow stays unchanged; a config switch selects the flavor, so
the two paths give a direct A/B benchmark.

### 8.1 The merged relation (`relation_pair.rs`)

15 public signals (order is normative; the chain rebuilds 7..14 from
its order rows and takes 0..6 from the request):

```
 0 cmp              sign(q_a − q_b) in {−1, 0, 1}
 1 cm_note_out_a    payout note minted TO trader A (B pays it)
 2 cm_note_out_b    payout note minted TO trader B (A pays it)
 3 cm_q_res_a       A's residual quantity commitment (used iff cmp = +1)
 4 cm_locked_res_a  A's residual collateral commitment
 5 cm_q_res_b       B's residual quantity commitment (used iff cmp = −1)
 6 cm_locked_res_b  B's residual collateral commitment
 7 cm_q_a           order A quantity commitment (on chain)
 8 cm_q_b           order B quantity commitment (on chain)
 9 locked_a         order A collateral commitment (on chain)
10 locked_b         order B collateral commitment (on chain)
11 price            execution price (equal-price rule)
12 a_is_seller      1 when A sells token1
13 asset_recv_a     assetID of the token A receives
14 asset_recv_b     assetID of the token B receives
```

Constraints: booleanity + recomposition of `q_a`, `q_b`, and the price
bits; Poseidon opens of both order and both collateral commitments (the
collateral value is not a witness — the circuit computes `needed =
q·price + side·(q − q·price)` and opens the commitment against it); the
MSB-scan comparison; `fill = min(q_a, q_b)`; residual quantity and
collateral commitments for BOTH sides (the filled side commits zero);
and the two payout-note chains `NoteCommit(npk, asset, recv, r)`.
16 Poseidon gadgets; 16 384 gates after padding — inside the existing
`MAX_DEGREE = 32768` SRS. Keys are cached under a separate
`settlepair2p-*` tag.

Range safety: every derived amount is bounded by a 64-bit-checked
input. The buyer-side collateral equation pins `q·price` to the opened
admission-time collateral, so `fill·price` and the residual collateral
stay below 2^64 without extra bit witnesses.

### 8.2 The merged session (`session_pair.rs`)

Same preamble, witness binding, and comparison as §2. Then, INSTEAD of
reveal + solo settle proofs + leg exchange:

1. Compute the six output commitments OVER SHARES (Poseidon on the
   fabric; the fill selection is public once `cmp` is open) and open
   them. Opening a hiding commitment reveals nothing.
2. Ferry ONE signature per trader over the full 15-signal statement
   (domain `invisibook-settle-pair-cozk2p-v1`).
3. Collaboratively prove the merged relation; verify locally.
4. Hand `{cmp, public, proof, sig_a, sig_b}` to the host. The host
   submits `SettlePairCoZk2p` and BLOCKS until the settlement is FINAL.
5. Only after finality does the smaller side reveal the fill (bound to
   the MPC shares — a lying reveal aborts), so the larger side learns
   its payout amount and residual opening.

Privacy delta vs. the split flow: no quantity is revealed to anyone
before the settlement is final, and the reveal shrinks from `(q, r)` to
the fill value alone. The F1 anchor becomes the settlement itself.
Griefing caveat: a counterparty that vanishes after finality but before
the fill reveal leaves the larger side with a minted note of unknown
amount; the WAL keeps the session recoverable, and the amount can be
re-learned only from the counterparty.

### 8.3 Chain writing (`SettlePairCoZk2p`)

Accepts a MATCHED pair directly (no Settling stage). It re-does the
compare-phase preconditions (mutual match, opposite sides, maker = A,
equal prices), verifies both ed25519 signatures and ONE PLONK proof
(`cozk2p_verify_settle_pair` over the same cgo bridge), then reuses the
SettlePair pipeline unchanged: journal → idempotent mint of both payout
notes → close/relist in one transaction → recovery on boot. Config key:
`settle_pair_cozk2p_vk_path`; artifact:
`chain/vk/settle_pair_cozk2p_vk.bin` (`make dump-settlepair2p-fixture`).

### 8.4 Selecting the flavor

- App config: `settle2p_mode = "merged"` (or env
  `INVISIBOOK_SETTLE2P_MODE=merged`); default is `split`.
- Subprocess: `settle2p_session --mode merged`.
- Benchmark: `settle_e2e_relist` (split) vs `settle_e2e_relist_merged`
  (merged), same scenario and assertions; run them one at a time.
