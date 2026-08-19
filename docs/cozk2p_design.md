# 2-Party Collaborative-ZK Settlement (cozk2p)

> **Status:** Current (2026-08-19, crossing prices + encrypted reveal +
> owner-bound native proof shares). For every place this design differs from the paper, see
> [paper_deviations.md](paper_deviations.md). The 3-party co-snarks
> experiment it replaced lives only in git history (branch
> `cozk-settlement`).

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
| MPC framework | [`ark-mpc`](https://github.com/invisibook-lab/ark-mpc-1) (fork, pinned) | 2-party SPDZ protocol machinery: authenticated `Scalar` shares + MACs, dataflow `MpcFabric`, QUIC transport; the configured `PartyIDBeaverSource` is non-production (§5) |
| collaborative SNARK | [`mpc-jellyfish`](https://github.com/invisibook-lab/mpc-jellyfish) (fork, pinned) | TurboPlonk (KZG, BN254) with an `MpcPlonkCircuit` whose wires are SPDZ shares; Fiat–Shamir opens the common transcript components, while the two final KZG G1 points remain additively shared until the chain reconstructs them |

SPDZ MACs abort on checked in-protocol deviations, and
`open_authenticated` MAC-checks the proof components deliberately revealed
for the Fiat–Shamir transcript. The two final point values are not opened
between the traders: each session exports only its local SPDZ value share.
Their MAC shares remain inside the MPC process and are not sent to the chain;
the reconstructed standard proof is accepted only if the chain's PLONK
verification succeeds.

## 2. The session protocol (`session.rs`)

Roles: trader A = maker = `PARTY0` (QUIC dialer), trader B = taker =
`PARTY1` (listener) — deterministic from the matched pair (block
height, intra-block index, then order id). Both parties run the identical program over
one `MpcFabric`; the host app drives the `settle2p_session` subprocess
over stdio ([app_design.md](app_design.md) §4.2).

1. **Preamble.** Exchange a Poseidon fingerprint of the chain-sourced
   statement (the two collateral commitments, both own prices, execution
   price, side). Divergent
   chain reads abort before any secret flows.
2. **Bind.** Share both quantities and collateral blindings into the
   fabric; compute each side's `needed(q, side)` on shares (the side
   flags and each order's own price are public, so the scaling is share-local) and
   verify it opens that side's ON-CHAIN collateral commitment inside
   the MPC (Poseidon on shares). The collateral commitment is the
   order's ONLY commitment — there is no separate quantity commitment.
3. **Compare.** Three-way comparison over shares; only
   `cmp = sign(q_A − q_B)` is opened.
4. **Sign + prove.** The hosts' ed25519 signatures over
   `(order_a, order_b, cmp)` are ferried in and exchanged; the
   collaborative prove of π_cmp runs. Both sessions materialize the same
   canonical template from the components already disclosed to the
   Fiat–Shamir transcript. The two final KZG opening points are NOT opened;
   each session places only its own native additive G1 value share in the
   payload's two final-point slots. Neither trader constructs or locally
   verifies a complete standard proof.
5. **On-chain proof-share gate.** Each host submits only its owner's
   identity/round/deadline-bound canonical share payload. Rust checks the two
   common templates are identical (they are neither re-shared nor added), group-adds
   only the two pairs of final G1 value shares, constructs the standard proof,
   and PLONK-verifies π_cmp. The session BLOCKS until
   both orders are `Settling`; **the reveal never precedes that on-chain
   verification.** The comparison-share deadline is the current round's
   `MatchHeight + 10`; original `BlockHeight` remains only a matching-priority
   field. An incomplete comparison round releases both orders without a
   privacy penalty. Successful verification also creates the settlement-leg
   round with absolute deadline `verification_height + 10`.
6. **Pre-reveal payout-note keys.** Each side derives its incoming note's
   opening and writes its own `(npk, r)` to `payout_keys.json` before
   publishing it. The pairs are exchanged, and each side updates its WAL with
   the peer pair. Both complete local WALs are durable before reveal.
7. **Encrypted reveal.** The smaller party sends `(q, r_locked)` under a
   chain-authenticated per-round X25519/ChaCha20-Poly1305 channel. The receiver
   checks the plaintext locally against the comparison-proof-bound collateral
   commitment. From successful disclosure onward, neither side needs another
   peer message or MPC operation to finish its witness and proof.
8. **Independent settle-leg submission.** Each side completes its
   `witness.json` locally; the host proves ITS settle
   circuit (rapidsnark, outside the subprocess) and immediately submits
   the owner-bound leg within the already-open settlement window. The second
   valid leg triggers atomic execution. At expiry, zero legs mean pre-reveal
   failure and release both owners without blame. For `cmp != 0`, a lone
   valid large-side leg proves its owner knew the smaller opening, so its
   owner is released and the missing small owner is frozen. A lone small-side
   leg does not prove that `q` reached the large owner. Only-small, zero-leg,
   and every incomplete `cmp = 0` round therefore release both without blame.
   This is deliberately asymmetric and conservative against false blame; it
   does not make the overall protocol Byzantine-safe (§7 limitations).

Phase timings are recorded per session (`stats.json`): the MPC/prove
phases separately from the host/chain waits (`compare_onchain_wait_ms`;
the legacy `leg_exchange_ms` field is zero), so chain latency never contaminates the
cryptographic numbers.

## 3. The relation (compare-only, 6 publics)

π_cmp proves exactly (with `needed(q, p, s) = q·p + s·(q − q·p)`
and `s_B = 1 − s_A`):

```
P2(needed(q_A, price_A, s_A), r_A) = locked_A
P2(needed(q_B, price_B, s_B), r_B) = locked_B
cmp = sign(q_A − q_B) ∈ {−1, 0, 1}
```

Publics: `[cmp, locked_a, locked_b, price_a, price_b, a_is_seller]` — the same
6-signal statement as the Groth16 twin `settle_cozk.circom`. In the
locked-only model an order commits ONLY its collateral, so the
compared quantities are pinned by opening each collateral against its
in-circuit `needed` (input legitimacy); both prices and `a_is_seller`
therefore enter the statement (the equation is injective in `q` for
the corresponding price is positive — see
[paper_deviations.md](paper_deviations.md) D17).

`MpcPlonkCircuit` has no gadget library and cannot bit-decompose a
shared value, so each quantity enters as 64 little-endian bits supplied
by its owner (boolean-constrained in-circuit — the PLONK mirror of the
circom twin's `Num2Bits(64)` range check). Both prices and `a_is_seller` are
PUBLIC wires and are used as they are: the chain builds them from the
order rows (u64 prices and a 0-1 flag), a prover cannot lie about a public
input, so neither is re-checked in-circuit (88 constraints saved).
Comparison is an MSB-first equality-prefix scan; Poseidon is a
hand-written gadget matching the circom permutation (t=3, 8 full +
57 partial rounds, x^5 S-box), golden-tested against `Poseidon(0,0)`.
The relation is written once against the
generic `Circuit<F>` trait and instantiated on both `PlonkCircuit<Fr>`
(keygen, tests) and `MpcPlonkCircuit` (collaborative proving).
Circuit size: 2048 gates; proof 769 B compressed.

## 4. Chain verification

Only the chain-side Rust bridge constructs the standard jellyfish
TurboPlonk proof. It is not snarkjs-compatible, so the chain links the
`cozk2p` crate as a Rust staticlib over cgo:

- `cozk2p/src/ffi.rs` exports
  `cozk2p_verify_settle_shares(vk, public_json, share_a, share_b)` for the
  production comparison path. It canonically decodes and party-checks both
  payloads, requires equality of every already-public common component,
  group-adds only `opening_proof` and `shifted_opening_proof`, constructs a
  standard proof, and verifies it. The legacy complete-proof verifier remains
  an internal test/helper entry.
- `chain/core/plonkverify.go` + the `SubmitCompareCoZk2pShare` writings
  rebuild the 6-signal statement from the order rows (collateral
  commitments, each order's own public price, order A's side) and call the bridge.
  Each share signature is domain-separated and binds chain, owner, pair,
  match round, `cmp`, the round's `MatchHeight + 10` deadline, and the share
  digest. Successful verification creates the separate settlement-leg
  deadline before payout-key exchange/reveal begins.
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
| Beaver triples | `PartyIDBeaverSource` mock — masks are predictable constants, so **a counterparty reads the other trader's inputs off the shares** and the collaborative proof protocol provides no input privacy or zero-knowledge guarantee. This is non-production test infrastructure and must be replaced by a real SPDZ offline phase (LowGear or an OT-based generator) |
| QUIC TLS | self-signed cert + pass-through verifier; settlement reveal confidentiality/authentication is supplied separately by signed per-round X25519 keys and ChaCha20-Poly1305, while SPDZ MACs protect shared computation |
| Rendezvous | peer addresses exchanged in plaintext on chain (`RegisterSettleAddr`) — production needs an anonymous overlay ([paper_deviations.md](paper_deviations.md) D9) |
| Toolchain | pinned `nightly-2025-02-20` (ark-mpc needs the unstable `inherent_associated_types` feature); `time`/`time-core` held back |
| `price` range | the circuits do not re-range-check `price`; the chain guarantees `price < 2^64` at admission |
| Upstream nit | mpc-jellyfish drops the MAC-check of the public-input opening feeding the transcript; a resulting inconsistent proof still fails the chain's final PLONK verification, but the missing early diagnostic should be fixed upstream |

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
│   ├── session.rs             # THE session (§2): compare → payout-key WAL → reveal
│   ├── setup.rs               # dev SRS + PK/VK cache
│   ├── prove.rs               # circuit builders, collaborative + single provers
│   ├── proof_share.rs         # canonical native-share wire + chain-side reconstruction
│   ├── net.rs                 # QUIC connect with spawn-order tolerance
│   ├── ffi.rs                 # cgo verifier export (§4)
│   ├── stats.rs               # peak-RSS helper
│   └── bin/
│       ├── settle2p_session.rs    # the subprocess the app spawns (stdio protocol)
│       ├── settle2p_party.rs      # bare one-trader prover (no session)
│       ├── dump_settle2p_fixture.rs  # chain VK + Go-test fixture
│       └── bench_settle2p.rs      # benchmark harness
└── tests/
    ├── session_2p.rs          # happy path, abort-before-reveal, exchange primitives
    ├── settle_2p.rs           # relation satisfiability, tamper, cmp branches
    └── gate_census.rs         # measured per-step gate table of the relation
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
- **Partial — atomic pair execution; payout authorization open (P0).** Each
  owner submits only its own leg, and the internal executor mints both payout
  notes together or not at all. However, payout-key pairs are neither
  owner-signed nor committed on chain, and the private `npk_ctr, r_note`
  witness is not publicly bound to the peer's pre-reveal choice. A malicious
  payer can redirect its payout while producing a valid settle proof. Until
  owner-signed pre-reveal payout-key commitments are public inputs of both
  settle circuits and checked by the chain, the end-to-end claim is only
  compliant-until-fail-stop.
- **Open — dev SRS + mock Beaver (P0).** §5. No soundness, no privacy
  until replaced.
- **Open — malicious-security wording (P0).** SPDZ MACs give
  correct-or-abort on shares, not `t`-zero-knowledge over an invalid
  joint witness (eprint 2025/1026, Pitfalls 1–2). Until an in-MPC
  witness-validity gate lands, describe the guarantee as
  **computational integrity + abort**.
- **Partial — abort/timeout economics (P2).** The comparison deadline is
  round-bound at `MatchHeight + 10`. Comparison verification opens a second
  absolute deadline before payout-key exchange/reveal: zero legs at expiry
  release both without blame. After a non-equal comparison, only a lone
  large-side leg proves knowledge of the smaller opening and freezes the
  missing small owner. A lone small-side leg is not objective delivery
  evidence, so only-small and incomplete `cmp = 0` rounds release both.
  Fully Byzantine **symmetric** attribution still needs verifiable encrypted
  reveal (a withholdable signed receipt is insufficient), and the paper's
  automatic unfreeze remains open.
- **Open — fail-open verification (P1).** An empty VK path skips
  verification; set `require_proofs = true` on production nodes.
