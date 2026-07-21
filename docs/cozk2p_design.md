# 2-Party Collaborative-ZK Settlement (cozk2p)

A TWO-party variant of the privacy-preserving settlement: the two matched
traders jointly generate the settlement proof with **no helper node**,
matching the application setting exactly (a trade has two counterparties;
introducing a third machine was an artifact of the 3-party protocol).

Lives in the separate [`cozk2p/`](../cozk2p) workspace. The 3-party
co-snarks path ([`lib/cozk`](../lib/cozk), [cozk_design.md](cozk_design.md))
is kept unchanged — the two are alternative provers for the same settlement
statement, and the benchmarks compare them.

## 1. Why 2 parties needs a different stack

Honest-majority MPC (what co-snarks REP3 provides at ~1× single-prover
speed) is meaningless at N=2: tolerating one corruption out of two IS
dishonest majority. A 2-party collaborative prover therefore needs a
SPDZ-style protocol — authenticated shares with MACs and Beaver-triple
preprocessing (Ozdemir–Boneh, USENIX Sec '22, measured this at ~2× a single
prover).

That is exactly what the renegade-fi stack implements, in production, for a
2-party dark pool:

| layer | crate | role |
|---|---|---|
| MPC framework | [`ark-mpc`](https://github.com/invisibook-lab/ark-mpc-1) (fork, pinned) | malicious-secure 2-party SPDZ: authenticated `Scalar` shares + MACs, dataflow `MpcFabric`, QUIC transport |
| collaborative SNARK | [`mpc-jellyfish`](https://github.com/invisibook-lab/mpc-jellyfish) (fork, pinned) | TurboPlonk (KZG, BN254) with an `MpcPlonkCircuit` whose wires are SPDZ shares; proof opens to a **standard single-prover PLONK proof** |

Security: each trader is protected against a fully malicious counterparty —
SPDZ MACs abort on any deviation, and `open_authenticated` MAC-checks the
revealed proof elements. Compare: the 3-party REP3 path is semi-honest and
assumes the helper does not collude with either trader.

## 2. Protocol

Roles: trader A = `PARTY0` (QUIC dialer), trader B = `PARTY1` (listener).
A is the **maker** of the matched pair (deterministic role assignment, as in
the 3-party path).

1. Off-chain, the traders agree on the public statement (execution price,
   the six updated commitments each computes for its own side, `cmp` — see
   below) — over the same channel they already use for settlement
   coordination.
2. Each trader locally bit-decomposes its own amounts and feeds its private
   inputs into the fabric via `share_scalar` (input-mask based: the
   counterparty learns nothing).
3. Both build the identical `MpcPlonkCircuit` over the shared wires; every
   gate's output share is computed by the fabric (witness extension =
   circuit construction).
4. `MultiproverPlonkKzgSnark::prove` runs the PLONK rounds on shares; the
   `CollaborativeProof` is opened with a MAC check into a standard
   `Proof<Bn254>`; each party verifies it locally before release.
5. Both traders sign the settlement message; the pair (public info, proof,
   both signatures) is submitted on-chain — same shape as the 3-party
   request.

`cmp` note: the comparison result is a *public output* of the settlement
(the chain needs it to update the book), so the traders must know it before
building the statement. The repo already has a 2-party MPC comparison phase
on-chain (`CompareOrders`, SPDZ MAC-verified); its result feeds step 1, and
the circuit *re-verifies* `cmp` against the hidden amounts — a mismatched
claim makes the witness unsatisfiable.

## 3. The relation (bits-as-inputs)

Same statement as `settle_cozk.circom` (see [cozk_design.md](cozk_design.md)
§3): open both order commitments, `cmp = sign(a-b) ∈ {-1,0,1}`,
`fill = min(a,b)`, remainders `a' = a-fill`, `b' = b-fill`, collateral
backing at the execution price (equal-price limitation carries over),
updated locked/receive commitments. 15 public signals in the identical
canonical order.

One structural difference, forced by the MPC circuit: `MpcPlonkCircuit` has
no range/comparison/hash gadgets and no way to bit-decompose a *shared*
value. So every amount enters as **64 little-endian bits supplied by the
party that knows the value in plaintext** (bit-decomposition is free on
plaintext), each bit boolean-constrained in-circuit. Downstream everything
is arithmetic on shares:

- value reconstruction: chained linear combinations (also yields the 64-bit
  range check for free);
- comparison: MSB-first equality-prefix scan over the two bit vectors
  (`lt`, `eq`, `gt = 1-lt-eq`, `cmp = gt-lt`) — ~6 gates/bit;
- Poseidon: a hand-written gadget implementing the circom-compatible
  permutation (t=3, 8 full + 57 partial rounds, x^5 S-box — TurboPlonk's
  `q_hash` selector natively supports x^5), constants shared with
  [`lib/mpc`'s cross-checked module](../lib/mpc/src/constants.rs). Golden
  test: the in-crate hash of (0,0) equals the chain's
  `PoseidonZeroCommitmentHex`.

The whole relation is written once against the generic
`mpc_relation::traits::Circuit<F>` trait and instantiated twice: on
`PlonkCircuit<Fr>` (key generation, baselines, satisfiability tests) and on
`MpcPlonkCircuit` (collaborative proving). Trait-default gate methods
compute witness values through the associated `Wire` type, so the MPC
instantiation transparently runs on SPDZ shares.

## 4. Chain verification story

The collaborative proof opens to a **standard jellyfish TurboPlonk proof**
(13 G1 + 10 Fr; 769 B compressed) verifying against a fixed verifying key
with the same 15 public signals the chain already rebuilds for
`SettleOrdersCoZk`. It is *not* snarkjs-Groth16-compatible, so go-rapidsnark
cannot verify it; instead the chain links the `cozk2p` crate as a Rust
`staticlib` over **cgo**:

- `cozk2p/src/ffi.rs` exports `cozk2p_verify_settle(vk, public_json,
  proof)` — vk/proof as ark-compressed bytes, the statement as the same
  `SettlePublic` JSON both traders agreed on (reusing the serde layer keeps
  the Go side free of field-element encodings).
- `chain/core/plonkverify.go` + the `SettleOrdersCoZk2p` writing rebuild
  the statement from on-chain state (`chain/core/orderbook_cozk2p.go`) and
  call the bridge. The signed settlement message is domain-separated from
  the 3-party variant (`invisibook-cozk2p-settle:` prefix).
- The bridge compiles in only with `go build -tags cozk2p` (see
  `make build-chain-cozk2p`), so the default chain build stays pure Go and
  decoupled from the pinned Rust toolchain; without the tag the writing
  rejects PLONK settlements at runtime.
- Artifacts: `chain/vk/settle_cozk2p_vk.bin` (ark-compressed vk, committed)
  and a chain-test fixture, both from `dump_settle2p_fixture`. Layout
  lockstep and accept/reject are pinned by `chain/core/cozk2p_*_test.go`;
  `chain/test/cozk2p_real_proof_test.go` settles a real collaborative proof
  on a running chain end to end (`make test-e2e-cozk2p`).

## 5. Trust caveats (dev/testnet)

> **These two rows are not "reduced security" — they are NO security.** The
> current binaries are strictly a functional demo. Do not deploy against real
> value until both are replaced (see §7).

| concern | status |
|---|---|
| KZG SRS | fixed-seed dev SRS (`setup.rs`, `DEV_SRS_SEED`) — **the toxic tau is publicly recomputable from the committed seed, so anyone can forge a proof that passes `settle_cozk2p_vk.bin` for an arbitrary statement: on-chain soundness is zero.** Needs a ceremony SRS (e.g. a Perpetual Powers of Tau export) for any non-demo use |
| Beaver triples | `PartyIDBeaverSource` mock in demo binaries — **the input masks and proving blinders are predictable constants, so (a) a counterparty reads the other trader's private inputs directly off the shares, and (b) the revealed PLONK proof carries zero zero-knowledge and is published on-chain. Not private even against a semi-honest counterparty.** Production = a real SPDZ offline phase — `ark-mpc-offline` ships LowGear (FHE, C++ MP-SPDZ dep), or an OT-based generator per `CLAUDE.md`'s roadmap could implement `PreprocessingPhase` |
| QUIC TLS | ark-mpc uses a self-signed cert + pass-through verifier: transport encryption without peer authentication; peers authenticate at the application layer (both traders ed25519-sign the settlement message) and SPDZ MACs abort on in-protocol tampering |
| Toolchain | pinned `nightly-2025-02-20` (ark-mpc uses the unstable `inherent_associated_types` feature, which regressed on newer nightlies); `time`/`time-core` held back in the lockfile |
| `price` range | the circuit does not re-range-check `price`; soundness relies on the chain guaranteeing `price < 2^64` (it is a u64 on-chain). All in-circuit products then stay `< 2^128 < r`, i.e. integer-exact |
| Upstream nit | mpc-jellyfish's multiprover drops the MAC-check of the public-input opening feeding the transcript; tampering there is still caught (wrong challenges → local verification fails), i.e. fail-safe but silent |

## 6. Layout

```
cozk2p/
├── rust-toolchain.toml      # nightly-2025-02-20 (see §5)
├── Cargo.toml               # own workspace; forks pinned by rev; [patch] unifies ark-mpc
├── src/
│   ├── constants.rs         # Poseidon ARK/MDS (copy of lib/mpc's cross-checked module)
│   ├── poseidon.rs          # native permutation + commit; golden test vs chain constant
│   ├── gadgets.rs           # bits→field, MSB-scan compare, Poseidon — generic over Circuit<F>
│   ├── relation.rs          # SidePrivate/SettlePublic, compute_public, build_settle_relation
│   ├── setup.rs             # deterministic dev SRS + PK/VK cache
│   ├── prove.rs             # both circuit builders, collaborative + single provers, verify
│   ├── net.rs               # QuicTwoPartyNet helper
│   └── bin/
│       ├── settle2p_party.rs  # one trader over QUIC
│       └── bench_settle2p.rs  # experiments harness
└── tests/settle_2p.rs       # satisfiability, tamper, cmp branches, mock-MPC e2e
```

Results: [cozk_experiments.md](cozk_experiments.md) §"2-party".

## 7. Security status & production checklist

A multi-paper self-audit (Ozdemir–Boneh USENIX'22; eprint 2025/1026;
Liu et al. USENIX'25; zkSaaS; Siniel; PLONK; Poseidon2) surfaced the gaps
below. The 2-party path is a **functional demo**, not a secure deployment,
until the P0 items are closed. Ordered by severity:

- **Malicious-security claim is not yet earned (P0).** SPDZ MACs give
  correct-or-abort on *shares*, not `t`-zero-knowledge. A counterparty may
  input shares that make the joint witness unsatisfiable; the invalid-witness
  proof is then opened to *both* parties before the local `verify_settle`,
  and a proof over an invalid witness is outside the zk-SNARK's ZK guarantee
  (2025/1026, Pitfalls 1–2; the positive "malicious security for free" result
  explicitly does **not** cover the dishonest-majority / 2-party setting).
  *Fix in progress:* an in-MPC witness-validity gate that aborts before any
  proof element is opened (a random linear combination of the relation's
  constraint residuals, opened as a single scalar). Until it lands, describe
  the guarantee as **computational integrity + abort**, not "tolerates a
  fully malicious counterparty".
- **Statement agreement leaks `min(a,b)` pre-proof (P0).** The six updated
  commitments are currently pre-agreed public *inputs*; computing one's own
  side requires knowing `fill = min(a,b)`, so the surviving trader learns the
  counterparty's amount *before* proving and even on a trade that never
  settles. The 3-party path avoids this by computing them as MPC *outputs*
  (`settle_cozk.circom`). *Fix:* compute the six commitments inside the MPC
  and open only the commitments (matching the 3-party statement). Mitigated
  in part, once implemented, by the on-chain confirm→irrevocable→freeze flow
  (matching is size-blind, so the settlement handshake is the only
  pre-settlement amount channel).
- **Dev SRS + mock Beaver = no soundness, no privacy (P0).** See §5. Replace
  with a ceremony SRS and a real SPDZ offline phase.
- **Fail-open verification (P1).** An empty VK path silently skips
  verification. Set `require_proofs = true` in the chain's orderbook config
  to make this a startup error (production nodes should).
- **No abort/timeout handling on-chain (P1).** A Matched pair whose
  counterparty stalls the MPC has no cancel/timeout path; collateral can be
  frozen indefinitely. Intended design: a confirmation step, after which
  settlement is irrevocable and a stalled pair is force-frozen — the
  `Frozen`/`Cancelled` order states exist but are not yet wired.
