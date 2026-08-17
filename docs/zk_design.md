# ZK Design

> **Status:** Current (2026-08-16, note model). For every place this
> design differs from the paper, see
> [paper_deviations.md](paper_deviations.md).

## 1. Overview

Invisibook never publishes a quantity or a balance. Value lives in a
shielded note pool; orders carry their quantity and collateral as
Poseidon commitments; every writing that touches hidden value carries a
proof:

- **Groth16 (circom + rapidsnark)** for all single-prover circuits —
  pool spends, order admission, per-side settlement, fee claims.
- **Collaborative TurboPlonk (cozk2p)** for the one statement neither
  trader may prove alone: the comparison of the two hidden order
  quantities. See [cozk2p_design.md](cozk2p_design.md).

Toolchain (curve = BN254 throughout): `circom 2.2.x` templates in
[lib/zk/templates/](../lib/zk/templates/); `snarkjs` trusted setup
(dev); `rapidsnark` proving; `go-rapidsnark` verification on chain.
Artifacts cache under `lib/target/circuit-build/<name>/`.

## 2. Note primitives (the frozen spec)

The shielded pool's derivation chain is pinned **byte-for-byte across
three languages** by [spec/golden.json](../spec/golden.json): Go
([chain/core/pool.go](../chain/core/pool.go)), Rust
([lib/chain/src/note.rs](../lib/chain/src/note.rs)), and circom
([lib/zk/templates/note.circom](../lib/zk/templates/note.circom)).
`P2` is the 2-input circomlib Poseidon.

```
nk  = P2(TAG_NK=1,  sk)          npk = P2(TAG_NPK=2, sk)
cm  = P2(P2(P2(P2(TAG_CM=3, npk), assetID), v), r)
rho = P2(P2(TAG_RHO=4, cm), leafIndex)
nf  = P2(P2(TAG_NF=5,  nk), rho)
```

- Tree: depth 20, empty leaf = Fr("invisibook.empty"), append-only;
  every historical root stays a valid anchor.
- Value commitments (`cm_q`, collateral, residuals) use the plain
  `P2(v, r)` shape (`poseidon_commit`).
- Asset ids are the token symbol's bytes as a field element (≤ 31
  bytes, no reduction).
- Change nothing here without regenerating the golden vectors in all
  three languages.

## 3. Conventions shared by every Groth16 circuit

- **`bind` public input** — `SHA-256(domain ‖ chain_id ‖ writing ‖
  version ‖ request fields)` reduced into Fr. Welds a proof to one
  exact request on one chain (replay protection). Go `BindHash` and
  Rust `note::bind_hash` are golden-pinned.
- **64-bit range checks** — every amount in conservation arithmetic
  goes through `Num2Bits(64)`; products with the u64 `price` stay below
  the modulus (the chain rejects prices ≥ 2^64 at admission).
- **2-slot shape** — spend circuits take exactly two input slots; a
  missing input is an Orchard-style dummy (fresh random secrets, zero
  value, membership disabled — its nullifier is an unsteerable PRF
  image). Collateral is `[Order.LockedCommitment, Poseidon(0,0)]`; the
  zero-commitment constant is allowed ONLY as this pad (enforced by the
  grep-gate test
  [lib/chain/tests/model_gate.rs](../lib/chain/tests/model_gate.rs)).
- **Publics order** — the chain rebuilds each public-input vector
  itself; the per-circuit order below is normative.

## 4. Circuit catalog

### 4.1 Pool circuits

**`note_deposit.circom`** — mint one note from a bridged value.
Publics (4): `[bridge_commitment, asset_id, cm_out, bind]`.
Handler: `Account.NoteDeposit` (operator-signature gate until real
bridge proofs land — [paper_deviations.md](paper_deviations.md) D13).

**`spend_withdraw.circom`** — spend 2 slots (Merkle membership +
nullifier correctness), withdraw through the bridge, mint change.
Publics (7): `[anchor, nf_0, nf_1, asset_id, bridge_out_commitment,
cm_change, bind]`. Handler: `Account.NoteWithdraw`.

### 4.2 Order circuits

**`send_order.circom`** — admission with full collateralization: spend
2 note slots, commit the quantity (`cm_q`) and the side-dependent
collateral (`locked_commitment` = `q` sell / `q·price` buy), pay the
plaintext fee, mint the change note. Conservation:
`inputs = collateral + fee + change`.
Publics (11): `[anchor, nf_0, nf_1, lock_asset_id, cm_q,
locked_commitment, fee, cm_change, price, side, bind]`.
Handler: `OrderBook.SendOrder`. Prover:
[`prove_send_order`](../lib/chain/src/note_prover.rs).

**`claim_fees.circom`** — a block producer mints its accrued plaintext
fees as one pool note. Publics (4): `[asset_id, amount, cm_out, bind]`.
Handler: `OrderBook.ClaimFees`.

### 4.3 Settlement circuits (paper π_A / π_B)

**`settle_small.circom`** (π_A, the fully filled side) — opens own
`cm_q` and the 2-slot collateral, checks the collateral equals the
required amount at the execution price, and mints the WHOLE collateral
as the counterparty's payout note (under the counterparty-chosen
`npk`/`r`). Publics (8): `[cm_q, locked_0, locked_1, price, side,
pay_asset, cm_note_out, bind]`.

**`settle_large.circom`** (π_B, the surviving side) — additionally
opens the counterparty's on-chain `cm_q_ctr` with the REVEALED opening
(so the fill cannot be understated), range-proves `q ≥ q_ctr`, pays the
fill as the payout note, and re-commits the residual quantity and
collateral under fresh blindings. Publics (11): `[cm_q, cm_q_ctr,
locked_0, locked_1, price, side, cm_q_residual, cm_locked_residual,
pay_asset, cm_note_out, bind]`.

Asymmetry note: `settle_small` does not self-prove `q ≤ q_ctr`; the
chain's recorded `cmp` gates which circuit each side may use (F3 in the
hardening plan; [paper_deviations.md](paper_deviations.md) D15).

Both legs are verified together by the atomic `SettlePair` writing
(shared `verifySmallLeg`/`verifyLargeLeg` in
[chain/core/orderbook_cozk.go](../chain/core/orderbook_cozk.go)).

### 4.4 Compare gate

**`settle_cozk.circom`** — the single-prover twin of the collaborative
comparison: opens both order commitments and outputs
`cmp = sign(q_A − q_B)`. Publics (3): `[cmp, order_a_commitment,
order_b_commitment]`. Production uses the cozk2p PLONK prover for the
same 3-signal statement; this Groth16 twin serves fixtures, tests, and
the `SubmitCompareCoZk` variant.

## 5. Wallet-side proving

[lib/chain/src/note_prover.rs](../lib/chain/src/note_prover.rs) holds
the witness builders (`SpendSlot` with real/dummy constructors,
`SendOrderWitness`, `SettleSmallWitness`, `SettleLargeWitness`, …) and
rapidsnark drivers. Each builder exposes its output commitments BEFORE
proving so the caller can compute the `bind` and persist openings first
(persist-before-publish). [lib/zk/src/](../lib/zk/src/) keeps the
shared Poseidon helpers (`poseidon_commit`, `poseidon2`), the
snarkjs/rapidsnark subprocess drivers, and the `settle_cozk` fixture
prover.

Warm-key prove times (rapidsnark, mean of 3; full tables in
[cozk_experiments.md](cozk_experiments.md)):

| circuit | prove (ms) |
|---|---|
| note_deposit | 86 |
| spend_withdraw | 185 |
| send_order | 203 |
| settle_small | 90 |
| settle_large | 96 |
| claim_fees | 86 |

## 6. Trust boundaries and known limitations

| Concern | Status |
|---|---|
| Bridge inclusion/release proofs | **TODO** — `NoteDeposit` trusts an operator signature (dev: nothing); `NoteWithdraw`'s bridge-out amount is unbound off-chain |
| Trusted setup | snarkjs single-party dev setup; the cozk2p SRS is a fixed-seed dev SRS. Both need ceremonies before real value |
| Equal-price limitation | settle circuits equate the collateral price with the execution price; cross-price matches cannot settle ([paper_deviations.md](paper_deviations.md) D6) |
| `settle_small` asymmetry | does not self-prove "I am smaller" (F3, open) |
| Android | no on-device proving; order placement is disabled there |

## 7. Layout

```
lib/zk/templates/
├── utils/                 # circomlib primitives
├── note.circom            # note derivation chain (golden-pinned)
├── note_golden.circom     # golden-vector test circuit
├── commitments.circom     # P2 open + range + sum helpers
├── note_deposit.circom    # §4.1
├── spend_withdraw.circom  # §4.1
├── send_order.circom      # §4.2
├── claim_fees.circom      # §4.2
├── settle_small.circom    # §4.3 (π_A)
├── settle_large.circom    # §4.3 (π_B)
└── settle_cozk.circom     # §4.4 (compare twin)

lib/zk/src/       setup.rs prover.rs wallet.rs test_circuit.rs circom_bridge.rs
lib/chain/src/    note.rs note_tree.rs note_prover.rs (witnesses + provers)
chain/core/       zkverify.go plonkverify.go (verification) + vk/ (committed VKs)
spec/golden.json  cross-language golden vectors
```

## 8. Testing

- **Rust:** `cd lib && cargo test --workspace --exclude zk` (note
  primitives, provers, stores, the `model_gate` grep-gate) and
  `cargo test -p zk` (Poseidon parity, setup smoke, `settle_cozk`
  round-trip). Note-circuit round-trips through rapidsnark live in
  `lib/chain`'s `note_prover` tests.
- **Go fixtures:** `make dump-pool-fixture` regenerates
  `/tmp/pool_fixture.json` + the committed VKs;
  `chain/core/pool_verify_test.go` pins signal-rebuild lockstep and
  accept/reject; `make test-e2e-pool` runs the pool lifecycle on a live
  chain.
- **Benchmarks:** `cargo run --release -p invisibook-lib --example
  bench_circuits`; end-to-end numbers come from the app's
  `settle_e2e` test. Results in
  [cozk_experiments.md](cozk_experiments.md).
