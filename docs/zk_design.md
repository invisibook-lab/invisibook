# ZK Design

## 1. Overview

Invisibook hides every plaintext amount that flows through the chain. On-chain
state stores a Poseidon commitment per `Cash` row instead of the raw value, and
every writing that mutates `Cash` state must be accompanied by a Groth16 zk
proof that the wallet operation is consistent with those commitments. The
chain verifies the proof but never sees the plaintext.

Five circuits cover the four wallet operations:

| Wallet operation | Circuit | What the circuit proves |
|---|---|---|
| Deposit | `deposit.circom` | The new Cash commitment opens to the same hidden amount the bridge attests via `bridge_commitment` |
| Withdraw | `withdraw.circom` | Spent inputs cover the hidden withdraw amount + change, where the withdraw amount is bound to a `bridge_out_commitment` |
| SendOrder split | `split.circom` | Splitting an Active Cash into a Locked output + a change output preserves total value |
| SettleOrder (larger side) | `settle_larger.circom` | Conservation of the side that has change + cross-leg ratio `fill_t2 == fill_t1 * price` |
| SettleOrder (smaller side) | `settle_smaller.circom` | Conservation of the side that fully fills (no change) |

Toolchain (curve = BN254 throughout):

- **Circuit language** — `circom 2.2.x`. Templates live in `lib/zk/templates/`,
  with reusable circomlib primitives moved under `templates/utils/` and
  wallet-specific helpers (`commitments.circom`) at the top level.
- **Trusted setup** — `snarkjs powersoftau` + `snarkjs groth16 setup` +
  `snarkjs zkey export verificationkey`. Wallet-side helpers in
  [`lib/zk/src/setup.rs`](../lib/zk/src/setup.rs) shell out to it; outputs
  cache under `lib/target/circuit-build/<name>/{vk.json,<name>.zkey}`.
- **Prover** — `rapidsnark` (C++, ~50× faster than snarkjs prove). Wallet-side
  invocation lives in [`lib/zk/src/prover.rs`](../lib/zk/src/prover.rs).
- **Verifier** — `go-rapidsnark/verifier` on the chain side, wrapped by
  [`chain/core/zkverify.go`](../chain/core/zkverify.go).

Wallet workflow per operation: assemble plaintext witness → call type-safe
wrapper in [`lib/zk/src/wallet.rs`](../lib/zk/src/wallet.rs) → wrapper builds
the JSON witness, gens the witness via `node generate_witness.js`, runs
rapidsnark, returns the snarkjs-format `proof.json` + public commitments.
Wallet sends commitments + proof JSON to chain. Chain rebuilds the
public-input vector from the commitments (and any plaintext public fields like
`price`) and calls `VerifyGroth16`.

## 2. Privacy Model

What the chain stores per `Cash` row:

| Field | Public on-chain | Notes |
|---|---|---|
| `ID` | yes | `SHA256(pubkey ‖ token ‖ commitment_hex)` — deterministic |
| `Pubkey` | yes | owner's ed25519 pubkey hex |
| `Token` | yes | e.g. ETH, USDT |
| `Amount` | **commitment hex only** | = `Poseidon(2)([plaintext_amount, random])` |
| `Status` | yes | Active / Locked / Spent |
| `ZkProof` | yes | the proof that authorised this Cash's creation |
| `By` | yes | Locked → order ID; Spent → tx/cash ID |

What the wallet keeps locally (in `~/.invisibook/cash.json`, see
[`CashRecord`](../lib/chain/src/cash_store.rs)):

- `cash_id` (matches chain)
- `amount` (plaintext u64) — needed to open the commitment when spending
- `random` (32-byte hex) — the blinding factor; without it the wallet
  cannot prove ownership of value

Order metadata stored on-chain ([`Order`](../chain/core/order.go)):

- `Type / Subject / Price / Pubkey / InputCashIDs / HandlingFee` — public
- `Amount` — commitment hex (not plaintext)

Observers can therefore see *who* trades *what pair* at *what price*, but
not *how much*.

## 3. Common Conventions Across Circuits

- **Commitment shape** — `Poseidon(2)([amount, random])` where `amount` fits
  in 64 bits and `random` is a 32-byte big-endian field element reduced to
  the BN254 scalar field. Wallet helper:
  [`zk::wallet::poseidon_commit`](../lib/zk/src/wallet.rs).
- **Range checks** — every plaintext amount that participates in conservation
  arithmetic is forced to 64 bits via `Num2Bits(64)`. Without this, a malicious
  prover could pick a field element that satisfies the equation but represents
  a "negative" value modulo the field characteristic.
- **Zero-pad slots** — wallet circuits use fixed-size input/output arrays
  (`N=2`, `M=2`). Unused slots are filled with `(amount=0, random=0)`; their
  Poseidon hash is the constant `Poseidon(2)([0, 0])`. Chain side rebuilds the
  same constant via `PoseidonZeroCommitment` /
  `PoseidonZeroCommitmentHex` in [`zkverify.go`](../chain/core/zkverify.go).
  The constant value is regenerable via `cargo run -p zk --example show_zero_commit`.
- **Proof on-wire format** — snarkjs `proof.json` (`pi_a`, `pi_b`, `pi_c`,
  `protocol`); chain trims rapidsnark's trailing NUL padding before parsing.
- **Public-input vector order** — must exactly match the circuit's
  `component main { public [...] }` declaration. Each circuit's section below
  lists the order chain uses.

Circuits are **not** wired into a one-shot proving service: every wallet binary
shells out to circom + snarkjs + rapidsnark on first use, then caches the
artifacts under `lib/target/circuit-build/`.

## 4. Circuit Catalog

### 4.1 Deposit (`deposit.circom`)

Mints a single new Cash whose hidden amount equals what was bridged in from
another chain.

**Public inputs (3)** — circuit declares
`public [bridge_commitment, output_hashes]` with `output_hashes[2]`:

1. `bridge_commitment` — Poseidon commitment of the deposited amount,
   eventually attested by the source-chain bridge inclusion proof
2. `output_hashes[0]` — the new Cash's commitment (becomes
   `Cash.Amount` on chain)
3. `output_hashes[1]` — zero-pad commitment

**Private inputs**: `deposit_amount`, `r_bridge`, `output_amounts[2]`,
`output_randomness[2]`.

**Constraints**:

1. `Poseidon(deposit_amount, r_bridge) === bridge_commitment` (binds the
   hidden amount to the public bridge commitment)
2. 64-bit range check on `deposit_amount`
3. `VerifyAmounts(2)` opens both output commitments + computes their sum
4. `outputs.sum === deposit_amount` (conservation)

**Wallet caller**: [`prove_deposit`](../lib/zk/src/wallet.rs).

**Chain handler**: [`Account.Deposit`](../chain/core/account.go) — verifies
`[bridge_commitment, output_commitment, PoseidonZeroCommitment]` against
`depositVK`.

**Open TODO**: bridge inclusion proof attesting `bridge_commitment` is not
yet verified — the chain trusts the value blindly. Suitable for testnet only.

### 4.2 Withdraw (`withdraw.circom`)

Spends 1–2 input Cashes to withdraw a hidden amount to the destination chain
plus an optional change output.

**Public inputs (5)**:

1. `bridge_out_commitment` — Poseidon commitment of the hidden withdraw amount
2. `input_hashes[0..1]` — commitments of the two locked input slots
3. `output_hashes[0]` — change Cash commitment (or zero-pad if no change)
4. `output_hashes[1]` — zero-pad

**Private inputs**: `withdraw_amount`, `r_bridge_out`, `input_amounts[2]`,
`input_randomness[2]`, `output_amounts[2]`, `output_randomness[2]`.

**Constraints**: bridge binding + 64-bit range check on `withdraw_amount` +
open every input via `VerifyAmounts` + open every output via `VerifyAmounts`
+ `inputs.sum === withdraw_amount + outputs.sum`.

**Chain handler**: [`Account.Withdraw`](../chain/core/account.go) — looks up
each `Inputs[i]` Cash, asserts `Active` + matching pubkey/token, pulls its
on-chain `Cash.Amount` as the input commitment, rebuilds the public vector,
verifies, then `SpendCash` + mints change if `OutputCommitments[0]` is not
the zero-pad constant.

**Open TODO**: destination-chain bridge release proof attesting
`bridge_out_commitment` is not yet verified.

### 4.3 SendOrder Split (`split.circom`)

Restructures the user's own Cashes when they want to lock a partial amount
for an order.

**Public inputs (4)**:

1–2. `input_hashes[0..1]` — original Active Cash commitments
3. `output_hashes[0]` — the new Locked Cash's commitment (the order's
   collateral, equals `req.Amount`)
4. `output_hashes[1]` — change Cash commitment (or zero-pad)

**Constraints**: open inputs + open outputs + `inputs.sum === outputs.sum`
(value conservation; no off-chain anchor needed since it's a pure internal
restructuring).

**Chain branch**: [`OrderBook.SendOrder` split branch](../chain/core/orderbook.go)
runs only when `req.Change != nil`. Non-split full-lock requests do *not*
need a proof because the commitment is unchanged (Active → Locked is a
status-only transition).

### 4.4 SettleOrder — Asymmetric Pair

Settlement of two matched orders involves two token groups (Token1 and
Token2). To both verify each side's value conservation **and** tie the two
sides together at the chain layer **without revealing fill amounts**,
settlement uses two asymmetric circuits, one per side of the trade:

- The **larger side** (whose locked input strictly exceeds the fill, so it
  has change) runs `settle_larger.circom`. Its proof binds *both* sides' fill
  commitments and enforces the cross-leg ratio internally.
- The **smaller side** (whose locked input is fully consumed by the fill,
  no change) runs `settle_smaller.circom`. Its proof binds only its own fill
  commitment.

Chain pairs the two proofs via cross-leg match-commitment equality.

#### 4.4.1 `settle_larger.circom`

**Public inputs (8)** — `public [my_match_commitment, other_match_commitment, price, is_token2_sender, input_hashes, change_commitment, counterparty_recv_commitment]`:

1. `my_match_commitment` — `Poseidon(my_fill, r_my)` where `my_fill = inputs.sum - change_amount`
2. `other_match_commitment` — `Poseidon(other_fill, r_other)`
3. `price` — plaintext, must equal on-chain `Order.Price`
4. `is_token2_sender` — boolean (1 if I'm sending Token2)
5–6. `input_hashes[0..1]` — my locked Cash commitments
7. `change_commitment` — my change Cash (or zero-pad if exact fill)
8. `counterparty_recv_commitment` — the counterparty's new Cash, **NOT
   opened** here (sender doesn't know the counterparty's random)

**Constraints**:

1. `is_token2_sender ∈ {0, 1}` (boolean check)
2. `VerifyAmounts(2)` opens own input commitments
3. `Poseidon(change_amount, change_random) === change_commitment`
4. `my_fill <== inputs.sum - change_amount` (derived signal — no separate
   `fill` input)
5. 64-bit range checks on `my_fill`, `change_amount`, `other_fill`
6. `Poseidon(my_fill, r_my) === my_match_commitment`,
   `Poseidon(other_fill, r_other) === other_match_commitment`
7. Mux: `(fill_t1, fill_t2) = is_token2_sender ? (other_fill, my_fill) : (my_fill, other_fill)`
8. `fill_t2 === fill_t1 * price` (cross-leg ratio enforced by the larger side)

#### 4.4.2 `settle_smaller.circom`

**Public inputs (4)** — `public [match_commitment, input_hashes, counterparty_recv_commitment]`:

1. `match_commitment` — `Poseidon(inputs.sum, r_match)` (no separate fill
   variable — fill ≡ inputs.sum)
2–3. `input_hashes[0..1]` — own locked Cash commitments
4. `counterparty_recv_commitment` — the counterparty's new Cash, not opened

**Constraints**: open inputs via `VerifyAmounts` + bind
`Poseidon(inputs.sum, r_match) === match_commitment`. That's it — no
cross-leg ratio (the larger side handles that), no change opening.

#### 4.4.3 Chain Verification of a Matched Pair

[`OrderBook.SettleOrder`](../chain/core/orderbook.go) accepts a request with
`Legs []SettleTokenLeg` (always length 2, one per token group). Each leg
carries a `Side` tag (`larger` or `smaller`) plus the side-specific fields
+ a snarkjs proof. Chain checks (in order):

1. Both `OrderIDs[0..1]` exist, are `Matched`, and reference each other
2. Both orders agree on `price` (sanity check)
3. For each leg, build the public-input vector matching its circuit's
   declaration order and call `VerifyGroth16` against the appropriate VK
   (`settleLargerVK` or `settleSmallerVK`)
4. **Cross-leg match-commitment equality** — replaces an on-chain
   `fill_t2 == fill_t1 * price` check (impossible because fills are private):
   `larger.OtherMatchCommitment == smaller.MatchCommitment`. Same Poseidon
   commitment ↔ same `(fill, r_match)` opening (collision resistance).
5. `larger.Price == on-chain order.Price`, `larger.IsToken2Sender`
   consistent with `larger.Token`
6. Each leg's `Token` matches the actual locked token of the corresponding
   order

After all proofs verify, chain spends both orders' input cashes, mints the
recv Cashes (and the larger side's change Cash if `ChangeCommitment !=
PoseidonZeroCommitmentHex`), and marks both orders `Done`.

#### 4.4.4 Off-Chain Coordination

Both parties must agree on `(fill_t1, fill_t2, r_match_t1, r_match_t2)`
before either can prove. Each party then computes their own
`recv_commitment` using their own random and exchanges only the hex with
the counterparty. The current demo in
[`cli/src/bin/cli_settle.rs`](../cli/src/bin/cli_settle.rs) bypasses this
exchange by holding both mnemonics in one driver and generating both proofs
locally — production needs a P2P leg-exchange channel.

## 5. Trust Boundaries and Known Limitations

| Concern | Status |
|---|---|
| Bridge inclusion proof (Deposit `bridge_commitment`) | **TODO** — chain trusts client value blindly |
| Bridge release proof (Withdraw `bridge_out_commitment`) | **TODO** — same |
| Counterparty receive cash opening (Settle) | Counterparty's own problem — they keep their `r_recv` private; if a sender gives a fake `recv_commitment`, the receiver can't spend the cash later, so it's self-harm not attack |
| Trusted setup ceremony | Currently `snarkjs` single-party (`dev_setup_snarkjs`) — toxic waste in process memory. Replace with a real Powers of Tau + per-circuit phase-2 ceremony before mainnet |
| Partial fills in matching engine | Not supported; smaller side always fully fills |
| `N>2` inputs / `M>2` outputs | Circuits are hardcoded to N=M=2; clients refuse selections that exceed it (`select_cash` is the gating point) |
| Android Poseidon | `lib/chain/src/orderbook.rs::encrypt_with_random` falls back to SHA-256 on `target_os = "android"`, which is **incompatible** with the circuits — Android cannot produce valid commitments today |
| App (Dioxus mobile/desktop) split proof generation | Stubbed (`trade_form.rs` passes `None`); only the CLI binaries currently produce real proofs |
| Settle exact-fill (both sides have no change) | The `dual-larger` chain branch exists but the `cli_settle` demo bails out — needs implementation |

## 6. Repository Layout

```
lib/zk/
├── templates/                           # circom sources
│   ├── utils/                           # circomlib primitives (bitify, comparators, poseidon[_constants])
│   ├── commitments.circom               # VerifyAmounts (Poseidon open + range check + sum)
│   ├── deposit.circom
│   ├── withdraw.circom
│   ├── split.circom
│   ├── settle_larger.circom
│   └── settle_smaller.circom
├── src/
│   ├── lib.rs                           # CircuitParams<E>, CircuitProof<E>, dev_setup, generate_proof, verify_proof
│   ├── circom_bridge.rs                 # parses .r1cs / .wtns; impl ConstraintSynthesizer for ark-groth16
│   ├── setup.rs                         # snarkjs subprocess wrapper for ptau + zkey + vk.json
│   ├── prover.rs                        # rapidsnark subprocess wrapper
│   ├── wallet.rs                        # poseidon_commit, fr_to_hex, prove_{deposit,withdraw,split,settle_*}
│   └── test_circuit.rs                  # node-based witness generation for tests
└── examples/
    ├── show_zero_commit.rs              # prints Poseidon(0,0) for chain to hardcode
    └── dump_{deposit,withdraw,split,settle}_fixture.rs   # produce fixtures consumed by chain Go tests

chain/core/
├── zkverify.go                          # LoadVK / VerifyGroth16 / HexToDecimal / Poseidon zero constants
├── zkverify_test.go                     # fixture-driven verifier tests for all circuits
├── account.go                           # Deposit + Withdraw handlers
├── orderbook.go                         # SendOrder (split branch) + SettleOrder
├── config.go                            # OrderBookConfig.Split/Settle*VKPath, AccountConfig.Deposit/WithdrawVKPath
└── cash_scheme.go                       # CreateCash now honours caller's Status field

cli/src/bin/
├── cli_deposit.rs                       # standalone subcommand binaries
├── cli_withdraw.rs
├── cli_send_order.rs
└── cli_settle.rs                        # demo driver (holds both mnemonics)
```

## 7. Toolchain Prerequisites

Required to run the prover/verifier locally:

- **Rust** stable, with workspaces enabled (default).
- **Go** 1.21+ for chain (project `go.mod` requires 1.25+; `go-rapidsnark` itself needs 1.21+).
- **Node.js** 18+ — used for circom witness generation (`generate_witness.js`).
- **circom** ≥ 2.2.x — `cargo install --git https://github.com/iden3/circom.git`
  or download a release. Must be on `$PATH`.
- **snarkjs** — `npm install -g snarkjs` (≥ 0.7.x). Must be on `$PATH`.
- **rapidsnark** — C++ binary from
  [`iden3/rapidsnark`](https://github.com/iden3/rapidsnark). Build per its
  README; the result must be on `$PATH` as `rapidsnark`. The chain Go
  verifier (`go-rapidsnark`) does not need the binary; only the wallet does.

The first invocation of any wallet circuit caches its compiled artifacts and
trusted-setup output under `lib/target/circuit-build/<circuit>/`. Subsequent
runs reuse the cache (delete that directory to force a re-setup).

## 8. Testing

### 8.1 Unit Tests

#### Rust (`lib/zk` + `lib/chain`)

```bash
cd lib
cargo test -p zk        # 24+ tests covering all circuits + Poseidon parity + setup + prover round-trips
cargo test -p invisibook-lib   # lib/chain client + helpers
```

The `zk` test suite spans:

- `lib.rs::tests::deposit_proof_*` (4) — circuit-level prove/verify with
  ark-groth16, including a "bridge_commitment doesn't bind hidden amount"
  rejection case.
- `lib.rs::tests::withdraw_proof_*` (4) — analogous for withdraw.
- `lib.rs::tests::split_proof_*` (2) — conservation pass + violation reject.
- `lib.rs::tests::settle_larger_proof_*` (4) — valid + zero-change variant +
  ratio mismatch reject + change-exceeds-inputs reject.
- `lib.rs::tests::settle_smaller_proof_*` (2) — valid + match-binding reject.
- `wallet.rs::tests` — Poseidon helper invariants + hex padding.
- `setup.rs::tests::deposit_dev_setup_produces_zkey_and_vk` — snarkjs setup
  smoke test.
- `prover.rs::tests::*_proof_round_trips_through_rapidsnark` — full
  prove-and-parse loop for deposit / withdraw / split / settle_larger /
  settle_smaller.

The first run of any test that hits a circuit takes ~5–10 s (circom compile
+ snarkjs ptau setup); subsequent runs reuse the cache and finish in seconds.

#### Go (`chain/core`)

The chain-side verifier tests load fixtures produced by the Rust example
binaries. Generate or refresh the fixtures first:

```bash
cd lib
cargo run -p zk --example dump_deposit_fixture  -- /tmp/deposit_fixture.json
cargo run -p zk --example dump_withdraw_fixture -- /tmp/withdraw_fixture.json
cargo run -p zk --example dump_split_fixture    -- /tmp/split_fixture.json
cargo run -p zk --example dump_settle_fixture   -- /tmp/settle_fixture.json
```

Then run:

```bash
cd chain
go test ./core/        # ~14 tests: HexToDecimal + per-circuit Verify + tamper rejection
```

If a fixture file is missing, the corresponding Go test prints a `t.Skip`
message rather than failing.

### 8.2 End-to-End Test

Builds chain + four CLI subcommands, runs a complete deposit → trade →
settle cycle between Alice and Bob, and inspects the chain state via
`GetAccount`. ~2 minutes the first run, ~30 s on subsequent runs.

#### Step 1 — Build everything

```bash
# zk artifacts (cached after first run)
cd lib && cargo run -p zk --example show_zero_commit   # forces all circuits to compile + setup

# chain
cd ../chain && go build -o invisibook .

# CLI binaries
cd ../cli && cargo build --bin cli_deposit --bin cli_withdraw --bin cli_send_order --bin cli_settle
```

#### Step 2 — Start the chain

```bash
# from chain/
rm -rf data && rm -f ~/.invisibook/cash.json   # clean slate
./invisibook
# log: "register Writing (Deposit)" / "register Writing (SendOrder)" etc., then "I am Leader!" repeating
```

Wait until the chain has produced a few blocks (5–10 s). Genesis cashes for
Alice and Bob are minted automatically per `chain/cfg/core.toml`.

Two test mnemonics (predefined in `chain/test/e2e_test.go`):

- Alice: `test test test test test test test test test test test junk`
- Bob:   `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`

#### Step 3 — Each side deposits

```bash
# from invisibook/
./cli/target/debug/cli_deposit --token ETH --amount 80 \
    --mnemonic "test test test test test test test test test test test junk"

./cli/target/debug/cli_deposit --token USDT --amount 60 \
    --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Expect each command to print `deposit ok: token=... amount=... cash_id=...`
within 5 s (circuit setup is cached after the first call).

#### Step 4 — Each side sends a matching order

```bash
./cli/target/debug/cli_send_order --type sell --token1 ETH --token2 USDT \
    --price 1 --amount 80 \
    --mnemonic "test test test test test test test test test test test junk"

./cli/target/debug/cli_send_order --type buy  --token1 ETH --token2 USDT \
    --price 1 --amount 60 \
    --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Each prints `send_order ok: id=... type=... price=1 amount=... (split=false)`
(no split because deposits are exact). Note the two order IDs.

Verify they matched:

```bash
curl -sS -X POST 'http://localhost:7999/api/reading' \
    -H "Content-Type: application/json" \
    -d '{"tripod_name":"orderbook","func_name":"QueryOrders","params":"{}"}' \
    | python3 -m json.tool
# Both orders should show "status": 1 (Matched) and reference each other in match_order.
```

#### Step 5 — Settle

Use the two order IDs from step 4:

```bash
./cli/target/debug/cli_settle \
    --orders <ALICE_ORDER_ID>,<BOB_ORDER_ID> \
    --alice-mnemonic "test test test test test test test test test test test junk" \
    --bob-mnemonic   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

Expect:

```
matched: alice ETH=80, bob USDT=60, price=1, fill_t1=60, fill_t2=60
preparing settle circuits (compile + snarkjs setup, cached)...
submitting settle to chain...
settle ok: orders ... / ... done; alice received 60 USDT; bob received 60 ETH
```

#### Step 6 — Verify final state

```bash
ALICE=3b37d4c67dfd535549e73bc044ff6bc8b62bdfb962a92f1b3e11c6c0b3b4dedb
BOB=175b274d53b54ddf4426bbdb98c8416972f0476a678ac320f52ff960f69e189b

get_account() {
    local pubkey=$1 token=$2
    curl -sS -X POST 'http://localhost:7999/api/reading' \
        -H "Content-Type: application/json" \
        -d "{\"tripod_name\":\"account\",\"func_name\":\"GetAccount\",\"params\":\"{\\\"pubkey\\\":\\\"$pubkey\\\",\\\"token\\\":\\\"$token\\\"}\"}" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); s={0:'Active',1:'Locked',2:'Spent'}; [print(f\"  {c['id'][:16]}...  {s.get(c['status'],c['status'])}  {c['amount'][:16]}...\") for c in d['cash']]"
}

echo "=== alice ETH ==="   ; get_account "$ALICE" ETH    # genesis (Active) + 20-ETH change (Active)
echo "=== alice USDT ==="  ; get_account "$ALICE" USDT   # genesis (Active) + 60-USDT recv (Active)
echo "=== bob ETH ==="     ; get_account "$BOB"   ETH    # genesis (Active) + 60-ETH recv (Active)
echo "=== bob USDT ==="    ; get_account "$BOB"   USDT   # genesis (Active) only — bob's 60-USDT deposit was fully filled
```

The 80-ETH deposit and its locked counterpart on alice's side are `Spent` and
filtered out by `GetAccount`'s `status != Spent` query, as is bob's 60-USDT
deposit + lock. `Cash.amount` is always the commitment hex; the plaintext
value never appears on chain.

#### Tamper Test (optional)

To confirm the verifier rejects bad inputs:

```bash
# Modify any leg's MatchCommitmentT1 by one character before submission, or
# replace cli_settle's body to flip a hex char in the commitment field.
# Chain log should show: "cross-leg mismatch: larger.other_match_commitment != smaller.match_commitment"
```

#### Cleanup

```bash
pkill invisibook
rm -rf chain/data ~/.invisibook/cash.json
```

### 8.3 What the Tests Cover Together

| Layer | Coverage | Where |
|---|---|---|
| Circuit semantics | Pass on valid witness, reject on tampered witness, range checks fire on wrap | `lib/zk/src/lib.rs::tests::*_proof_*` (Rust ark-groth16 prove + verify) |
| Wallet → wire format | Witness JSON shape, snarkjs proof JSON parsing, commitment hex echo | `lib/zk/src/prover.rs::tests::*_round_trips_through_rapidsnark` |
| Chain verifier wiring | go-rapidsnark consumes wallet's proof + reconstructed public inputs | `chain/core/zkverify_test.go::TestVerifyGroth16Accepts*` |
| Chain reject paths | Tampered commitments / proofs rejected | `chain/core/zkverify_test.go::TestVerifyGroth16Rejects*` |
| Cross-leg binding | Larger's other_match must equal smaller's match | `chain/core/zkverify_test.go::TestSettleCrossLegMatchEquality` (consistency) + handler-level cross-check |
| End-to-end privacy | Real chain rejects bad proofs and accepts good ones; on-chain state holds only commitments | E2E flow above |
