# Invisibook Test Guide 3 — Proof of Buy

This guide covers acceptance of the Proof of Buy (PoB) consensus against a real CKB
chain: a miner prepays on CKB and writes an allocation table, the budget cell's
zero-knowledge balance proof is verified **on CKB** by the `pob-budget` script, the L2
node checks each declared payment against L1, and blocks are produced, anchored on CKB
and settled.

It has two parts:

- **Part A — automated tests.** Rust (prover/verifier, CKB scripts) and Go (node,
  miner). No chain needed. About 5 minutes.
- **Part B — end-to-end on a local CKB devnet.** Once from the command line, once from
  the browser console. About 10 minutes each.

---

## Prerequisites

| Tool | Why | Install |
|------|-----|---------|
| Go (version in `chain/go.mod`) | node, `pob-miner`, deploy tool | https://go.dev/dl |
| Rust via `rustup` | prover, CKB scripts | https://rustup.rs |
| RISC-V target | CKB scripts | `rustup target add riscv64imac-unknown-none-elf` |
| RISC-V GCC | `ckb-std` build script | `brew install riscv64-elf-gcc` |
| `ckb` | local devnet (Part B) | https://github.com/nervosnetwork/ckb/releases |
| `curl`, `python3` | devnet script (Part B) | usually preinstalled |

`ckb-std` looks for `riscv64-unknown-elf-gcc`; Homebrew installs it as
`riscv64-elf-gcc`. Point it there in every shell that builds CKB scripts:

```bash
export CC_riscv64imac_unknown_none_elf=riscv64-elf-gcc
export AR_riscv64imac_unknown_none_elf=riscv64-elf-ar
```

Part B uses ports **8114** (CKB RPC), **8081** (node payment listener) and **8082**
(miner console). Make sure they are free.

---

## Part A — Automated Tests

Run everything from the repository root.

### A1. Prover and verifier (Rust)

```bash
cd lib && cargo test --release -p budget-stark && cd ..
```

**Verify**: all tests pass (8 in `tests/balance.rs`, 2 in `src/witness.rs`). They
prove honest tables of 1–16 entries and check that the verifier
rejects a wrong total, an inflated or reordered or extra/missing commitment, and a
tampered proof.

Optional — proving time, proof size and security level per table size:

```bash
cd lib && cargo run --release -p budget-stark --features prover --example bench && cd ..
```

**Expected**: proof ≈ 110 KB for up to 128 entries, ≈ 140–150 KB at 1024; proving
≈ 0.1–0.3 s (most of it the 20-bit proof-of-work, so it varies run to run);
conjectured security 103 bits, proven 67 bits.

### A2. CKB scripts

Build all four scripts, then run the rule tests:

```bash
cd ckb
for c in pob-budget pob-submission pob-vault pob-spent; do
    cargo build --manifest-path contracts/$c/Cargo.toml \
        --target riscv64imac-unknown-none-elf --release
done
cargo test --release --manifest-path tests/Cargo.toml -- --nocapture --test-threads=1
cd ..
```

**Verify**: 14 budget-cell tests plus the vault / spent / submission tests all pass.
The R3.2 (balance proof) cases are:

| Test | Expectation |
|------|-------------|
| `creating_a_budget_cell_that_matches_the_payment_is_allowed` | balanced table + proof is accepted |
| `a_table_that_does_not_add_up_is_refused` | table sums to more than `prepaid` → error 9 |
| `a_reordered_table_is_refused` | commitments swapped after proving → error 9 |
| `a_table_without_a_proof_is_refused` | no proof in the witnesses → error 9 |
| `a_truncated_proof_is_refused` | last proof chunk dropped → error 9 |
| `an_empty_table_is_refused` | no entries → error 9 |
| `a_malformed_table_is_refused` | bad entry count / non-canonical commitment → error 8 |
| `balance_proof_cycles_by_table_size` | prints the on-chain cost (below) |

**Expected cycles** (printed by the last test):

| Entries | Proof | Cycles | Share of a block (3.5 B) |
|---------|-------|--------|--------------------------|
| 1 – 128 | ≈ 110 KB | ≈ 49 M | 1.4 % |
| 512 | ≈ 132 KB | ≈ 69 M | 2.0 % |
| 1024 | ≈ 142 KB | ≈ 89 M | 2.5 % |

**Verify** the script contains no RISC-V atomic instruction (CKB-VM cannot execute
them):

```bash
riscv64-elf-objdump -d ckb/contracts/pob-budget/target/riscv64imac-unknown-none-elf/release/pob-budget \
    | grep -cE "\s(lr|sc|amo[a-z]+)\.(w|d)"
```

**Expected**: `0`.

### A3. Node and miner (Go)

```bash
cd chain && go vet ./... && go test ./consensus/ ./ckb/ ./miner/ && cd ..
```

**Verify**: all pass. The PoB-specific ones:

- `consensus`: `TestPoseidon2PermutationMatchesPlonky3`, `TestPaymentCommitMatchesPlonky3`
  — the Go payment commitment matches vectors dumped from the Rust prover byte for byte.
- `ckb`: `TestCreateBudget` (proof is cut into witnesses of ≤ 32 KB each),
  `TestCreateBudgetRequiresAProof`, `TestProofWitnessesLayout`.
- `miner`: `TestSeal*` (a proof over other commitments is refused before paying),
  `TestNodeClient*` (the console talks to a real node payment server).

Then the Go ↔ Rust prover bridge, which needs the static library:

```bash
make build-budget-stark-lib
cd chain && go test -tags budgetstark ./budgetproof/ ./miner/ && cd ..
```

**Verify**: `TestProveMatchesGoCommitments` passes — the prover's commitments equal the
ones the node recomputes when a miner opens them.

---

## Part B — End-to-End on a CKB Devnet

`scripts/devnet.sh` runs everything under `.devnet/` and never touches the repository's
own configs or databases. Start from a clean state:

```bash
scripts/devnet.sh clean
```

### B1. Command line (`pob-miner`)

```bash
scripts/devnet.sh up
```

The script starts a CKB devnet, builds and deploys the four scripts, builds the prover,
prepays 200 heights × 100 CKB with `pob-miner prepay` (which proves the table), waits
out the 24-block payment lead, starts the L2 node and declares the openings. Heights,
count and amount can be changed with `BID_FROM`, `BID_COUNT` and `BID_AMOUNT`
(shannon).

**Verify** the output contains, in order:

```
ckb-deploy: committed in L1 block <n>
prepaid 2000000000000 shannon over heights 1..200
budget cell in 0x<tx hash>
committed in L1 block <m>; blocks spending it may not anchor before L1 block <m+24>
...
declared 200 of 200 heights (1..200)
==> up.
```

`budget cell in ...` followed by `committed in L1 block ...` means CKB accepted the
budget cell, i.e. **the `pob-budget` script verified the balance proof on chain** and
the miner's standard sighash lock accepted the chunked witnesses.

Then watch the chain:

```bash
scripts/devnet.sh status
```

**Verify**: `L2 blocks` and `settled` keep increasing across calls (one L2 block every
~3 s). Stop with `scripts/devnet.sh down`.

### B2. Browser console (`pob-miner console`)

```bash
scripts/devnet.sh clean
scripts/devnet.sh console
```

This starts the devnet, the L2 node and `pob-miner console`, without prepaying.

**Verify** the split of roles — the node no longer serves the console, only a status
endpoint:

```bash
curl -s http://127.0.0.1:8081/payment_status        # {"consumed_height":0,"pending":0}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/pob/status   # 404
```

Open **http://127.0.0.1:8082/**.

1. **Miner** panel: CKB balance, L2 height, L1 tip and the miner address are shown;
   the network is `devnet`.
2. **New prepayment**: total `1000`, first L2 height as suggested, number of heights
   `20`, split **Random** → **Generate split**.
3. Edit a few amounts in the table by hand (e.g. set height 2 to `250.5`).
   **Verify**: the total above the table updates to the new sum.
4. Keep **Declare automatically once L1 confirms** checked → **Prepay** → **Confirm**.
5. **Prepayments** panel: the status moves `broadcasting` → `confirming` →
   `confirmed`. Expand **Show heights**: each height moves `maturing` → `declared` →
   `passed` as the chain produces it (the lead takes ~24 L1 blocks).

**Verify** the chain used the hand-edited amounts:

```bash
grep -o "using declared payment height=[0-9]* amount=[0-9]*" .devnet/logs/l2.log | head
```

**Expected**: each height's amount in shannon equals the table (250.5 CKB →
`25050000000`).

Stop with `scripts/devnet.sh down`; `scripts/devnet.sh clean` removes `.devnet/`.

### B3. Checking the transaction on CKB (optional)

With the devnet still up, the budget cell transaction can be inspected:

```bash
curl -s -H 'content-type: application/json' \
  -d '{"id":1,"jsonrpc":"2.0","method":"get_transaction","params":["0x<tx hash>"]}' \
  http://127.0.0.1:8114 | python3 -m json.tool | grep -E '"status"|"cycles"'
```

**Expected**: `"status": "committed"` and `cycles` ≈ 64 M for B1's default 200
heights (the table is padded to 256 rows), ≈ 55 M for 128 heights or fewer, such as
B2's 20. Most of it is the balance proof; the rest is the lock and the other scripts.
The proof is spread over consecutive witnesses of ≤ 32 KB; the fee is ≈ 0.0012 CKB.

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/proof_of_buy.md](../proof_of_buy.md) / [proof_of_buy_en.md](../proof_of_buy_en.md) | Whitepaper: protocol, payment layer (§7), finality (§8), attacks and defenses (§9), economics (§10) |
| [docs/ckb_layout.md](../ckb_layout.md) | Cells on CKB and their rules R3.x–R5.x; §3 the budget cell and the balance proof (circuit, witness layout, cost); §6 what L2 nodes verify (V1–V8); §7 L2 ↔ CKB interfaces |
| [docs/chain_design.md](../chain_design.md) | Node implementation: consensus package, payment endpoints, CKB client, miner console |
| [ckb/README.md](../../ckb/README.md) | Building, testing and deploying the CKB scripts; the RISC-V atomics restriction |
| [chain/miner/README.md](../../chain/miner/README.md) | `pob-miner console`: features, configuration, endpoints |

Key code:

| Path | What |
|------|------|
| `lib/budget-stark/` | Balance proof: circuit (`src/air.rs`), commitments (`src/hash.rs`), STARK parameters (`src/config.rs`), witness layout (`src/witness.rs`) |
| `lib/budget-stark-ffi/` | Static library exposing the prover to Go |
| `ckb/contracts/pob-budget/` | Budget cell script, R3.1–R3.5 (R3.2 verifies the proof) |
| `ckb/contracts/pob-vault/`, `pob-spent/`, `pob-submission/` | Mining addr, spent-token marking, block commitments |
| `chain/consensus/` | PoB consensus: VRF, scoring, payment checks, anchoring, reveal, fork choice |
| `chain/consensus/poseidon2.go` | Payment commitment (Go port of the prover's Poseidon2) |
| `chain/ckb/` | CKB client: budget cell transaction, reading allocations and anchors |
| `chain/cmd/pob-miner/`, `chain/miner/` | Miner CLI and browser console; the only place that proves and pays |
| `scripts/devnet.sh` | Local end-to-end run |

---

## Known Limitations

- **Compensation for losing miners** (whitepaper §10.2) is not implemented: only the
  winning block's miner is rewarded.
- The items under "待确认" in [ckb_layout.md](../ckb_layout.md) §8 are open design
  questions: retention of openings and treating a commitment that is never revealed as
  an abstention, re-submission after an L1 reorg, bounds of weak subjectivity, and the
  cost of spam commit cells.
- `pob-miner` must be built with `make build-pob-miner` (it links the Rust prover). A
  build without the `budgetstark` tag still runs but refuses to prepay with a message
  saying so. The node is built as usual (`go build -o invisibook .`) and does not link
  the prover.
