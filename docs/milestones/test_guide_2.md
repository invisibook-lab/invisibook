# Invisibook Test Guide 2 — Dual-Party Settlement

> **Status:** Historical (milestone acceptance guide). It references
> the cash model wallet files, which Phase 5 removed. For current test entry points, read
> [../README.md](../README.md) (docs index) and
> [../app_design.md](../app_design.md) §4; dev wallets now come from
> `chain/cfg/tests/{alice,bob}_notes.json` via `scripts/dev-dual.sh`.


This guide tests the full settlement flow with two separate desktop instances (Alice and Bob) communicating via MPC and P2P.

## Prerequisites

```bash
# Build the chain
cd chain
go build -o invisibook .

# Build the desktop app
cd app/desktop
cargo build --release
```

## Test Accounts

| Role  | Mnemonic | Initial ETH | Initial USDT |
|-------|----------|-------------|--------------|
| Alice | `test test test test test test test test test test test junk` | 2000 | 800000 |
| Bob   | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` | 1500 | 600000 |

Cash files are pre-configured in `chain/cfg/tests/` and automatically loaded by the launch script.

---

## Step 1: Start the Chain

```bash
cd chain
rm -rf data/
./invisibook --core-config cfg/tests/core_test.toml
```

Wait until you see `start a new block` in the log before continuing.

> `core_test.toml` uses test mode (no ZK verification), and includes genesis cash for both Alice and Bob.

## Step 2: Launch Alice and Bob

Open **two separate terminals**:

```bash
# Terminal 1 — Alice
./scripts/dev-dual.sh alice

# Terminal 2 — Bob
./scripts/dev-dual.sh bob
```

The script automatically:
- Creates isolated data directories (`.dev/alice/`, `.dev/bob/`)
- Writes each user's mnemonic
- Copies the corresponding `cash.json` (with pre-funded balances)

**Verify**: Both windows open. Each shows its address in the top-right corner. The right panel displays their respective ETH and USDT balances.

> To wipe data and start fresh: `./scripts/dev-dual.sh clean`

## Step 3: Alice Places a Sell Order

In **Alice's window**:

1. Select **Sell**
2. Trading pair: **ETH / USDT**
3. Price: `100`, Amount: `5`
4. Click **Sell ETH**

**Verify**: After ~3 seconds, a Pending sell order appears in the order book. Alice's ETH balance decreases (500 ETH locked).

## Step 4: Bob Places a Buy Order (Triggers Match)

In **Bob's window**:

1. Select **Buy**
2. Trading pair: **ETH / USDT**
3. Price: `100`, Amount: `10`
4. Click **Buy ETH**

**Verify**: After ~3 seconds, both orders change to **Matched** status.

> Bob locks 1000 USDT (10 ETH * 100). Alice locks 500 ETH (5 ETH).

## Step 5: Settlement (Automatic)

Once matched, both clients automatically begin the settlement flow:

1. **Address exchange** — Both register QUIC addresses on-chain
2. **MPC comparison** — Determines which order is smaller (Alice: 500 ETH vs Bob: 1000 USDT; Alice is smaller)
3. **P2P amount exchange** — Alice (smaller) sends her locked amount to Bob (larger) via TCP
4. **Chain comparison** — Both submit MPC shares; chain verifies and marks `is_smaller`
5. **ZK proof** — Bob (larger) generates settle proof, both submit to chain
6. **P2P blinding factor** — Bob sends the recv cash blinding factor to Alice via TCP
7. **Auto-repost** — Bob's remainder is automatically reposted as a new buy order

Watch the toast messages at the bottom of each window for progress.

**Verify (Alice's window)**:
- Toast shows settlement progress, ending with `Settlement complete!`
- Alice receives USDT (5 * 100 = 500 USDT)
- Alice's original sell order changes to **Done**

**Verify (Bob's window)**:
- Toast shows settlement progress, ending with `Settlement complete!`
- Bob receives ETH (5 ETH from Alice)
- Bob's original buy order changes to **Done**
- A **new buy order** appears automatically (Bob's remainder: 10 - 5 = 5 ETH @ 100)

## Step 6: Verify Final State

| Party | ETH Change | USDT Change | Remainder |
|-------|-----------|-------------|-----------|
| Alice | -500 (sold) | +500 (received) | None (smaller, fully consumed) |
| Bob   | +5 (received) | -1000 (locked) → -500 (filled) | New buy order: 5 ETH @ 100 |

---

## Troubleshooting

| Symptom | Solution |
|---------|----------|
| Window doesn't open | Check `cargo build --release` succeeded |
| No balance shown | Run `./scripts/dev-dual.sh clean` then re-launch |
| Orders stuck at Matched | Check chain is running; settlement requires both clients online simultaneously |
| MPC timeout | Both clients must be running at the same time for QUIC connection |
| P2P exchange fails | Check no firewall blocking localhost ephemeral ports |
| Repost shows wrong amount | Verify price is correct; display amount is in token1 (ETH) |
| `input cash not found` | Run `clean` and restart; cash.json may be stale |

## Architecture Notes

- **MPC comparison**: Uses ark-mpc (SPDZ-style 2PC over BN254) via QUIC transport
- **P2P amount exchange**: Smaller party sends its locked amount to larger party via TCP (port = QUIC port + 1). Larger party must NOT send its amount to smaller.
- **P2P blinding factor**: Larger party sends the recv cash blinding factor to smaller party via TCP (port = QUIC port + 2), so the smaller party can construct its recv CashRecord.
- **Peer addresses**: Currently exchanged on-chain using physical IP. In production, this will use Tor or similar anonymous overlay network for privacy.
