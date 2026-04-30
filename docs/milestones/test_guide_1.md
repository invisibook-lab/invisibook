# Invisibook Test & Acceptance Guide

## Setup

### Build

```bash
# Build the chain
cd chain
go build -o invisibook .

# Build the Desktop App
cd app/desktop
cargo build --release
```

### Test Account

| Role | Mnemonic | Initial Balance |
|------|----------|----------------|
| Alice | `test test test test test test test test test test test junk` | 1000 ETH, 500000 USDT |

Cash file: `chain/cfg/tests/alice_plain_cash.json`

---

## Test Steps

### 1. Start the Chain

```bash
cd chain
rm -rf data/
rm ~/.invisibook/cash.json
./invisibook
```

Wait until you see `start a new block` before continuing.

### 2. Launch Desktop and Import Account

1. Start the Desktop App
2. Click **Import Key** in the top-right corner
3. Enter mnemonic: `test test test test test test test test test test test junk`
4. Drag in `chain/cfg/tests/alice_plain_cash.json`
5. Click **Import**

**Verify**: The address appears in the top-right corner, and the right panel shows `ETH: 1000` and `USDT: 500000`

### 3. Submit a Sell Order

1. Select **Sell** on the right panel
2. Choose trading pair **ETH / USDT**
3. Enter Price `3500`, Amount `100`
4. Click **Sell ETH**

**Verify**: After ~3 seconds, an order appears in the Order Book with status **Pending**

### 4. Submit a Buy Order (Triggers Matching)

1. Switch to **Buy**
2. Trading pair **ETH / USDT**, enter Price `3500`, Amount `100`
3. Click **Buy ETH**

**Verify**: After ~3 seconds, both orders in the Order Book change to status **Matched**

---

## Matching Rules

| Priority | Rule | Description |
|----------|------|-------------|
| 1 | Price Priority | Buyer gets the lowest sell price; Seller gets the highest buy price |
| 2 | Block Height Priority | When prices are equal, earlier on-chain orders take precedence |
| 3 | Fee Priority | When in the same block, orders with higher fees take precedence |

Price compatibility condition: Buy price >= Sell price (e.g., Buy@3500 + Sell@3500 can match)

---

## Troubleshooting

| Symptom | Solution |
|---------|----------|
| Order Book not updating | Confirm the chain process is running |
| Both orders stuck at Pending | Verify the trading pair is the same and Buy price >= Sell price |
| Insufficient balance error | Check Active Token balance |
| No balance after import | Re-import the key and drag in the cash.json file again |
