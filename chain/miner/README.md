# miner

The PoB miner console: lets a miner carry out the prepayment and allocation of
[proof_of_buy_en.md](../../docs/proof_of_buy_en.md) §7.2 from a browser, instead of running
`pob-miner prepay` / `declare` by hand.

It starts with the node and is served on the node's payment listener (`payment_listen` in
`core.toml`, `:8081` by default). It uses the node's own miner key and payment book, so the
key that pays, produces and signs is always the same one (§6.2 Identity Binding).

## What it does

1. **Prepay**: pays CKB to the mining addr and, in the same transaction, writes the
   allocation table — which L2 heights, and how much for each.
2. **Allocate**: three ways, each summing to exactly the prepaid total (§7.2, equality
   rather than "no more than"):
   - `random` (default): each height varies around the mean, ±50% by default
   - `even`: an equal share per height
   - `manual`: the miner fills in every height
3. **Keep the openings**: each height's plaintext amount and blinding factor are written
   to a local file **before** the L1 transaction goes out. L1 only holds the commitments;
   losing the openings forfeits the prepayment.
4. **Declare**: hands the openings to the node's payment book, but only once the
   prepayment satisfies §7.3's lead time of 24 L1 blocks. Declared earlier, the node would
   produce a block with it straight away, and that block would fail the lead-time check at
   settlement and never finalize.

## Files

| File | Contents |
| --- | --- |
| `amount.go` | CKB ↔ shannon conversion (1 CKB = 10^8 shannon) |
| `plan.go` | Allocation (even / random / manual) and commitments |
| `store.go` | Local store of prepayments and their openings |
| `service.go` | Prepaying, following the transaction onto L1, waiting out the lead time, declaring; resumes unfinished prepayments after a restart |
| `api.go` | HTTP endpoints and access control |
| `web/index.html` | The browser page, embedded into the binary at build time |

## Usage

With the node running, open `http://127.0.0.1:8081/` on the node's machine.

The node needs a `[ckb]` section. Against the in-memory mock L1 the console can show
status but cannot prepay.

Local end-to-end run:

```
scripts/devnet.sh console   # CKB devnet + node, no prepayment
scripts/devnet.sh down      # stop
```

### Configuration (`[consensus]` in `cfg/core.toml`)

| Key | Meaning |
| --- | --- |
| `schedule_path` | The openings file, `data/prepayments.json` by default, mode 0600. **Back it up like a private key.** |
| `miner_api_token` | Empty: the endpoints answer this machine only. Set: they require `Authorization: Bearer <token>` instead. |

### Endpoints

Amounts are in CKB; writes must be `application/json`.

| Endpoint | Purpose |
| --- | --- |
| `GET /pob/status` | Miner address, spendable balance, L1's latest block number, settled L2 height, suggested start height |
| `POST /pob/plan` | Preview an allocation without paying |
| `POST /pob/prepay` | Prepay and allocate; by default declares automatically once the lead time is met |
| `POST /pob/declare` | Declare the not-yet-declared heights of a prepayment by hand |
| `GET /pob/prepayments` | Every prepayment and the state of each height (blinding factors are never returned) |

```
# Preview: 1000 CKB split at random over heights 31..80
curl -s -H 'Content-Type: application/json' \
  -d '{"mode":"random","from":31,"count":50,"total_ckb":"1000"}' \
  http://127.0.0.1:8081/pob/plan

# Allocate by hand and prepay, without auto-declaring
curl -s -H 'Content-Type: application/json' \
  -d '{"mode":"manual","allocations":[{"height":31,"amount_ckb":"20"},{"height":32,"amount_ckb":"5.5"}],"auto_declare":false}' \
  http://127.0.0.1:8081/pob/prepay

# Declare by hand once the lead time is met
curl -s -H 'Content-Type: application/json' \
  -d '{"prepayment_id":"<id>"}' http://127.0.0.1:8081/pob/declare
```

### Suggested start height

The page pre-fills the first L2 height to allocate to:

- An earlier prepayment still reaches ahead → right after its last height, leaving no
  gap (with no other miner, a height nobody allocated is a height nobody produces, and
  the chain stops there)
- The chain is waiting for a declaration → the next height
- The chain is moving → the current height plus the L2 heights expected to pass during
  the 24-L1-block lead time

It is only a suggestion and can be edited.
