# MPC — Multi-Party Computation Settlement

Pure Rust 2-party computation library for Invisibook order settlement, built on [ark-mpc](https://github.com/renegade-fi/ark-mpc) (SPDZ-style protocol over BN254).

## Architecture

```
┌─────────────┐       QUIC        ┌─────────────┐
│  Party 0    │◄──────────────────►│  Party 1    │
│  (Buy side) │                    │  (Sell side) │
│  settle()   │                    │  settle()   │
└─────────────┘                    └─────────────┘
```

Both parties run the same `settle()` function. Neither party learns the comparison result — both receive only additive shares + MAC shares, which are submitted to chain for on-chain reconstruction and MAC verification.

## Protocol Steps

1. **Share inputs** — Each party secret-shares its value `v` and randomness `r`
2. **Verify commitment consistency** — Confirm both parties agree on `C1`, `C2`
3. **Poseidon verification** — Verify `Poseidon(v, r) == C` in MPC (no opening)
4. **Compare** — Zero-leakage `v1 >= v2` via masked bit decomposition (~65 Beaver triples)
5. **MUX loser's randomness** — Select loser's `r` without revealing who lost
6. **Output shares** — Return additive shares + MAC shares (no values opened to either party)

## Usage

```rust
use mpc::{settle, SettleConfig, Side, SettleShare};

let config = SettleConfig {
    local_addr: "0.0.0.0:9000".parse().unwrap(),
    peer_addr: "192.168.1.101:9000".parse().unwrap(),
};

let share: SettleShare = settle(
    &config,
    Side::Buy,        // this party's role
    my_value,         // secret amount (u64)
    "12345...",       // secret randomness (BN254 Fr, decimal string)
    "67890...",       // C1 = poseidon(v1, r1) from buy side (decimal string)
    "11111...",       // C2 = poseidon(v2, r2) from sell side (decimal string)
).await?;

// submit share to chain for on-chain verification:
// (mac_A + mac_B) == (delta_A + delta_B) * (share_A + share_B) mod P
println!("cmp_share: {}", share.cmp_share);
println!("cmp_mac: {}", share.cmp_mac);
println!("r_loser_share: {}", share.r_loser_share);
println!("r_loser_mac: {}", share.r_loser_mac);
println!("mac_key_share: {}", share.mac_key_share);
```

## Modules

| Module | Description |
|--------|-------------|
| `settle` | Top-level settlement API (`settle()`, `SettleConfig`, `Side`, `SettleShare`) |
| `poseidon` | Poseidon hash over MPC-shared field elements (circom-compatible, t=3, x^5 S-box) |
| `compare` | Zero-leakage u64 comparison via masked bit decomposition (statistical security κ=40) |
| `constants` | 195 ARK + MDS matrix for Poseidon (matches `light-poseidon::new_circom(2)`) |
| `error` | `MpcError` enum (Network / Auth / Protocol) |

## Requirements

- **Nightly Rust** (ark-mpc uses `#![feature]` gates) — `rust-toolchain.toml` is configured
- QUIC connectivity between the two parties (UDP, NAT traversal handled by caller)

## Beaver Triple Source

Currently uses `PartyIDBeaverSource` (deterministic, for development/testing). Production will use OT-based triple generation.
