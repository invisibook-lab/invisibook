use rand::RngCore;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

use crate::cash_store::CashRecord;
use crate::types::*;

// ────────────────────── ID Generator ──────────────────────

/// Returns the first 7 characters of an order ID for display purposes.
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(7)]
}

/// Computes a deterministic order ID by SHA-256 hashing the concatenation
/// of all input Cash IDs. Must match the Go side ComputeOrderID.
pub fn compute_order_id(input_cash_ids: &[String]) -> OrderID {
    let mut hasher = Sha256::new();
    for id in input_cash_ids {
        hasher.update(id.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

// ────────────────────── Cipher ──────────────────────

/// Core implementation: returns ciphertext = poseidon(amount, random).
/// `random_bytes` is provided by the caller so genesis cash can use a fixed value.
fn encrypt_with_random(plaintext: &str, random_bytes: [u8; 32]) -> (CipherText, u64) {
    let amount: u64 = plaintext.parse().unwrap_or(0);

    #[cfg(not(target_os = "android"))]
    {
        use ark_bn254::Fr;
        use ark_ff::{BigInteger, PrimeField};
        use light_poseidon::{Poseidon, PoseidonHasher};

        let result = (|| -> Option<String> {
            let amount_fr = Fr::from(amount);
            let random_fr = Fr::from_be_bytes_mod_order(&random_bytes);
            let mut hasher = Poseidon::<Fr>::new_circom(2).ok()?;
            let hash = hasher.hash(&[amount_fr, random_fr]).ok()?;
            let bytes = hash.into_bigint().to_bytes_be();
            Some(bytes.iter().map(|b| format!("{:02x}", b)).collect())
        })();

        if let Some(hex) = result {
            return (hex, amount);
        }
    }

    // Android fallback: SHA-256(amount || random)
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hasher.update(random_bytes);
    let cipher = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    (cipher, amount)
}

/// Core implementation: returns (ciphertext, amount_u64, random_bytes).
fn encrypt_amount_inner(plaintext: &str) -> (CipherText, u64, [u8; 32]) {
    let mut random_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);
    let (cipher, amount) = encrypt_with_random(plaintext, random_bytes);
    (cipher, amount, random_bytes)
}

/// Encrypts the plaintext amount. Use `encrypt_amount_with_info` when you
/// need to persist the (amount, random) for later cash verification.
pub fn encrypt_amount(plaintext: &str) -> CipherText {
    encrypt_amount_inner(plaintext).0
}

/// Encrypts the plaintext amount and returns `(ciphertext, amount, random_hex)`
/// so callers can store the cash record locally.
pub fn encrypt_amount_with_info(plaintext: &str) -> (CipherText, u64, String) {
    let (cipher, amount, random_bytes) = encrypt_amount_inner(plaintext);
    let random_hex = hex::encode(random_bytes);
    (cipher, amount, random_hex)
}

// ────────────────────── Cash Selection ──────────────────────

/// Result of selecting cash for an order.
#[derive(Debug)]
pub enum CashSelection {
    /// One or more cash exactly cover the total — no change needed.
    Exact(Vec<String>),
    /// Selected cash exceed the total — change is needed.
    WithChange {
        cash_ids: Vec<String>,
        change_amount: u64,
    },
    /// Not enough active cash for this token.
    Insufficient,
}

/// Select the best set of active cash records for the given token and total.
///
/// Priority:
/// 1. Exact match — a single cash where amount == total
/// 2. Combine smaller cash (preferred) — greedily pick descending until sum >= total
/// 3. Split a larger cash (fallback) — smallest cash where amount > total
pub fn select_cash(records: &[CashRecord], token: &str, total: u64) -> CashSelection {
    // Collect active records for this token
    let mut active: Vec<&CashRecord> = records
        .iter()
        .filter(|r| r.token == token && r.status == CASH_ACTIVE)
        .collect();

    if active.is_empty() {
        return CashSelection::Insufficient;
    }

    // 1) Exact match: single cash == total
    if let Some(rec) = active.iter().find(|r| r.amount == total) {
        return CashSelection::Exact(vec![rec.cash_id.clone()]);
    }

    // 2) Combine smaller cash (amount < total), sorted desc, greedy
    let mut smaller: Vec<&CashRecord> = active.iter().copied().filter(|r| r.amount < total).collect();
    smaller.sort_by(|a, b| b.amount.cmp(&a.amount)); // descending
    let mut sum = 0u64;
    let mut picked: Vec<String> = Vec::new();
    for rec in &smaller {
        sum += rec.amount;
        picked.push(rec.cash_id.clone());
        if sum >= total {
            break;
        }
    }
    if sum == total {
        return CashSelection::Exact(picked);
    }
    if sum > total {
        return CashSelection::WithChange {
            cash_ids: picked,
            change_amount: sum - total,
        };
    }

    // 3) Split: smallest cash where amount > total
    active.sort_by_key(|r| r.amount);
    if let Some(rec) = active.iter().find(|r| r.amount > total) {
        return CashSelection::WithChange {
            cash_ids: vec![rec.cash_id.clone()],
            change_amount: rec.amount - total,
        };
    }

    CashSelection::Insufficient
}

/// Derive a deterministic Cash ID from its contents: SHA256(pubkey + token + amount).
pub fn compute_cash_id(pubkey: &str, token: &str, amount: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.as_bytes());
    hasher.update(token.as_bytes());
    hasher.update(amount.as_bytes());
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

// ────────────────────── Order Helpers ──────────────────────

pub fn sort_orders(orders: &mut [Order]) {
    orders.sort_by(|a, b| match (a.price, b.price) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater, // None goes to end
        (Some(_), None) => Ordering::Less,    // Some comes first
        (Some(pa), Some(pb)) => pb.cmp(&pa),  // descending by price
    });
}

// ────────────────────── Genesis Cipher ──────────────────────

/// Compute a deterministic ciphertext for a genesis cash entry.
/// random = SHA256("genesis-random:" + cash_id), always the same for the same cash_id.
/// Returns (ciphertext_hex, random_hex) to be stored in core.toml and alice/bob_cash.json.
pub fn genesis_encrypt(cash_id: &str, amount_plaintext: &str) -> (CipherText, String) {
    let mut hasher = Sha256::new();
    hasher.update(b"genesis-random:");
    hasher.update(cash_id.as_bytes());
    let random_bytes: [u8; 32] = hasher.finalize().into();
    let (cipher, _) = encrypt_with_random(amount_plaintext, random_bytes);
    (cipher, hex::encode(random_bytes))
}

// ────────────────────── Sample Data ──────────────────────

pub fn sample_orders() -> Vec<Order> {
    let make = |trade_type: TradeType, t1: &str, t2: &str, price: u64, amt: &str, status: OrderStatus, idx: u32| {
        let subject = TradePair { token1: t1.into(), token2: t2.into() };
        let amount = encrypt_amount(amt);
        let fake_cash_id = format!("sample-cash-{}", idx);
        let id = compute_order_id(std::slice::from_ref(&fake_cash_id));
        Order { id, trade_type, subject, price: Some(price), amount, pubkey: String::new(), input_cash_ids: vec![fake_cash_id], handling_fee: vec!["0".to_string()], status, match_order: None }
    };

    vec![
        make(TradeType::Buy,  "ETH", "USDT",  3500,  "10", OrderStatus::Pending, 1),
        make(TradeType::Sell, "ETH", "USDT",  3600,   "5", OrderStatus::Pending, 2),
        make(TradeType::Buy,  "BTC", "USDT", 65000,   "2", OrderStatus::Pending, 3),
        make(TradeType::Sell, "BTC", "USDT", 64500,   "1", OrderStatus::Matched, 4),
        make(TradeType::Buy,  "SOL", "USDT",   180,  "50", OrderStatus::Pending, 5),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_genesis_ciphertexts() {
        let entries = [
            ("f8c0ea0222c6acba512cc9ed613b64e3", "ETH",  "1000",   "alice"),
            ("68ff80c3b73a39798be67087fb9f97ed", "USDT", "500000", "alice"),
            ("4e88dd94be4154a37da7dd5b9d06a4a1", "ETH",  "1000",   "bob"),
            ("ddada5eb9484fa322a931d53bb945431", "USDT", "500000", "bob"),
        ];
        for (cash_id, token, amount, who) in entries {
            let (cipher, random) = genesis_encrypt(cash_id, amount);
            println!("{} {} cash_id={} cipher={} random={}", who, token, cash_id, cipher, random);
        }
    }
}
