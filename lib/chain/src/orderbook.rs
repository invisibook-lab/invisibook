use rand::RngCore;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

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

/// Core implementation: returns (ciphertext, amount_u64, random_bytes).
/// chain stores amount = poseidon(amount_plaintext, random);
/// plaintext and random must be kept off-chain by the client.
fn encrypt_amount_inner(plaintext: &str) -> (CipherText, u64, [u8; 32]) {
    let amount: u64 = plaintext.parse().unwrap_or(0);
    let mut random_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);

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
            return (hex, amount, random_bytes);
        }
    }

    // Android fallback: SHA-256(amount || random)
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hasher.update(random_bytes);
    let cipher = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
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

// ────────────────────── Order Helpers ──────────────────────

pub fn sort_orders(orders: &mut [Order]) {
    orders.sort_by(|a, b| match (a.price, b.price) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater, // None goes to end
        (Some(_), None) => Ordering::Less,    // Some comes first
        (Some(pa), Some(pb)) => pb.cmp(&pa),  // descending by price
    });
}

// ────────────────────── Sample Data ──────────────────────

pub fn sample_orders() -> Vec<Order> {
    let make = |trade_type: TradeType, t1: &str, t2: &str, price: u64, amt: &str, status: OrderStatus, idx: u32| {
        let subject = TradePair { token1: t1.into(), token2: t2.into() };
        let amount = encrypt_amount(amt);
        let fake_cash_id = format!("sample-cash-{}", idx);
        let id = compute_order_id(std::slice::from_ref(&fake_cash_id));
        Order { id, trade_type, subject, price: Some(price), amount, owner: String::new(), input_cash_ids: vec![fake_cash_id], handling_fee: vec!["0".to_string()], status, match_order: None }
    };

    vec![
        make(TradeType::Buy,  "ETH", "USDT",  3500,  "10", OrderStatus::Pending, 1),
        make(TradeType::Sell, "ETH", "USDT",  3600,   "5", OrderStatus::Pending, 2),
        make(TradeType::Buy,  "BTC", "USDT", 65000,   "2", OrderStatus::Pending, 3),
        make(TradeType::Sell, "BTC", "USDT", 64500,   "1", OrderStatus::Matched, 4),
        make(TradeType::Buy,  "SOL", "USDT",   180,  "50", OrderStatus::Pending, 5),
    ]
}
