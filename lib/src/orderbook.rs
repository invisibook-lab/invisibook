use sha2::{Digest, Sha256};
use std::cmp::Ordering;

use crate::types::*;

// ────────────────────── ID Generator ──────────────────────

/// Returns the first 7 characters of an order ID for display purposes.
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(7)]
}

/// Computes a deterministic order ID using Poseidon(BN254) over five field elements:
///   [type, price, token1, token2, amount]
/// where string fields are reduced via SHA-256 mod BN254r (Fr::from_be_bytes_mod_order).
/// Must match the Go side ComputeOrderID in chain/core/order.go.
///
/// Android fallback: SHA-256 over a fixed JSON string (ark-ff SIGSEGV workaround).
pub fn compute_order_id(
    trade_type: TradeType,
    subject: &TradePair,
    price: Option<i64>,
    amount: &CipherText,
) -> OrderID {
    #[cfg(not(target_os = "android"))]
    {
        use ark_bn254::Fr;
        use ark_ff::{BigInteger, PrimeField};
        use light_poseidon::{Poseidon, PoseidonHasher};

        fn str_to_fr(s: &str) -> Fr {
            let mut h = Sha256::new();
            h.update(s.as_bytes());
            Fr::from_be_bytes_mod_order(&h.finalize())
        }

        let result = (|| -> Option<String> {
            let type_fr = Fr::from(match trade_type {
                TradeType::Buy => 0u64,
                TradeType::Sell => 1u64,
            });
            let price_fr = Fr::from(price.unwrap_or(0) as u64);
            let token1_fr = str_to_fr(&subject.token1);
            let token2_fr = str_to_fr(&subject.token2);
            let amount_fr = str_to_fr(amount);

            let mut hasher = Poseidon::<Fr>::new_circom(5).ok()?;
            let hash = hasher
                .hash(&[type_fr, price_fr, token1_fr, token2_fr, amount_fr])
                .ok()?;
            let bytes = hash.into_bigint().to_bytes_be();
            Some(bytes.iter().map(|b| format!("{:02x}", b)).collect())
        })();

        if let Some(id) = result {
            return id;
        }
    }

    // Android fallback: SHA-256 over JSON (ark-ff SIGSEGV workaround).
    let type_int = match trade_type {
        TradeType::Buy => 0,
        TradeType::Sell => 1,
    };
    let price_str = price.map(|p| p.to_string()).unwrap_or_default();
    let json = format!(
        r#"{{"type":{},"token1":"{}","token2":"{}","price":"{}","amount":"{}"}}"#,
        type_int, subject.token1, subject.token2, price_str, amount
    );
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

// ────────────────────── Cipher Mock ──────────────────────

/// Simulates FHE encryption – hashes the plaintext amount.
/// Uses Poseidon (BN254) on desktop; falls back to SHA-256 on Android (arm64
/// ark-ff SIGSEGV workaround).
pub fn mock_cipher_text(plaintext: &str) -> CipherText {
    #[cfg(not(target_os = "android"))]
    {
        use ark_bn254::Fr;
        use ark_ff::{BigInteger, PrimeField};
        use light_poseidon::{Poseidon, PoseidonHasher};

        let amount: u64 = plaintext.parse().unwrap_or(0);
        let result = (|| -> Option<String> {
            let mut hasher = Poseidon::<Fr>::new_circom(1).ok()?;
            let hash = hasher.hash(&[Fr::from(amount)]).ok()?;
            let bytes = hash.into_bigint().to_bytes_be();
            Some(bytes.iter().map(|b| format!("{:02x}", b)).collect())
        })();

        if let Some(hex) = result {
            return format!("0x{}", hex);
        }
    }

    // Android (and Poseidon fallback): use SHA-256
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let bytes = hasher.finalize();
    format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
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
    let make = |trade_type: TradeType, t1: &str, t2: &str, price: i64, amt: &str, status: OrderStatus| {
        let subject = TradePair { token1: t1.into(), token2: t2.into() };
        let amount = mock_cipher_text(amt);
        let id = compute_order_id(trade_type, &subject, Some(price), &amount);
        Order { id, trade_type, subject, price: Some(price), amount, status }
    };

    vec![
        make(TradeType::Buy,  "ETH", "USDT",  3500,  "10", OrderStatus::Pending),
        make(TradeType::Sell, "ETH", "USDT",  3600,   "5", OrderStatus::Pending),
        make(TradeType::Buy,  "BTC", "USDT", 65000,   "2", OrderStatus::Pending),
        make(TradeType::Sell, "BTC", "USDT", 64500,   "1", OrderStatus::Matched),
        make(TradeType::Buy,  "SOL", "USDT",   180,  "50", OrderStatus::Pending),
    ]
}
