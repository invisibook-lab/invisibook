use sha2::{Digest, Sha256};
use std::cmp::Ordering;

use crate::types::*;

// ────────────────────── ID Generator ──────────────────────

/// Computes a deterministic order ID by SHA-256-hashing the order's immutable
/// content fields.  The JSON layout must match the Go side exactly:
///   {"type":<int>,"token1":"...","token2":"...","price":"...","amount":"..."}
/// where `type` is 0 for Buy / 1 for Sell, and `price` is an empty string when
/// no price is given.
/// Returns the first 7 characters of an order ID for display purposes.
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(7)]
}

pub fn compute_order_id(
    trade_type: TradeType,
    subject: &TradePair,
    price: Option<i64>,
    amount: &CipherText,
) -> OrderID {
    let type_int = match trade_type {
        TradeType::Buy => 0,
        TradeType::Sell => 1,
    };
    let price_str = match price {
        Some(p) => p.to_string(),
        None => String::new(),
    };
    let json = format!(
        r#"{{"type":{},"token1":"{}","token2":"{}","price":"{}","amount":"{}"}}"#,
        type_int, subject.token1, subject.token2, price_str, amount
    );
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

// ────────────────────── Cipher Mock ──────────────────────

/// Simulates FHE encryption – returns a hex digest.
pub fn mock_cipher_text(plaintext: &str) -> CipherText {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let result = hasher.finalize();
    let hex_str: String = result[..10].iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex_str)
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
