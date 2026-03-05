use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};

use crate::types::*;

// ────────────────────── ID Generator ──────────────────────

static ORDER_SEQ: AtomicI64 = AtomicI64::new(100); // sample orders use 0001‑0005

pub fn next_order_id() -> OrderID {
    let id = ORDER_SEQ.fetch_add(1, AtomicOrdering::SeqCst) + 1;
    format!("ord-{:04}", id)
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
    vec![
        Order {
            id: "ord-0001".into(),
            trade_type: TradeType::Buy,
            subject: TradePair {
                token1: "ETH".into(),
                token2: "USDT".into(),
            },
            price: Some(3500),
            amount: mock_cipher_text("10"),
            status: OrderStatus::Pending,
        },
        Order {
            id: "ord-0002".into(),
            trade_type: TradeType::Sell,
            subject: TradePair {
                token1: "ETH".into(),
                token2: "USDT".into(),
            },
            price: Some(3600),
            amount: mock_cipher_text("5"),
            status: OrderStatus::Pending,
        },
        Order {
            id: "ord-0003".into(),
            trade_type: TradeType::Buy,
            subject: TradePair {
                token1: "BTC".into(),
                token2: "USDT".into(),
            },
            price: Some(65000),
            amount: mock_cipher_text("2"),
            status: OrderStatus::Pending,
        },
        Order {
            id: "ord-0004".into(),
            trade_type: TradeType::Sell,
            subject: TradePair {
                token1: "BTC".into(),
                token2: "USDT".into(),
            },
            price: Some(64500),
            amount: mock_cipher_text("1"),
            status: OrderStatus::Matched,
        },
        Order {
            id: "ord-0005".into(),
            trade_type: TradeType::Buy,
            subject: TradePair {
                token1: "SOL".into(),
                token2: "USDT".into(),
            },
            price: Some(180),
            amount: mock_cipher_text("50"),
            status: OrderStatus::Pending,
        },
    ]
}
