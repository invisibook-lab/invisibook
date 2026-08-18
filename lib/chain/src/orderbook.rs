use sha2::{Digest, Sha256};
use std::cmp::Ordering;

use crate::types::*;

// ────────────────────── ID Generator ──────────────────────

/// Returns the first 7 characters of an order ID for display purposes.
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(7)]
}

/// Computes a deterministic order ID by SHA-256 hashing the concatenation
/// of the input nullifiers. Must match the Go side ComputeOrderID.
pub fn compute_order_id(input_nullifiers: &[String]) -> OrderID {
    let mut hasher = Sha256::new();
    for id in input_nullifiers {
        hasher.update(id.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

// ────────────────────── Order Helpers ──────────────────────

/// Orders a matched pair deterministically, mirroring Go `makerTakerOrder`
/// (chain/core/orderbook_cozk.go): the maker is the order with the lower
/// `block_height`; on a tie, the lower intra-block index; then the
/// lexicographically smaller `id`. Returns `(maker, taker)`.
pub fn maker_taker<'a>(x: &'a Order, y: &'a Order) -> (&'a Order, &'a Order) {
    if x.block_height < y.block_height {
        return (x, y);
    }
    if y.block_height < x.block_height {
        return (y, x);
    }
    if x.intra_block_index < y.intra_block_index {
        return (x, y);
    }
    if y.intra_block_index < x.intra_block_index {
        return (y, x);
    }
    if x.id <= y.id {
        return (x, y);
    }
    (y, x)
}

pub fn sort_orders(orders: &mut [Order]) {
    orders.sort_by(|a, b| match (a.kind, b.kind) {
        (OrderKind::Market, OrderKind::Limit) => Ordering::Less,
        (OrderKind::Limit, OrderKind::Market) => Ordering::Greater,
        _ => match (a.price, b.price) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater, // None goes to end
            (Some(_), None) => Ordering::Less,    // Some comes first
            (Some(pa), Some(pb)) => pb.cmp(&pa),  // descending by price
        },
    });
}

// ────────────────────── Sample Data ──────────────────────

pub fn sample_orders() -> Vec<Order> {
    let make = |trade_type: TradeType,
                t1: &str,
                t2: &str,
                price: u64,
                amt: &str,
                status: OrderStatus,
                idx: u32| {
        let subject = TradePair {
            token1: t1.into(),
            token2: t2.into(),
        };
        // Display-only placeholder commitment (samples never touch a chain).
        let mut h = Sha256::new();
        h.update(b"sample-cm:");
        h.update(amt.as_bytes());
        let locked: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        let fake_nf = format!("sample-nf-{}", idx);
        let id = compute_order_id(std::slice::from_ref(&fake_nf));
        Order {
            id,
            kind: OrderKind::Limit,
            trade_type,
            subject,
            price: Some(price),
            protection_price: None,
            execution_price: None,
            match_round: 0,
            pubkey: String::new(),
            locked_commitment: locked,
            fee: 0,
            block_height: 0,
            intra_block_index: 0,
            status,
            match_order: None,
        }
    };

    vec![
        make(
            TradeType::Buy,
            "ETH",
            "USDT",
            3500,
            "10",
            OrderStatus::Pending,
            1,
        ),
        make(
            TradeType::Sell,
            "ETH",
            "USDT",
            3600,
            "5",
            OrderStatus::Pending,
            2,
        ),
        make(
            TradeType::Buy,
            "BTC",
            "USDT",
            65000,
            "2",
            OrderStatus::Pending,
            3,
        ),
        make(
            TradeType::Sell,
            "BTC",
            "USDT",
            64500,
            "1",
            OrderStatus::Matched,
            4,
        ),
        make(
            TradeType::Buy,
            "SOL",
            "USDT",
            180,
            "50",
            OrderStatus::Pending,
            5,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal Order with the given id, block height, and a tag
    /// stored in `pubkey` so tests can tell the two arguments apart.
    fn test_order(id: &str, block_height: u32, tag: &str) -> Order {
        Order {
            id: id.to_string(),
            kind: OrderKind::Limit,
            trade_type: TradeType::Buy,
            subject: TradePair {
                token1: "ETH".into(),
                token2: "USDT".into(),
            },
            price: None,
            protection_price: None,
            execution_price: None,
            match_round: 0,
            pubkey: tag.to_string(),
            locked_commitment: String::new(),
            fee: 0,
            block_height,
            intra_block_index: 0,
            status: OrderStatus::Pending,
            match_order: None,
        }
    }

    /// The order with the lower block height is the maker, regardless of
    /// argument order.
    #[test]
    fn maker_taker_lower_height_wins() {
        let early = test_order("bbb", 5, "early");
        let late = test_order("aaa", 9, "late");

        let (maker, taker) = maker_taker(&early, &late);
        assert_eq!(maker.pubkey, "early");
        assert_eq!(taker.pubkey, "late");

        let (maker, taker) = maker_taker(&late, &early);
        assert_eq!(maker.pubkey, "early");
        assert_eq!(taker.pubkey, "late");
    }

    /// On equal heights the lexicographically smaller id is the maker,
    /// regardless of argument order.
    #[test]
    fn maker_taker_equal_height_smaller_id_wins() {
        let small_id = test_order("aaa", 7, "small");
        let big_id = test_order("bbb", 7, "big");

        let (maker, taker) = maker_taker(&small_id, &big_id);
        assert_eq!(maker.pubkey, "small");
        assert_eq!(taker.pubkey, "big");

        let (maker, taker) = maker_taker(&big_id, &small_id);
        assert_eq!(maker.pubkey, "small");
        assert_eq!(taker.pubkey, "big");
    }

    /// Degenerate case: equal height and equal id — the first argument is
    /// the maker (id <= other.id).
    #[test]
    fn maker_taker_equal_height_equal_id_first_arg_wins() {
        let x = test_order("same", 3, "x");
        let y = test_order("same", 3, "y");

        let (maker, taker) = maker_taker(&x, &y);
        assert_eq!(maker.pubkey, "x");
        assert_eq!(taker.pubkey, "y");
    }
}
