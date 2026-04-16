use std::fmt;

// ────────────────────── Type Aliases ──────────────────────

pub type OrderID = String;
pub type CipherText = String;
pub type TokenID = String;

// ────────────────────── TradeType ──────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TradeType {
    Buy,
    Sell,
}

impl fmt::Display for TradeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TradeType::Buy => write!(f, "BUY"),
            TradeType::Sell => write!(f, "SELL"),
        }
    }
}

// ────────────────────── OrderStatus ──────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum OrderStatus {
    Pending,
    Matched,
    Done,
    Cancelled,
    Frozen,
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrderStatus::Pending => write!(f, "Pending"),
            OrderStatus::Matched => write!(f, "Matched"),
            OrderStatus::Done => write!(f, "Done"),
            OrderStatus::Cancelled => write!(f, "Cancelled"),
            OrderStatus::Frozen => write!(f, "Frozen"),
        }
    }
}

// ────────────────────── TradePair ──────────────────────

#[derive(Debug, Clone)]
pub struct TradePair {
    pub token1: TokenID,
    pub token2: TokenID,
}

impl fmt::Display for TradePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.token1, self.token2)
    }
}

// ────────────────────── Order ──────────────────────

#[derive(Debug, Clone)]
pub struct Order {
    pub id: OrderID,
    pub trade_type: TradeType,
    pub subject: TradePair,
    pub price: Option<i64>,
    pub amount: CipherText,
    pub status: OrderStatus,
}
