use std::fmt;

// ────────────────────── Type Aliases ──────────────────────

pub type OrderID = String;
pub type TokenID = String;
pub const NATIVE_TOKEN: &str = "invis";

// ────────────────────── TradeType ──────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TradeType {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OrderKind {
    Limit,
    Market,
}

impl fmt::Display for OrderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrderKind::Limit => write!(f, "LIMIT"),
            OrderKind::Market => write!(f, "MARKET"),
        }
    }
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
    Settling,
}

impl fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrderStatus::Pending => write!(f, "Pending"),
            OrderStatus::Matched => write!(f, "Matched"),
            OrderStatus::Done => write!(f, "Done"),
            OrderStatus::Cancelled => write!(f, "Cancelled"),
            OrderStatus::Frozen => write!(f, "Frozen"),
            OrderStatus::Settling => write!(f, "Settling"),
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

// ────────────────────── MPC Share ──────────────────────

// ────────────────────── Order ──────────────────────

#[derive(Debug, Clone)]
pub struct Order {
    pub id: OrderID,
    pub kind: OrderKind,
    pub trade_type: TradeType,
    pub subject: TradePair,
    pub price: Option<u64>,
    pub protection_price: Option<u64>,
    pub execution_price: Option<u64>,
    pub match_round: u64,
    /// Height at which the current match round was created. Unlike the
    /// original block height (time priority), this refreshes on rematch.
    pub match_height: u64,
    pub pubkey: String, // owner's ed25519 pubkey (64-char hex)
    pub locked_commitment: String,
    pub fee: u64,
    pub block_height: u32,
    pub intra_block_index: u32,
    pub status: OrderStatus,
    pub match_order: Option<OrderID>,
}
