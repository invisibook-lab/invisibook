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

// ────────────────────── CashOutput (for settlement) ──────────────────────

#[derive(Debug, Clone)]
pub struct CashOutput {
    pub pubkey: String, // recipient's ed25519 pubkey (64-char hex)
    pub token: TokenID,
    pub amount: CipherText,
}

// ────────────────────── Account / Cash ──────────────────────

// CashStatus values: 0 = Active, 1 = Locked, 2 = Spent
pub const CASH_ACTIVE: u8 = 0;
pub const CASH_LOCKED: u8 = 1;
pub const CASH_SPENT: u8 = 2;

#[derive(Debug, Clone)]
pub struct CashItem {
    pub id: String,
    pub pubkey: String, // owner's raw ed25519 pubkey (64-char hex)
    pub token: TokenID,
    pub amount: CipherText,
    pub zk_proof: String,
    pub status: u8,
    pub by: String,
}

#[derive(Debug, Clone)]
pub struct AccountRecord {
    pub pubkey: String, // owner's raw ed25519 pubkey (64-char hex)
    pub token: TokenID,
    pub cash: Vec<CashItem>,
}

#[derive(Debug, Clone)]
pub struct ChangeOutput {
    pub pubkey: String, // recipient's ed25519 pubkey (64-char hex)
    pub amount: CipherText,
}

/// Change output attached to a SendOrder when splitting cash.
#[derive(Debug, Clone)]
pub struct CashChange {
    pub cash_id: String,      // client-generated change cash ID
    pub amount: CipherText,   // encrypted change amount
}

// ────────────────────── Order ──────────────────────

#[derive(Debug, Clone)]
pub struct Order {
    pub id: OrderID,
    pub trade_type: TradeType,
    pub subject: TradePair,
    pub price: Option<u64>,
    pub amount: CipherText,
    pub pubkey: String, // owner's ed25519 pubkey (64-char hex)
    pub input_cash_ids: Vec<String>,
    pub handling_fee: Vec<String>,
    pub block_height: u32,
    pub status: OrderStatus,
    pub match_order: Option<OrderID>,
}
