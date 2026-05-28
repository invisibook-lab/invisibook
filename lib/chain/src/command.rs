use crate::{orderbook, types::*};

// ────────────────────── Suggestion Pools ──────────────────────

const ACTION_SUGGESTIONS: &[&str] = &["buy", "sell"];
const TOKEN_SUGGESTIONS: &[&str] = &["ETH", "BTC", "SOL", "USDT", "USDC", "DAI"];

// ────────────────────── Command Result ──────────────────────

pub struct CommandResult {
    pub order: Option<Order>,
    pub plain_amount: Option<String>,
    /// 32-byte hex blinding factor for the locked-amount commitment in `order.amount`.
    /// `Some` when an order was successfully constructed (so the caller can later
    /// open the locked Cash for split / settle proofs); `None` on parse errors.
    pub locked_random: Option<String>,
    pub message: String,
    pub is_error: bool,
}

// ────────────────────── Command Handling ──────────────────────
// Syntax: buy/sell {token_1} {price} {amount} {token_2}

pub fn parse_command(input: &str) -> CommandResult {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() != 5 {
        return CommandResult {
            order: None,
            plain_amount: None,
            locked_random: None,
            message: "✗ Invalid format! Usage: buy/sell {token_1} {price} {amount} {token_2}"
                .into(),
            is_error: true,
        };
    }

    let action = parts[0].to_lowercase();
    let token1 = parts[1].to_uppercase();
    let price_str = parts[2];
    let amount_str = parts[3];
    let token2 = parts[4].to_uppercase();

    // validate action
    let trade_type = match action.as_str() {
        "buy" => TradeType::Buy,
        "sell" => TradeType::Sell,
        _ => {
            return CommandResult {
                order: None,
                plain_amount: None,
                locked_random: None,
                message: "✗ Unknown action! Please use buy or sell".into(),
                is_error: true,
            };
        }
    };

    // validate price is a positive integer
    let price: u64 = match price_str.parse() {
        Ok(p) if p > 0 => p,
        _ => {
            return CommandResult {
                order: None,
                plain_amount: None,
                locked_random: None,
                message: "✗ price must be a positive integer!".into(),
                is_error: true,
            };
        }
    };

    // validate amount is a positive integer
    let _amount: u64 = match amount_str.parse() {
        Ok(a) if a > 0 => a,
        _ => {
            return CommandResult {
                order: None,
                plain_amount: None,
                locked_random: None,
                message: "✗ amount must be a positive integer!".into(),
                is_error: true,
            };
        }
    };

    let subject = TradePair {
        token1: token1.clone(),
        token2: token2.clone(),
    };
    // Persist the random alongside the commitment so the wallet can later open
    // this Cash for split / settle proofs. Throwing the random away (the
    // previous `encrypt_amount` call did) made the locked Cash unspendable.
    let (amount, _, locked_random) = orderbook::encrypt_amount_with_info(amount_str);

    // NOTE: order ID and input_cash_ids will be set when the order is
    // actually submitted with real cash. For local preview we use a placeholder.
    let order = Order {
        id: String::new(),
        trade_type,
        subject,
        price: Some(price),
        amount,
        pubkey: String::new(),
        input_cash_ids: Vec::new(),
        handling_fee: vec!["0".to_string()],
        block_height: 0,
        status: OrderStatus::Pending,
        match_order: None,
        is_smaller: false,
    };

    let type_name = match trade_type {
        TradeType::Buy => "BUY",
        TradeType::Sell => "SELL",
    };

    CommandResult {
        order: Some(order),
        plain_amount: Some(amount_str.to_string()),
        locked_random: Some(locked_random),
        message: format!(
            "✓ Order created: {} {}/{} price {} amount {}",
            type_name, token1, token2, price_str, amount_str
        ),
        is_error: false,
    }
}

// ────────────────────── Context Suggestions ──────────────────────
//
//   pos 0 (action):  buy / sell
//   pos 1 (token_1): token names
//   pos 2 (price):   no suggestions (user types a number)
//   pos 3 (amount):  no suggestions (user types a number)
//   pos 4 (token_2): token names

pub fn context_suggestions(value: &str) -> Vec<String> {
    let parts: Vec<&str> = value.split(' ').collect();
    let pos = parts.len().saturating_sub(1); // index of the word being typed

    let prefix = if pos > 0 {
        let mut p = parts[..pos].join(" ");
        p.push(' ');
        p
    } else {
        String::new()
    };

    let pool: &[&str] = match pos {
        0 => ACTION_SUGGESTIONS,
        1 | 4 => TOKEN_SUGGESTIONS,
        _ => return Vec::new(), // numbers – no suggestions
    };

    pool.iter()
        .map(|s| format!("{}{}", prefix, s))
        .filter(|s| s.starts_with(value))
        .collect()
}
