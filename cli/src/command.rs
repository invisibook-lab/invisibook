use crate::model::App;
use crate::orderbook;
use crate::types::*;

// ────────────────────── Suggestion Pools ──────────────────────

const ACTION_SUGGESTIONS: &[&str] = &["buy", "sell"];
const TOKEN_SUGGESTIONS: &[&str] = &["ETH", "BTC", "SOL", "USDT", "USDC", "DAI"];

// ────────────────────── Command Handling ──────────────────────
// Syntax: buy/sell {token_1} {price} {amount} {token_2}

pub fn handle_command(app: &mut App, input: &str) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() != 5 {
        app.message = Some(
            "✗ Invalid format! Usage: buy/sell {token_1} {price} {amount} {token_2}".into(),
        );
        app.is_error = true;
        return;
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
            app.message = Some("✗ Unknown action! Please use buy or sell".into());
            app.is_error = true;
            return;
        }
    };

    // validate price is a positive integer
    let price: i64 = match price_str.parse() {
        Ok(p) if p > 0 => p,
        _ => {
            app.message = Some("✗ price must be a positive integer!".into());
            app.is_error = true;
            return;
        }
    };

    // validate amount is a positive integer
    let _amount: i64 = match amount_str.parse() {
        Ok(a) if a > 0 => a,
        _ => {
            app.message = Some("✗ amount must be a positive integer!".into());
            app.is_error = true;
            return;
        }
    };

    let order = Order {
        id: orderbook::next_order_id(),
        trade_type,
        subject: TradePair {
            token1: token1.clone(),
            token2: token2.clone(),
        },
        price: Some(price),
        amount: orderbook::mock_cipher_text(amount_str),
        status: OrderStatus::Pending,
    };

    let order_id = order.id.clone();
    app.orders.push(order);
    app.own_order_ids
        .insert(order_id, amount_str.to_string()); // track own order with plain amount
    orderbook::sort_orders(&mut app.orders);

    let type_name = match trade_type {
        TradeType::Buy => "BUY",
        TradeType::Sell => "SELL",
    };
    app.message = Some(format!(
        "✓ Order created: {} {}/{} price {} amount {}",
        type_name, token1, token2, price_str, amount_str
    ));
    app.is_error = false;
    app.expanded = None;
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
