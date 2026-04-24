use std::collections::HashMap;
use std::sync::Arc;

use invisibook_lib::cash_store::CashStore;
use invisibook_lib::chain::{ChainClient, OrderEvent};
use invisibook_lib::orderbook;
use invisibook_lib::types::*;

use crate::command;

// ────────────────────── Text Input ──────────────────────

pub struct TextInput {
    pub value: String,
    pub cursor: usize,
    pub placeholder: String,
}

// ────────────────────── App Model ──────────────────────

pub struct App {
    pub orders: Vec<Order>,
    pub own_order_ids: HashMap<OrderID, String>, // own order ID -> plain amount
    pub cursor: usize,
    pub expanded: Option<usize>, // None = nothing expanded
    pub input: TextInput,
    pub message: Option<String>,
    pub is_error: bool,
    pub chain_client: Option<Arc<ChainClient>>,
    pub runtime: tokio::runtime::Runtime,
    pub event_rx: Option<std::sync::mpsc::Receiver<OrderEvent>>,
    pub my_address: String,
    pub balances: HashMap<TokenID, usize>, // token -> active cash count
    pub cash_store: CashStore,
}

impl App {
    pub fn new_with(
        chain_orders: Option<Vec<Order>>,
        chain_client: Option<Arc<ChainClient>>,
        runtime: tokio::runtime::Runtime,
        event_rx: Option<std::sync::mpsc::Receiver<OrderEvent>>,
        my_address: String,
        balances: HashMap<TokenID, usize>,
        cash_store: CashStore,
    ) -> Self {
        let mut orders = chain_orders.unwrap_or_else(|| orderbook::sample_orders());
        orderbook::sort_orders(&mut orders);

        App {
            orders,
            own_order_ids: HashMap::new(),
            cursor: 0,
            expanded: None,
            input: TextInput {
                value: String::new(),
                cursor: 0,
                placeholder: "buy/sell {token_1} {price} {amount} {token_2}".into(),
            },
            message: None,
            is_error: false,
            chain_client,
            runtime,
            event_rx,
            my_address,
            balances,
            cash_store,
        }
    }

    /// Drain confirmed orders from the background WS subscription and upsert them.
    pub fn process_chain_events(&mut self) {
        let Some(ref rx) = self.event_rx else { return };
        while let Ok(event) = rx.try_recv() {
            match event {
                OrderEvent::Confirmed(order) => {
                    let id = order.id.clone();
                    if let Some(existing) = self.orders.iter_mut().find(|o| o.id == id) {
                        *existing = order;
                    } else {
                        self.orders.push(order);
                        orderbook::sort_orders(&mut self.orders);
                    }
                    self.message = Some(format!(
                        "✓ Order {} confirmed on chain",
                        &id[..id.len().min(7)]
                    ));
                    self.is_error = false;
                }
                OrderEvent::Error(e) => {
                    self.message = Some(format!("✗ Chain error: {e}"));
                    self.is_error = true;
                }
            }
        }
    }

    // ────────────────────── Navigation ──────────────────────

    pub fn move_cursor_up(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.expanded = None;
        }
    }

    pub fn move_cursor_down(&mut self) {
        if self.cursor < self.orders.len().saturating_sub(1) {
            self.cursor += 1;
            self.expanded = None;
        }
    }

    // ────────────────────── Enter Key ──────────────────────

    pub fn handle_enter(&mut self) {
        let input = self.input.value.trim().to_string();
        if !input.is_empty() {
            command::handle_command(self, &input);
            self.input.value.clear();
            self.input.cursor = 0;
        } else {
            // toggle expand / collapse
            if self.expanded == Some(self.cursor) {
                self.expanded = None;
            } else {
                self.expanded = Some(self.cursor);
            }
        }
    }

    // ────────────────────── Text Input ──────────────────────

    pub fn input_char(&mut self, c: char) {
        self.input.value.insert(self.input.cursor, c);
        self.input.cursor += c.len_utf8();
    }

    pub fn input_backspace(&mut self) {
        if self.input.cursor > 0 {
            let prev = self.input.value[..self.input.cursor]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.input.value.remove(prev);
            self.input.cursor = prev;
        }
    }

    pub fn accept_suggestion(&mut self) {
        let suggestions = command::context_suggestions(&self.input.value);
        if let Some(suggestion) = suggestions.first() {
            self.input.value = suggestion.clone();
            self.input.cursor = self.input.value.len();
        }
    }

    // ────────────────────── Amount Display ──────────────────────

    /// Returns the plain amount for own orders and cipher text (first 7 chars) for others.
    /// Used in the order book list view.
    pub fn display_amount(&self, order: &Order) -> String {
        if let Some(plain_amt) = self.own_order_ids.get(&order.id) {
            return plain_amt.clone();
        }
        let amount = &order.amount;
        if amount.len() > 7 {
            amount[..7].to_string()
        } else {
            amount.clone()
        }
    }

    /// Returns the plain amount for own orders and full cipher text for others.
    /// Used in the expanded detail panel.
    pub fn display_amount_full(&self, order: &Order) -> String {
        if let Some(plain_amt) = self.own_order_ids.get(&order.id) {
            return plain_amt.clone();
        }
        order.amount.clone()
    }
}
