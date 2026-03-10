use std::collections::HashMap;

use dioxus::prelude::*;

use invisibook_lib::orderbook;
use invisibook_lib::types::*;

/// The order book panel: table header + scrollable order rows.
#[component]
pub fn OrderBook(
    orders: Signal<Vec<Order>>,
    own_order_ids: Signal<HashMap<OrderID, String>>,
    selected: Signal<Option<usize>>,
    expanded: Signal<Option<usize>>,
) -> Element {
    rsx! {
        div { class: "orderbook-panel",
            div { class: "panel-title", "Order Book" }
            div { class: "order-table",
                if orders.read().is_empty() {
                    div { class: "empty-state", "No orders yet" }
                } else {
                    div { class: "table-header",
                        span { class: "col-index", "#" }
                        span { class: "col-id", "Order ID" }
                        span { "Side" }
                        span { "Pair" }
                        span { "Price" }
                        span { class: "col-amount", "Amount" }
                        span { class: "col-status", "Status" }
                    }
                    {render_rows(&orders.read(), &own_order_ids.read(), &selected.read(), &expanded.read(), selected, expanded)}
                }
            }
        }
    }
}

// ────────────────────── Row Rendering ──────────────────────

fn render_rows(
    orders: &[Order],
    own_ids: &HashMap<OrderID, String>,
    selected: &Option<usize>,
    expanded: &Option<usize>,
    mut sel_signal: Signal<Option<usize>>,
    mut exp_signal: Signal<Option<usize>>,
) -> Element {
    rsx! {
        for (i, order) in orders.iter().enumerate() {
            {
                let is_selected = selected.map_or(false, |s| s == i);
                let is_expanded = expanded.map_or(false, |e| e == i);

                let type_class = match order.trade_type {
                    TradeType::Buy => "type-buy",
                    TradeType::Sell => "type-sell",
                };
                let status_class = match order.status {
                    OrderStatus::Pending => "status-pending",
                    OrderStatus::Matched => "status-matched",
                    OrderStatus::Done => "status-done",
                    OrderStatus::Cancelled => "status-cancelled",
                };
                let price_str = match order.price {
                    Some(p) => p.to_string(),
                    None => "-".into(),
                };
                let row_class = if is_selected { "order-row selected" } else { "order-row" };

                let (amt_text, is_own) = if let Some(plain) = own_ids.get(&order.id) {
                    (plain.clone(), true)
                } else {
                    let a = &order.amount;
                    let t = if a.len() > 14 { format!("{}…", &a[..14]) } else { a.clone() };
                    (t, false)
                };
                let amt_class = if is_own { "amount-plain" } else { "amount-cipher" };

                let full_amount = if let Some(plain) = own_ids.get(&order.id) {
                    plain.clone()
                } else {
                    order.amount.clone()
                };

                let order_id = order.id.clone();
                let short_id = orderbook::short_id(&order.id).to_string();
                let type_str = order.trade_type.to_string();
                let pair_str = order.subject.to_string();
                let status_str = order.status.to_string();
                let price_str2 = price_str.clone();

                rsx! {
                    div {
                        key: "{order_id}",
                        class: "{row_class}",
                        onclick: move |_| {
                            sel_signal.set(Some(i));
                            let currently_expanded = exp_signal.read().map_or(false, |e| e == i);
                            if currently_expanded {
                                exp_signal.set(None);
                            } else {
                                exp_signal.set(Some(i));
                            }
                        },
                        span { class: "col-index", "{i + 1}" }
                        span { class: "col-id", "{short_id}" }
                        span { class: "{type_class}", "{type_str}" }
                        span { "{pair_str}" }
                        span { "{price_str}" }
                        span { class: "col-amount {amt_class}", "{amt_text}" }
                        span { class: "col-status {status_class}", "{status_str}" }
                    }
                    if is_expanded {
                        div { class: "detail-panel",
                            span { class: "detail-label", "Order ID" }
                            span { class: "detail-value", "{short_id}" }

                            span { class: "detail-label", "Side" }
                            span { class: "detail-value {type_class}", "{type_str}" }

                            span { class: "detail-label", "Pair" }
                            span { class: "detail-value", "{pair_str}" }

                            span { class: "detail-label", "Price" }
                            span { class: "detail-value", "{price_str2}" }

                            span { class: "detail-label", "Amount" }
                            span { class: "detail-value", "{full_amount}" }

                            span { class: "detail-label", "Status" }
                            span { class: "detail-value {status_class}", "{status_str}" }
                        }
                    }
                }
            }
        }
    }
}
