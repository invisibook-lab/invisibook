use std::collections::HashMap;
use std::sync::Arc;

use dioxus::prelude::*;

use invisibook_lib::chain::ChainClient;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;

use crate::constants::TOKENS;

/// The trade panel: Buy/Sell tabs, pair selector, price/amount inputs, submit.
#[component]
pub fn TradeForm(
    orders: Signal<Vec<Order>>,
    own_order_ids: Signal<HashMap<OrderID, String>>,
    expanded: Signal<Option<usize>>,
    message: Signal<Option<(String, bool)>>,
    chain_client: Signal<Option<Arc<ChainClient>>>,
    my_address: Signal<String>,
) -> Element {
    // ── Form state ──
    let mut side = use_signal(|| TradeType::Buy);
    let mut token1 = use_signal(|| "ETH".to_string());
    let mut token2 = use_signal(|| "USDT".to_string());
    let mut price_input = use_signal(String::new);
    let mut amount_input = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    // ── Derived ──
    let current_side = *side.read();
    let t1_display = token1.read().clone();
    let t2_display = token2.read().clone();

    let price_val: f64 = price_input.read().parse().unwrap_or(0.0);
    let amount_val: f64 = amount_input.read().parse().unwrap_or(0.0);
    let total = price_val * amount_val;
    let total_str = if total > 0.0 {
        format!("{:.2} {}", total, t2_display)
    } else {
        format!("-- {}", t2_display)
    };

    let is_submitting = *submitting.read();
    let can_submit = price_val > 0.0 && amount_val > 0.0 && !is_submitting;

    // ── Submit handler ──
    let on_submit = move |_| {
        let price_str = price_input.read().clone();
        let price: i64 = match price_str.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                message.set(Some(("✗ Price must be a positive integer!".into(), true)));
                return;
            }
        };

        let amount_str = amount_input.read().clone();
        let _amount: i64 = match amount_str.parse() {
            Ok(a) if a > 0 => a,
            _ => {
                message.set(Some((
                    "✗ Amount must be a positive integer!".into(),
                    true,
                )));
                return;
            }
        };

        let trade_type = *side.read();
        let t1 = token1.read().clone();
        let t2 = token2.read().clone();

        let subject = TradePair {
            token1: t1.clone(),
            token2: t2.clone(),
        };
        let amount = orderbook::encrypt_amount(&amount_str);
        let owner = my_address.read().clone();

        let order = Order {
            id: String::new(),
            trade_type,
            subject,
            price: Some(price),
            amount,
            owner,
            input_cash_ids: Vec::new(),
            handling_fee: vec!["0".to_string()],
            status: OrderStatus::Pending,
            match_order: None,
        };

        let client = chain_client.read().clone();

        if let Some(client) = client {
            // Async send to chain
            submitting.set(true);
            let amount_str_clone = amount_str.clone();
            spawn(async move {
                match client.send_order(&order).await {
                    Ok(()) => {
                        let order_id = order.id.clone();
                        {
                            let mut o = orders.write();
                            o.push(order);
                            orderbook::sort_orders(&mut *o);
                        }
                        own_order_ids
                            .write()
                            .insert(order_id, amount_str_clone);
                        expanded.set(None);
                        message.set(Some((
                            format!(
                                "✓ {} {}/{} price {} amount {}",
                                trade_type, t1, t2, price_str, amount_str
                            ),
                            false,
                        )));
                    }
                    Err(e) => {
                        message.set(Some((format!("✗ Send order failed: {}", e), true)));
                    }
                }
                submitting.set(false);
            });
        } else {
            // No chain client — local only
            let order_id = order.id.clone();
            {
                let mut o = orders.write();
                o.push(order);
                orderbook::sort_orders(&mut *o);
            }
            own_order_ids
                .write()
                .insert(order_id, amount_str.clone());
            expanded.set(None);
            message.set(Some((
                format!(
                    "✓ {} {}/{} price {} amount {} (local)",
                    trade_type, t1, t2, price_str, amount_str
                ),
                false,
            )));
        }

        price_input.set(String::new());
        amount_input.set(String::new());
    };

    rsx! {
        div { class: "trade-panel",

            // ── Buy / Sell Tabs ──
            div { class: "side-tabs",
                div {
                    class: if current_side == TradeType::Buy { "side-tab buy-active" } else { "side-tab" },
                    onclick: move |_| side.set(TradeType::Buy),
                    "Buy"
                }
                div {
                    class: if current_side == TradeType::Sell { "side-tab sell-active" } else { "side-tab" },
                    onclick: move |_| side.set(TradeType::Sell),
                    "Sell"
                }
            }

            // ── Form ──
            div { class: "trade-form",

                // Pair selector
                div { class: "pair-row",
                    select {
                        class: "pair-select",
                        value: "{token1}",
                        onchange: move |evt: Event<FormData>| token1.set(evt.value()),
                        for t in TOKENS.iter() {
                            option { value: *t, "{t}" }
                        }
                    }
                    span { class: "pair-slash", "/" }
                    select {
                        class: "pair-select",
                        value: "{token2}",
                        onchange: move |evt: Event<FormData>| token2.set(evt.value()),
                        for t in TOKENS.iter() {
                            option { value: *t, "{t}" }
                        }
                    }
                }

                // Price
                div { class: "input-group",
                    span { class: "input-label", "Price" }
                    div { class: "input-wrapper",
                        input {
                            class: "input-field",
                            r#type: "number",
                            min: "1",
                            placeholder: "0",
                            value: "{price_input}",
                            oninput: move |evt: Event<FormData>| price_input.set(evt.value()),
                        }
                        span { class: "input-suffix", "{t2_display}" }
                    }
                }

                // Amount
                div { class: "input-group",
                    span { class: "input-label", "Amount" }
                    div { class: "input-wrapper",
                        input {
                            class: "input-field",
                            r#type: "number",
                            min: "1",
                            placeholder: "0",
                            value: "{amount_input}",
                            oninput: move |evt: Event<FormData>| amount_input.set(evt.value()),
                        }
                        span { class: "input-suffix", "{t1_display}" }
                    }
                }

                // Total
                div { class: "total-row",
                    span { class: "total-label", "Total" }
                    span { class: "total-value", "{total_str}" }
                }

                // Submit
                button {
                    r#type: "button",
                    class: if current_side == TradeType::Buy { "submit-btn buy" } else { "submit-btn sell" },
                    disabled: !can_submit,
                    onclick: on_submit,
                    if is_submitting {
                        "Submitting..."
                    } else if current_side == TradeType::Buy {
                        "Buy {t1_display}"
                    } else {
                        "Sell {t1_display}"
                    }
                }
            }
        }
    }
}
