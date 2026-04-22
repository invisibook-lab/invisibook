use std::collections::HashMap;
use std::sync::Arc;

use dioxus::prelude::*;

use invisibook_lib::cash_store::CashStore;
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
    cash_store: Signal<CashStore>,
) -> Element {
    // ── Form state ──
    let mut side = use_signal(|| TradeType::Buy);
    let mut token1 = use_signal(|| "ETH".to_string());
    let mut token2 = use_signal(|| "USDT".to_string());
    let mut price_input = use_signal(String::new);
    let mut amount_input = use_signal(String::new);
    let mut fee_input = use_signal(|| "1".to_string());
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

    // ── Balance from CashStore: (token, active_count, locked_count) ──
    // Group all local cash records by token and count by status.
    let balances_data: Vec<(String, usize, usize)> = {
        let store = cash_store.read();
        let mut map: HashMap<String, (usize, usize)> = HashMap::new();
        for rec in store.records() {
            let entry = map.entry(rec.token.clone()).or_default();
            if rec.status == CASH_ACTIVE {
                entry.0 += 1;
            } else if rec.status == CASH_LOCKED {
                entry.1 += 1;
            }
        }
        let mut result: Vec<_> = map.into_iter().map(|(t, (a, l))| (t, a, l)).collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    };

    // ── Submit handler ──
    let on_submit = move |_| {
        let price_str = price_input.read().clone();
        let price: u64 = match price_str.parse() {
            Ok(p) if p > 0 => p,
            _ => {
                message.set(Some(("✗ Price must be a positive integer!".into(), true)));
                return;
            }
        };

        let amount_str = amount_input.read().clone();
        let _amount: u64 = match amount_str.parse() {
            Ok(a) if a > 0 => a,
            _ => {
                message.set(Some((
                    "✗ Amount must be a positive integer!".into(),
                    true,
                )));
                return;
            }
        };

        let fee_str = fee_input.read().clone();
        let fee = if fee_str.trim().is_empty() { "1".to_string() } else { fee_str };

        let trade_type = *side.read();
        let t1 = token1.read().clone();
        let t2 = token2.read().clone();

        // Buy → pays with token2; Sell → spends token1
        let input_token = if trade_type == TradeType::Buy { t2.clone() } else { t1.clone() };

        // Collect active cash IDs for the input token from the local CashStore
        let input_cash_ids: Vec<String> = {
            let store = cash_store.read();
            store
                .records()
                .iter()
                .filter(|r| r.token == input_token && r.status == CASH_ACTIVE)
                .map(|r| r.cash_id.clone())
                .collect()
        };

        if input_cash_ids.is_empty() {
            message.set(Some((format!("✗ No active {} cash available", input_token), true)));
            return;
        }

        let order_id = orderbook::compute_order_id(&input_cash_ids);

        let subject = TradePair {
            token1: t1.clone(),
            token2: t2.clone(),
        };
        let amount = orderbook::encrypt_amount(&amount_str);
        let owner = my_address.read().clone();

        let order = Order {
            id: order_id,
            trade_type,
            subject,
            price: Some(price),
            amount,
            owner,
            input_cash_ids,
            handling_fee: vec![fee.clone()],
            status: OrderStatus::Pending,
            match_order: None,
        };

        let client = chain_client.read().clone();

        let Some(client) = client else {
            message.set(Some(("✗ Not connected to chain".into(), true)));
            return;
        };

        submitting.set(true);
        let amount_str_clone = amount_str.clone();
        spawn(async move {
            match client.send_order(&order).await {
                Ok(()) => {
                    own_order_ids
                        .write()
                        .insert(order.id.clone(), amount_str_clone);
                    expanded.set(None);
                    message.set(Some((
                        format!("⏳ {} {}/{} submitting to chain...", trade_type, t1, t2),
                        false,
                    )));
                }
                Err(e) => {
                    message.set(Some((format!("✗ Send order failed: {e}"), true)));
                }
            }
            submitting.set(false);
        });

        price_input.set(String::new());
        amount_input.set(String::new());
        fee_input.set("1".to_string());
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

                // Handling Fee
                div { class: "input-group",
                    span { class: "input-label", "Fee" }
                    div { class: "input-wrapper",
                        input {
                            class: "input-field",
                            r#type: "number",
                            min: "0",
                            placeholder: "1",
                            value: "{fee_input}",
                            oninput: move |evt: Event<FormData>| fee_input.set(evt.value()),
                        }
                    }
                }

                // Total
                div { class: "total-row",
                    span { class: "total-label", "Total" }
                    span { class: "total-value", "{total_str}" }
                }

                // Active Token
                div { class: "balance-section",
                    span { class: "balance-header", "Active Token" }
                    if balances_data.is_empty() {
                        div { class: "balance-row",
                            span { class: "balance-none", "—" }
                        }
                    } else {
                        for (token, active, _locked) in balances_data.iter() {
                            div { key: "active-{token}", class: "balance-row",
                                span { class: "balance-token", "{token}" }
                                span {
                                    class: if *active > 0 { "balance-value balance-ok" } else { "balance-value balance-none" },
                                    "{active} cash"
                                }
                            }
                        }
                    }
                }

                // Locked Token
                div { class: "balance-section",
                    span { class: "balance-header", "Locked Token" }
                    if balances_data.is_empty() {
                        div { class: "balance-row",
                            span { class: "balance-none", "—" }
                        }
                    } else {
                        for (token, _active, locked) in balances_data.iter() {
                            div { key: "locked-{token}", class: "balance-row",
                                span { class: "balance-token", "{token}" }
                                span {
                                    class: if *locked > 0 { "balance-value balance-locked" } else { "balance-value balance-none" },
                                    "{locked} cash"
                                }
                            }
                        }
                    }
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
