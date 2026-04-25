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

    // ── Balance from CashStore: (token, active_amount, locked_amount) ──
    // Group all local cash records by token and sum amounts by status.
    let (active_entries, locked_entries): (Vec<(String, u64)>, Vec<(String, u64)>) = {
        let store = cash_store.read();
        let mut map: HashMap<String, (u64, u64)> = HashMap::new();
        for rec in store.records() {
            let entry = map.entry(rec.token.clone()).or_default();
            if rec.status == CASH_ACTIVE {
                entry.0 += rec.amount;
            } else if rec.status == CASH_LOCKED {
                entry.1 += rec.amount;
            }
        }
        let mut pairs: Vec<(String, u64, u64)> =
            map.into_iter().map(|(t, (a, l))| (t, a, l)).collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let active = pairs.iter().filter(|(_, a, _)| *a > 0).map(|(t, a, _)| (t.clone(), *a)).collect();
        let locked = pairs.iter().filter(|(_, _, l)| *l > 0).map(|(t, _, l)| (t.clone(), *l)).collect();
        (active, locked)
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

        // Compute total: Buy → price * amount (token2); Sell → amount (token1)
        let total: u64 = if trade_type == TradeType::Buy {
            price * _amount
        } else {
            _amount
        };

        let pubkey = my_address.read().clone();

        // Smart cash selection
        let (input_cash_ids, cash_change) = {
            let store = cash_store.read();
            match orderbook::select_cash(store.records(), &input_token, total) {
                orderbook::CashSelection::Exact(ids) => (ids, None),
                orderbook::CashSelection::WithChange { cash_ids, change_amount } => {
                    let (change_cipher, _change_amt, change_random) =
                        orderbook::encrypt_amount_with_info(&change_amount.to_string());
                    let change_cash_id = orderbook::compute_cash_id(&pubkey, &input_token, &change_cipher);
                    let change = CashChange {
                        cash_id: change_cash_id.clone(),
                        amount: change_cipher,
                    };
                    (cash_ids, Some((change, change_cash_id, change_amount, _change_amt, change_random)))
                }
                orderbook::CashSelection::Insufficient => {
                    message.set(Some((format!("✗ Insufficient {} balance (need {})", input_token, total), true)));
                    return;
                }
            }
        };

        let order_id = orderbook::compute_order_id(&input_cash_ids);

        let subject = TradePair {
            token1: t1.clone(),
            token2: t2.clone(),
        };
        let amount = orderbook::encrypt_amount(&amount_str);

        let order = Order {
            id: order_id,
            trade_type,
            subject,
            price: Some(price),
            amount,
            pubkey,
            input_cash_ids: input_cash_ids.clone(),
            handling_fee: vec![fee.clone()],
            block_height: 0,
            status: OrderStatus::Pending,
            match_order: None,
        };

        let client = chain_client.read().clone();

        let Some(client) = client else {
            message.set(Some(("✗ Not connected to chain".into(), true)));
            return;
        };

        // Extract change info for the async block
        let change_ref = cash_change.as_ref().map(|(c, _, _, _, _)| c.clone());

        submitting.set(true);
        let amount_str_clone = amount_str.clone();
        spawn(async move {
            match client.send_order(&order, change_ref.as_ref()).await {
                Ok(()) => {
                    own_order_ids
                        .write()
                        .insert(order.id.clone(), amount_str_clone);
                    expanded.set(None);

                    // Update CashStore: mark originals as Spent, add change record
                    if let Some((_, change_cash_id, change_amount, _, change_random)) = cash_change {
                        let mut store = cash_store.write();
                        for rec in store.records_mut().iter_mut() {
                            if input_cash_ids.contains(&rec.cash_id) {
                                rec.status = CASH_SPENT;
                            }
                        }
                        store.records_mut().push(invisibook_lib::cash_store::CashRecord {
                            cash_id: change_cash_id,
                            token: input_token.clone(),
                            amount: change_amount,
                            random: change_random,
                            status: CASH_ACTIVE,
                        });
                        let _ = store.flush();
                    }

                    message.set(Some((
                        format!("✓ {} {}/{} order submitted", trade_type, t1, t2),
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
                    if active_entries.is_empty() {
                        div { class: "balance-row",
                            span { class: "balance-none", "—" }
                        }
                    } else {
                        for (token, active) in active_entries.iter() {
                            div { key: "active-{token}", class: "balance-row",
                                span { class: "balance-token", "{token}" }
                                span { class: "balance-value balance-ok", "{active}" }
                            }
                        }
                    }
                }

                // Locked Token
                div { class: "balance-section",
                    span { class: "balance-header", "Locked Token" }
                    if locked_entries.is_empty() {
                        div { class: "balance-row",
                            span { class: "balance-none", "—" }
                        }
                    } else {
                        for (token, locked) in locked_entries.iter() {
                            div { key: "locked-{token}", class: "balance-row",
                                span { class: "balance-token", "{token}" }
                                span { class: "balance-value balance-locked", "{locked}" }
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
