use std::collections::HashMap;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;

use invisibook_lib::orderbook;
use invisibook_lib::types::*;

// ────────────────────── Token List ──────────────────────

const TOKENS: &[&str] = &["ETH", "BTC", "SOL", "USDT", "USDC", "DAI"];

// ────────────────────── CSS ──────────────────────

const CSS: &str = r#"
:root {
    --green: #0ecb81;
    --green-hover: #0bb374;
    --red: #f6465d;
    --red-hover: #d93a50;
    --white: #eaecef;
    --text-secondary: #848e9c;
    --text-third: #5e6673;
    --gold: #f0b90b;
    --bg: #0b0e11;
    --bg-card: #1e2329;
    --bg-input: #2b3139;
    --bg-hover: #2b3139;
    --border: #2b3139;
    --purple: #7D56F4;
    --purple-light: #9B7BF7;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--white);
    height: 100vh;
    overflow: hidden;
    user-select: none;
}

.app {
    display: flex;
    flex-direction: column;
    height: 100vh;
}

/* ── Header ── */
.header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
}

.header-logo {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1.5px;
    color: var(--gold);
}

.header-pair {
    font-size: 14px;
    color: var(--text-secondary);
}

/* ── Main Layout ── */
.main {
    display: flex;
    flex: 1;
    min-height: 0;
}

/* ── Order Book (left) ── */
.orderbook-panel {
    flex: 1;
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    min-width: 0;
}

.panel-title {
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    background: var(--bg-card);
}

.order-table {
    flex: 1;
    overflow-y: auto;
    background: var(--bg);
}

.table-header {
    display: grid;
    grid-template-columns: 40px 90px 60px 110px 90px 1fr 70px;
    gap: 4px;
    padding: 8px 12px;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-third);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg-card);
    z-index: 1;
}

.order-row {
    display: grid;
    grid-template-columns: 40px 90px 60px 110px 90px 1fr 70px;
    gap: 4px;
    padding: 6px 12px;
    font-size: 12px;
    cursor: pointer;
    border-bottom: 1px solid rgba(43, 49, 57, 0.5);
    transition: background 0.1s;
    align-items: center;
}

.order-row:hover { background: var(--bg-hover); }

.order-row.selected {
    background: var(--bg-hover);
    border-left: 2px solid var(--gold);
    padding-left: 10px;
}

.type-buy  { color: var(--green); font-weight: 600; }
.type-sell { color: var(--red);   font-weight: 600; }

.status-pending   { color: var(--gold); }
.status-matched   { color: var(--green); }
.status-done      { color: var(--text-third); }
.status-cancelled { color: var(--red); }

.amount-cipher {
    font-size: 11px;
    color: var(--text-third);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: 'SF Mono', 'Fira Code', monospace;
}

.amount-plain {
    font-size: 12px;
    color: var(--gold);
    font-weight: 600;
}

/* ── Detail Panel ── */
.detail-panel {
    grid-column: 1 / -1;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 16px;
    margin: 4px 12px;
    background: var(--bg-card);
    display: grid;
    grid-template-columns: 80px 1fr;
    gap: 6px 12px;
    font-size: 12px;
    animation: slideDown 0.12s ease-out;
}

@keyframes slideDown {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
}

.detail-label {
    color: var(--text-secondary);
    text-align: right;
}

.detail-value {
    color: var(--white);
    word-break: break-all;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 11px;
}

/* ── Trade Panel (right) ── */
.trade-panel {
    width: 320px;
    min-width: 320px;
    display: flex;
    flex-direction: column;
    background: var(--bg-card);
}

/* ── Buy / Sell Tabs ── */
.side-tabs {
    display: flex;
}

.side-tab {
    flex: 1;
    padding: 12px;
    font-size: 14px;
    font-weight: 700;
    text-align: center;
    cursor: pointer;
    border: none;
    font-family: inherit;
    transition: all 0.15s;
    color: var(--text-secondary);
    background: var(--bg);
    border-bottom: 2px solid transparent;
}

.side-tab:hover { color: var(--white); }

.side-tab.buy-active {
    color: var(--green);
    background: var(--bg-card);
    border-bottom: 2px solid var(--green);
}

.side-tab.sell-active {
    color: var(--red);
    background: var(--bg-card);
    border-bottom: 2px solid var(--red);
}

/* ── Form Body ── */
.trade-form {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 16px;
    gap: 12px;
}

/* ── Pair Selector ── */
.pair-row {
    display: flex;
    align-items: center;
    gap: 8px;
}

.pair-select {
    flex: 1;
    background: var(--bg-input);
    color: var(--white);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 10px;
    font-family: inherit;
    font-size: 13px;
    cursor: pointer;
    outline: none;
    appearance: auto;
}

.pair-select:focus { border-color: var(--gold); }

.pair-select option { background: var(--bg-card); color: var(--white); }

.pair-slash {
    font-size: 16px;
    font-weight: 700;
    color: var(--text-third);
}

/* ── Input Group ── */
.input-group {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.input-label {
    font-size: 12px;
    color: var(--text-secondary);
}

.input-wrapper {
    display: flex;
    align-items: center;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
    transition: border-color 0.15s;
}

.input-wrapper:focus-within { border-color: var(--gold); }

.input-field {
    flex: 1;
    background: transparent;
    color: var(--white);
    border: none;
    padding: 10px 12px;
    font-family: inherit;
    font-size: 14px;
    outline: none;
    min-width: 0;
}

.input-field::placeholder { color: var(--text-third); }

/* Hide number input arrows */
.input-field::-webkit-inner-spin-button,
.input-field::-webkit-outer-spin-button {
    -webkit-appearance: none;
    margin: 0;
}
.input-field[type="number"] {
    -moz-appearance: textfield;
}

.input-suffix {
    padding: 0 12px;
    font-size: 13px;
    color: var(--text-secondary);
    font-weight: 600;
    white-space: nowrap;
}

/* ── Total ── */
.total-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
}

.total-label {
    font-size: 12px;
    color: var(--text-secondary);
}

.total-value {
    font-size: 13px;
    font-weight: 600;
    color: var(--white);
}

/* ── Submit Button ── */
.submit-btn {
    padding: 12px;
    border: none;
    border-radius: 4px;
    font-family: inherit;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.15s;
    letter-spacing: 0.3px;
    margin-top: auto;
}

.submit-btn.buy {
    background: var(--green);
    color: #fff;
}
.submit-btn.buy:hover { background: var(--green-hover); }

.submit-btn.sell {
    background: var(--red);
    color: #fff;
}
.submit-btn.sell:hover { background: var(--red-hover); }

.submit-btn:disabled {
    opacity: 0.35;
    cursor: not-allowed;
}

/* ── Status Toast ── */
.toast {
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    padding: 10px 24px;
    border-radius: 4px;
    font-size: 13px;
    font-weight: 600;
    z-index: 100;
    animation: fadeInUp 0.2s ease-out;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
}

.toast.success {
    background: rgba(14, 203, 129, 0.15);
    color: var(--green);
    border: 1px solid var(--green);
}

.toast.error {
    background: rgba(246, 70, 93, 0.15);
    color: var(--red);
    border: 1px solid var(--red);
}

@keyframes fadeInUp {
    from { opacity: 0; transform: translateX(-50%) translateY(8px); }
    to   { opacity: 1; transform: translateX(-50%) translateY(0); }
}

/* ── Empty State ── */
.empty-state {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-third);
    font-size: 13px;
}

/* ── Scrollbar ── */
.order-table::-webkit-scrollbar { width: 4px; }
.order-table::-webkit-scrollbar-track { background: transparent; }
.order-table::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.order-table::-webkit-scrollbar-thumb:hover { background: var(--text-third); }
"#;

// ────────────────────── Entry Point ──────────────────────

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new()
                .with_window(
                    WindowBuilder::new()
                        .with_title("Invisibook")
                        .with_inner_size(LogicalSize::new(1060.0, 720.0))
                        .with_min_inner_size(LogicalSize::new(860.0, 520.0)),
                )
                .with_disable_context_menu(true),
        )
        .launch(App);
}

// ────────────────────── App Root ──────────────────────

#[component]
fn App() -> Element {
    // ── Order book state ──
    let mut orders = use_signal(|| {
        let mut o = orderbook::sample_orders();
        orderbook::sort_orders(&mut o);
        o
    });
    let mut own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let mut expanded = use_signal(|| None::<usize>);
    let mut message = use_signal(|| None::<(String, bool)>); // (msg, is_error)

    // ── Form state ──
    let mut side = use_signal(|| TradeType::Buy);
    let mut token1 = use_signal(|| "ETH".to_string());
    let mut token2 = use_signal(|| "USDT".to_string());
    let mut price_input = use_signal(String::new);
    let mut amount_input = use_signal(String::new);

    // ── Derived values ──
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

    let can_submit = price_val > 0.0 && amount_val > 0.0;

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
                message.set(Some(("✗ Amount must be a positive integer!".into(), true)));
                return;
            }
        };

        let trade_type = *side.read();
        let t1 = token1.read().clone();
        let t2 = token2.read().clone();

        let order = Order {
            id: orderbook::next_order_id(),
            trade_type,
            subject: TradePair {
                token1: t1.clone(),
                token2: t2.clone(),
            },
            price: Some(price),
            amount: orderbook::mock_cipher_text(&amount_str),
            status: OrderStatus::Pending,
        };

        let order_id = order.id.clone();
        orders.write().push(order);
        own_order_ids.write().insert(order_id, amount_str.clone());
        orderbook::sort_orders(&mut orders.write());
        expanded.set(None);

        message.set(Some((
            format!(
                "✓ {} {}/{} price {} amount {}",
                trade_type, t1, t2, price_str, amount_str
            ),
            false,
        )));

        price_input.set(String::new());
        amount_input.set(String::new());
    };

    rsx! {
        style { {CSS} }
        div { class: "app",

            // ── Header ──
            div { class: "header",
                span { class: "header-logo", "INVISIBOOK" }
                span { class: "header-pair", "{t1_display}/{t2_display}" }
            }

            // ── Main: Order Book + Trade Panel ──
            div { class: "main",

                // ── Left: Order Book ──
                div { class: "orderbook-panel",
                    div { class: "panel-title", "Order Book" }
                    div { class: "order-table",
                        if orders.read().is_empty() {
                            div { class: "empty-state", "No orders yet" }
                        } else {
                            div { class: "table-header",
                                span { "#" }
                                span { "Order ID" }
                                span { "Side" }
                                span { "Pair" }
                                span { "Price" }
                                span { "Amount" }
                                span { "Status" }
                            }
                            {render_order_rows(&orders.read(), &own_order_ids.read(), &selected.read(), &expanded.read(), selected, expanded)}
                        }
                    }
                }

                // ── Right: Trade Panel ──
                div { class: "trade-panel",

                    // ── Buy / Sell Tabs ──
                    div { class: "side-tabs",
                        button {
                            class: if current_side == TradeType::Buy { "side-tab buy-active" } else { "side-tab" },
                            onclick: move |_| side.set(TradeType::Buy),
                            "Buy"
                        }
                        button {
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
                            class: if current_side == TradeType::Buy { "submit-btn buy" } else { "submit-btn sell" },
                            disabled: !can_submit,
                            onclick: on_submit,
                            if current_side == TradeType::Buy {
                                "Buy {t1_display}"
                            } else {
                                "Sell {t1_display}"
                            }
                        }
                    }
                }
            }

            // ── Toast Message ──
            if let Some((ref msg, ref is_err)) = *message.read() {
                div {
                    class: if *is_err { "toast error" } else { "toast success" },
                    "{msg}"
                }
            }
        }
    }
}

// ────────────────────── Order Rows Render ──────────────────────

fn render_order_rows(
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
                        span { "{i + 1}" }
                        span { "{order_id}" }
                        span { class: "{type_class}", "{type_str}" }
                        span { "{pair_str}" }
                        span { "{price_str}" }
                        span { class: "{amt_class}", "{amt_text}" }
                        span { class: "{status_class}", "{status_str}" }
                    }
                    if is_expanded {
                        div { class: "detail-panel",
                            span { class: "detail-label", "Order ID" }
                            span { class: "detail-value", "{order_id}" }

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
