use std::collections::HashMap;
use std::sync::Arc;

use dioxus::prelude::*;

use invisibook_lib::cash_store::{CashRecord, CashStore};
use invisibook_lib::chain::ChainClient;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;
#[cfg(not(target_os = "android"))]
use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{SplitWitness, prove_split},
};

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

        // Smart cash selection — also collect CashRecords for split proof.
        let (input_cash_ids, input_records, cash_change) = {
            let store = cash_store.read();
            match orderbook::select_cash(store.records(), &input_token, total) {
                orderbook::CashSelection::Exact(ids) => {
                    let recs: Vec<CashRecord> = store
                        .records()
                        .iter()
                        .filter(|r| ids.contains(&r.cash_id))
                        .cloned()
                        .collect();
                    (ids, recs, None)
                }
                orderbook::CashSelection::WithChange { cash_ids, change_amount } => {
                    let recs: Vec<CashRecord> = store
                        .records()
                        .iter()
                        .filter(|r| cash_ids.contains(&r.cash_id))
                        .cloned()
                        .collect();
                    let (change_cipher, _change_amt, change_random) =
                        orderbook::encrypt_amount_with_info(&change_amount.to_string());
                    let change_cash_id = orderbook::compute_cash_id(&pubkey, &input_token, &change_cipher);
                    let change = CashChange {
                        cash_id: change_cash_id.clone(),
                        amount: change_cipher,
                    };
                    (cash_ids, recs, Some((change, change_cash_id, change_amount, _change_amt, change_random)))
                }
                orderbook::CashSelection::Insufficient => {
                    eprintln!("[trade] insufficient {} balance (need {})", input_token, total);
                    message.set(Some((format!("✗ Insufficient {} balance (need {})", input_token, total), true)));
                    return;
                }
            }
        };

        if input_records.len() > 2 {
            message.set(Some(("✗ Split circuit caps at 2 inputs — please consolidate first".into(), true)));
            return;
        }

        let order_id = orderbook::compute_order_id(&input_cash_ids);

        let subject = TradePair {
            token1: t1.clone(),
            token2: t2.clone(),
        };
        // Build the locked-amount commitment and remember its random for the
        // split proof witness.
        let (locked_cipher, _, locked_random_hex) =
            orderbook::encrypt_amount_with_info(&amount_str);

        let order = Order {
            id: order_id,
            trade_type,
            subject,
            price: Some(price),
            amount: locked_cipher.clone(),
            pubkey: pubkey.clone(),
            input_cash_ids: input_cash_ids.clone(),
            handling_fee: vec![fee.clone()],
            block_height: 0,
            status: OrderStatus::Pending,
            match_order: None,
            is_smaller: false,
        };

        let client = chain_client.read().clone();

        let Some(client) = client else {
            message.set(Some(("✗ Not connected to chain".into(), true)));
            return;
        };

        // Generate split proof if we have a change output.
        #[cfg(not(target_os = "android"))]
        let (change_ref, split_proof) = if let Some((ref change, _, change_amount, _, ref change_random_hex)) = cash_change {
            let proof = match generate_split_proof(
                &input_records,
                _amount,
                &locked_random_hex,
                change_amount,
                change_random_hex,
            ) {
                Ok(p) => {
                    eprintln!("[trade] split proof generated successfully");
                    p
                }
                Err(e) => {
                    eprintln!("[trade] split proof failed: {e}");
                    message.set(Some((format!("✗ Split proof failed: {e}"), true)));
                    return;
                }
            };
            (Some(change.clone()), Some(proof))
        } else {
            (None, None)
        };
        #[cfg(target_os = "android")]
        let (change_ref, split_proof): (Option<CashChange>, Option<String>) = {
            let cr = cash_change.as_ref().map(|(c, _, _, _, _)| c.clone());
            (cr, None)
        };

        submitting.set(true);
        let amount_str_clone = amount_str.clone();
        spawn(async move {
            match client.send_order(&order, change_ref.as_ref(), split_proof).await {
                Ok(()) => {
                    eprintln!("[trade] order submitted successfully: {}", order.id);
                    own_order_ids
                        .write()
                        .insert(order.id.clone(), amount_str_clone);
                    expanded.set(None);

                    // Update CashStore: mark originals as Spent, add change record.
                    if let Some((_, change_cash_id, change_amount, _, change_random)) = cash_change {
                        let mut store = cash_store.write();
                        for rec in store.records_mut().iter_mut() {
                            if input_cash_ids.contains(&rec.cash_id) {
                                rec.status = CASH_SPENT;
                            }
                        }
                        store.records_mut().push(CashRecord {
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
                    eprintln!("[trade] send order failed: {e}");
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

/// Generate a split ZK proof from input cash records, locked amount, and change amount.
/// Returns the proof JSON string on success.
#[cfg(not(target_os = "android"))]
fn generate_split_proof(
    input_records: &[CashRecord],
    locked_amount: u64,
    locked_random_hex: &str,
    change_amount: u64,
    change_random_hex: &str,
) -> Result<String, String> {
    let setup = dev_setup_snarkjs("split")
        .map_err(|e| format!("split circuit setup: {e}"))?;
    let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir)
        .map_err(|e| format!("loading compiled circuit: {e}"))?;

    let mut inputs_for_witness = Vec::with_capacity(input_records.len());
    for rec in input_records {
        let raw = hex::decode(&rec.random)
            .map_err(|e| format!("cash {} random hex invalid: {e}", rec.cash_id))?;
        if raw.len() != 32 {
            return Err(format!("cash {} random must be 32 bytes, got {}", rec.cash_id, raw.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        inputs_for_witness.push((rec.amount, arr));
    }

    let locked_random = decode_random_bytes(locked_random_hex)?;
    let change_random = decode_random_bytes(change_random_hex)?;

    let sp = prove_split(
        SplitWitness {
            inputs: inputs_for_witness,
            locked_amount,
            locked_random,
            change_amount,
            change_random,
        },
        &handle,
        &setup.zkey,
    )
    .map_err(|e| format!("prove_split: {e}"))?;

    serde_json::to_string(&sp.proof_json).map_err(|e| format!("serialize proof: {e}"))
}

/// Decode a hex string into a 32-byte array.
#[cfg(not(target_os = "android"))]
fn decode_random_bytes(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
