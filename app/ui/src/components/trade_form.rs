use std::{collections::HashMap, sync::Arc};

use dioxus::prelude::*;

use invisibook_lib::{
    chain::ChainClient,
    note_store::{NOTE_PENDING_MINT, NOTE_PENDING_SPEND, NOTE_UNSPENT, NoteStore},
    order_store::OrderStore,
    types::*,
};

#[cfg(not(target_os = "android"))]
use invisibook_lib::{
    chain::{SendOrderParams, SubmitError, TradePairJson},
    note::{asset_id, fr_from_be_bytes, note_fr_to_hex, npk_from_sk, send_order_bind},
    note_prover::{SendOrderWitness, SpendSlot, checked_required_collateral, prove_send_order},
    note_store::NoteRecord,
    note_tree::NoteTree,
    order_store::OrderOpening,
    orderbook,
};

use crate::constants::TOKENS;

/// Everything the send-order prover produces before submission: the wire
/// request plus the records the wallet must persist FIRST. Public so the
/// headless e2e test drives the exact production order path.
#[cfg(not(target_os = "android"))]
pub struct PreparedOrder {
    pub params: SendOrderParams,
    pub opening: OrderOpening,
    /// (cm, nullifier) per spent input note (marks them pending-spend).
    pub spent: Vec<(String, String)>,
    /// Non-zero collateral/native-fee change notes to track.
    pub changes: Vec<NoteRecord>,
}

#[cfg(not(target_os = "android"))]
fn spend_slots(tree: &NoteTree, notes: &[NoteRecord]) -> Result<[SpendSlot; 2], String> {
    if notes.len() > 2 {
        return Err("send_order supports at most two notes per asset".into());
    }
    let mut slots = Vec::new();
    for rec in notes {
        let sk_raw = hex::decode(&rec.sk).map_err(|e| format!("note sk hex: {e}"))?;
        let sk_arr: [u8; 32] = sk_raw
            .try_into()
            .map_err(|_| "note sk must be 32 bytes".to_string())?;
        let r_raw = hex::decode(&rec.r).map_err(|e| format!("note r hex: {e}"))?;
        let r_arr: [u8; 32] = r_raw
            .try_into()
            .map_err(|_| "note r must be 32 bytes".to_string())?;
        let (path, bits) = tree.path(rec.leaf_index);
        slots.push(SpendSlot::real(
            fr_from_be_bytes(&sk_arr),
            rec.amount,
            fr_from_be_bytes(&r_arr),
            path,
            bits,
        ));
    }
    while slots.len() < 2 {
        slots.push(SpendSlot::dummy());
    }
    Ok(slots.try_into().expect("exactly two slots"))
}

/// Build the complete SendOrder request from selected notes: spend slots
/// with Merkle paths, fresh (collateral, change) commitments, the bind,
/// and the rapidsnark proof. Pure CPU — call from a blocking context.
/// Each note bank contains at most two notes. For non-native collateral the
/// fee bank must consist of `invis` notes. For native collateral the
/// collateral bank funds both lock and fee and the fee bank is empty.
#[cfg(not(target_os = "android"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_order(
    chain_id: u64,
    tree: &NoteTree,
    collateral_notes: &[NoteRecord],
    fee_notes: &[NoteRecord],
    lock_token: &str,
    subject: (String, String),
    trade_type: TradeType,
    kind: OrderKind,
    collateral_price: u64,
    q: u64,
    fee: u64,
) -> Result<PreparedOrder, String> {
    use rand::RngCore;

    let side_sell = trade_type == TradeType::Sell;
    let lock_asset = asset_id(lock_token)?;
    let native_asset = asset_id(NATIVE_TOKEN)?;
    let collateral = checked_required_collateral(q, collateral_price, side_sell)
        .ok_or("required collateral exceeds 64 bits")?;
    let checked_sum = |notes: &[NoteRecord], bank: &str| {
        notes.iter().try_fold(0u64, |sum, note| {
            sum.checked_add(note.amount)
                .ok_or_else(|| format!("{bank} note total exceeds 64 bits"))
        })
    };
    let collateral_in = checked_sum(collateral_notes, "collateral")?;
    let fee_in = checked_sum(fee_notes, "fee")?;
    let (v_collateral_change, v_fee_change) = if lock_token == NATIVE_TOKEN {
        if !fee_notes.is_empty() {
            return Err("native collateral orders must use one combined note bank".into());
        }
        let total_required = collateral
            .checked_add(fee)
            .ok_or("collateral plus fee exceeds 64 bits")?;
        (
            collateral_in
                .checked_sub(total_required)
                .ok_or("selected invis notes do not cover collateral + fee")?,
            0,
        )
    } else {
        (
            collateral_in
                .checked_sub(collateral)
                .ok_or("selected notes do not cover collateral")?,
            fee_in
                .checked_sub(fee)
                .ok_or("selected invis notes do not cover fee")?,
        )
    };
    let collateral_slots = spend_slots(tree, collateral_notes)?;
    let fee_slots = spend_slots(tree, fee_notes)?;

    // Nullifiers determine the order id (SHA-256 over nf0 || nf1).
    let collateral_nf = [
        note_fr_to_hex(&collateral_slots[0].nullifier(lock_asset)),
        note_fr_to_hex(&collateral_slots[1].nullifier(lock_asset)),
    ];
    let fee_nf = [
        note_fr_to_hex(&fee_slots[0].nullifier(native_asset)),
        note_fr_to_hex(&fee_slots[1].nullifier(native_asset)),
    ];
    let all_nf = [
        collateral_nf[0].clone(),
        collateral_nf[1].clone(),
        fee_nf[0].clone(),
        fee_nf[1].clone(),
    ];
    let order_id = orderbook::compute_order_id(&all_nf);

    // Fresh blindings + a fresh change-note spending secret.
    let mut rng = rand::rng();
    let mut draw = || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    };
    let (r_locked, r_coll_change, coll_change_sk, r_fee_change, fee_change_sk) =
        (draw(), draw(), draw(), draw(), draw());

    let w = SendOrderWitness {
        collateral_slots,
        fee_slots,
        anchor: tree.root(),
        lock_asset,
        native_asset,
        q,
        r_locked: fr_from_be_bytes(&r_locked),
        price: collateral_price,
        side_sell,
        fee,
        npk_collateral_change: npk_from_sk(fr_from_be_bytes(&coll_change_sk)),
        v_collateral_change,
        r_collateral_change: fr_from_be_bytes(&r_coll_change),
        npk_fee_change: npk_from_sk(fr_from_be_bytes(&fee_change_sk)),
        v_fee_change,
        r_fee_change: fr_from_be_bytes(&r_fee_change),
        bind: fr_from_be_bytes(&[0u8; 32]),
    };
    let (locked_cm, cm_coll_change, cm_fee_change) = w.output_commitments();
    let mut w = w;
    w.bind = send_order_bind(
        chain_id,
        &order_id,
        if kind == OrderKind::Market { 1 } else { 0 },
        if side_sell { 1 } else { 0 },
        &subject.0,
        &subject.1,
        collateral_price,
        lock_token,
        &collateral_nf[0],
        &collateral_nf[1],
        &fee_nf[0],
        &fee_nf[1],
        &note_fr_to_hex(&locked_cm),
        fee,
        &note_fr_to_hex(&cm_coll_change),
        &note_fr_to_hex(&cm_fee_change),
    );

    let setup =
        zk::setup::dev_setup_snarkjs("send_order").map_err(|e| format!("send_order setup: {e}"))?;
    let handle = zk::test_circuit::TestCircuitHandle::from_compiled(&setup.circuit_dir)
        .map_err(|e| format!("circuit handle: {e}"))?;
    let proof = prove_send_order(w, &handle, &setup.zkey).map_err(|e| format!("prove: {e}"))?;

    let params = SendOrderParams {
        id: order_id.clone(),
        kind: if kind == OrderKind::Market { 1 } else { 0 },
        trade_type: if side_sell { 1 } else { 0 },
        subject: TradePairJson {
            token1: subject.0,
            token2: subject.1,
        },
        price: (kind == OrderKind::Limit).then_some(collateral_price),
        protection_price: (kind == OrderKind::Market).then_some(collateral_price),
        pubkey: String::new(),    // filled by ChainClient::send_order
        signature: String::new(), // filled by ChainClient::send_order
        anchor: note_fr_to_hex(&tree.root()),
        collateral_nullifiers: proof.collateral_nf_hex.to_vec(),
        fee_nullifiers: proof.fee_nf_hex.to_vec(),
        locked_commitment: proof.locked_commitment_hex.clone(),
        fee,
        collateral_change_commitment: proof.cm_collateral_change_hex.clone(),
        fee_change_commitment: proof.cm_fee_change_hex.clone(),
        zk_proof: serde_json::to_string(&proof.proof_json).map_err(|e| e.to_string())?,
    };
    let opening = OrderOpening {
        order_id,
        q,
        locked_amount: collateral,
        r_locked: hex::encode(r_locked),
        lock_token: lock_token.to_string(),
    };
    let mut spent: Vec<_> = collateral_notes
        .iter()
        .zip(proof.collateral_nf_hex.iter())
        .map(|(rec, nf)| (rec.cm.clone(), nf.clone()))
        .collect();
    spent.extend(
        fee_notes
            .iter()
            .zip(proof.fee_nf_hex.iter())
            .map(|(rec, nf)| (rec.cm.clone(), nf.clone())),
    );
    let mut changes = Vec::new();
    if v_collateral_change > 0 {
        changes.push(NoteRecord {
            cm: proof.cm_collateral_change_hex.clone(),
            token: lock_token.to_string(),
            amount: v_collateral_change,
            r: hex::encode(r_coll_change),
            key_index: 0,
            sk: hex::encode(coll_change_sk),
            leaf_index: 0,
            status: NOTE_PENDING_MINT,
            nf: String::new(),
            pending_order: opening.order_id.clone(),
        });
    }
    if v_fee_change > 0 {
        changes.push(NoteRecord {
            cm: proof.cm_fee_change_hex.clone(),
            token: NATIVE_TOKEN.to_string(),
            amount: v_fee_change,
            r: hex::encode(r_fee_change),
            key_index: 0,
            sk: hex::encode(fee_change_sk),
            leaf_index: 0,
            status: NOTE_PENDING_MINT,
            nf: String::new(),
            pending_order: opening.order_id.clone(),
        });
    }
    Ok(PreparedOrder {
        params,
        opening,
        spent,
        changes,
    })
}

/// Persist the wallet records of a prepared order BEFORE submission
/// (persist-before-publish): inputs become PENDING_SPEND carrying their
/// nullifiers and the pending order id, the change note joins as
/// PENDING_MINT, and the order opening is saved. A crash after this point
/// loses nothing the chain will later assume the wallet knows.
#[cfg(not(target_os = "android"))]
pub fn persist_prepared(
    notes: &mut NoteStore,
    orders: &mut OrderStore,
    prepared: &PreparedOrder,
) -> Result<(), String> {
    for (cm, nf) in &prepared.spent {
        if let Some(rec) = notes.find_mut(cm) {
            rec.status = NOTE_PENDING_SPEND;
            rec.nf = nf.clone();
            rec.pending_order = prepared.opening.order_id.clone();
        }
    }
    for change in &prepared.changes {
        notes.upsert(change.clone());
    }
    notes.save().map_err(|e| format!("saving notes: {e}"))?;
    orders.upsert(prepared.opening.clone());
    orders
        .save()
        .map_err(|e| format!("saving order opening: {e}"))
}

/// Roll the wallet records of a submission back: inputs return to UNSPENT,
/// the change note and the order opening are dropped. ONLY legal when the
/// chain PROVABLY did not accept the transaction (an explicit rejection or
/// a completed reconciliation) — see `apply_submit_failure`.
#[cfg(not(target_os = "android"))]
pub fn rollback_prepared(notes: &mut NoteStore, orders: &mut OrderStore, prepared: &PreparedOrder) {
    for (cm, _) in &prepared.spent {
        if let Some(rec) = notes.find_mut(cm) {
            rec.status = NOTE_UNSPENT;
            rec.nf = String::new();
            rec.pending_order = String::new();
        }
    }
    for change in &prepared.changes {
        let cm = change.cm.clone();
        notes.retain(|r| r.cm != cm);
    }
    let _ = notes.save();
    orders.remove(&prepared.opening.order_id);
    let _ = orders.save();
}

/// React to a submission failure per its classification. Returns true when
/// the records were rolled back (definite rejection); an UNCERTAIN outcome
/// keeps every record — the transaction may still land, and the poller's
/// reconciliation decides later.
#[cfg(not(target_os = "android"))]
pub fn apply_submit_failure(
    notes: &mut NoteStore,
    orders: &mut OrderStore,
    prepared: &PreparedOrder,
    err: &SubmitError,
) -> bool {
    match err {
        SubmitError::Rejected(_) => {
            rollback_prepared(notes, orders, prepared);
            true
        }
        SubmitError::Uncertain(_) => false,
    }
}

/// The trade panel: Buy/Sell tabs, pair selector, price/amount inputs, submit.
#[component]
pub fn TradeForm(
    orders: Signal<Vec<Order>>,
    own_order_ids: Signal<HashMap<OrderID, String>>,
    expanded: Signal<Option<usize>>,
    message: Signal<Option<(String, bool)>>,
    chain_client: Signal<Option<Arc<ChainClient>>>,
    my_address: Signal<String>,
    note_store: Signal<NoteStore>,
    order_store: Signal<OrderStore>,
) -> Element {
    // ── Form state ──
    let mut side = use_signal(|| TradeType::Buy);
    let mut order_kind = use_signal(|| OrderKind::Limit);
    let mut token1 = use_signal(|| "ETH".to_string());
    let mut token2 = use_signal(|| "USDT".to_string());
    let mut price_input = use_signal(String::new);
    let mut amount_input = use_signal(String::new);
    let mut fee_input = use_signal(|| "1".to_string());
    let mut submitting = use_signal(|| false);

    // ── Derived ──
    let current_side = *side.read();
    let current_kind = *order_kind.read();
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

    // ── Balances: spendable per token (notes) + locked per token (open
    //    orders' collateral openings) ──
    let (active_entries, locked_entries): (Vec<(String, u64)>, Vec<(String, u64)>) = {
        let mut active: HashMap<String, u64> = HashMap::new();
        for rec in note_store.read().records() {
            if rec.status == NOTE_UNSPENT || rec.status == NOTE_PENDING_MINT {
                *active.entry(rec.token.clone()).or_default() += rec.amount;
            }
        }
        let mut locked: HashMap<String, u64> = HashMap::new();
        for o in order_store.read().records() {
            *locked.entry(o.lock_token.clone()).or_default() += o.locked_amount;
        }
        let to_sorted = |m: HashMap<String, u64>| {
            let mut v: Vec<(String, u64)> = m.into_iter().filter(|(_, a)| *a > 0).collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v
        };
        (to_sorted(active), to_sorted(locked))
    };

    // ── Submit handler ──
    let on_submit = move |_| {
        let price: u64 = match price_input.read().parse() {
            Ok(p) if p > 0 => p,
            _ => {
                message.set(Some(("✗ Price must be a positive integer!".into(), true)));
                return;
            }
        };
        let q: u64 = match amount_input.read().parse() {
            Ok(a) if a > 0 => a,
            _ => {
                message.set(Some(("✗ Amount must be a positive integer!".into(), true)));
                return;
            }
        };
        let fee: u64 = {
            let s = fee_input.read().trim().to_string();
            if s.is_empty() {
                1
            } else {
                match s.parse() {
                    Ok(f) => f,
                    Err(_) => {
                        message.set(Some(("✗ Fee must be a non-negative integer!".into(), true)));
                        return;
                    }
                }
            }
        };

        let trade_type = *side.read();
        let kind = *order_kind.read();
        let t1 = token1.read().clone();
        let t2 = token2.read().clone();

        #[cfg(target_os = "android")]
        {
            let _ = (price, q, fee, trade_type, kind, &t1, &t2);
            message.set(Some((
                "✗ On-device order proving is not supported on mobile yet".into(),
                true,
            )));
        }

        #[cfg(not(target_os = "android"))]
        {
            // Buy → locks token2 (q·price); Sell → locks token1 (q).
            let lock_token = if trade_type == TradeType::Buy {
                t2.clone()
            } else {
                t1.clone()
            };
            let Some(collateral) =
                checked_required_collateral(q, price, trade_type == TradeType::Sell)
            else {
                message.set(Some(("✗ Required collateral exceeds 64 bits".into(), true)));
                return;
            };
            let collateral_need = if lock_token == NATIVE_TOKEN {
                let Some(total) = collateral.checked_add(fee) else {
                    message.set(Some(("✗ Collateral plus fee exceeds 64 bits".into(), true)));
                    return;
                };
                total
            } else {
                collateral
            };

            let collateral_notes = match note_store
                .read()
                .select_unspent(&lock_token, collateral_need)
            {
                Some(sel) => sel,
                None => {
                    message.set(Some((
                        format!("✗ Insufficient {lock_token} balance (need {collateral_need})"),
                        true,
                    )));
                    return;
                }
            };
            let fee_notes = if lock_token == NATIVE_TOKEN || fee == 0 {
                Vec::new()
            } else {
                match note_store.read().select_unspent(NATIVE_TOKEN, fee) {
                    Some(sel) => sel,
                    None => {
                        message.set(Some((
                            format!("✗ Insufficient {NATIVE_TOKEN} balance for fee (need {fee})"),
                            true,
                        )));
                        return;
                    }
                }
            };

            let Some(client) = chain_client.read().clone() else {
                message.set(Some(("✗ Not connected to chain".into(), true)));
                return;
            };

            submitting.set(true);
            // What the book shows for an own row is the LOCKED collateral
            // (the column other rows show the collateral commitment in), not
            // the typed quantity — locked-only model.
            let locked_str = collateral.to_string();
            spawn(async move {
                let result = submit_order(
                    &client,
                    note_store,
                    order_store,
                    collateral_notes,
                    fee_notes,
                    lock_token,
                    (t1.clone(), t2.clone()),
                    trade_type,
                    kind,
                    price,
                    q,
                    fee,
                )
                .await;
                match result {
                    Ok((order_id, confirmed)) => {
                        own_order_ids.write().insert(order_id, locked_str);
                        expanded.set(None);
                        if confirmed {
                            message.set(Some((
                                format!("✓ {} {}/{} order submitted", trade_type, t1, t2),
                                false,
                            )));
                        } else {
                            // Uncertain outcome: records are kept; the
                            // poller reconciles against the chain.
                            message.set(Some((
                                format!(
                                    "⚠ {} {}/{} order submission unconfirmed — reconciling",
                                    trade_type, t1, t2
                                ),
                                true,
                            )));
                        }
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
        }
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

                div { class: "side-tabs",
                    div {
                        class: if current_kind == OrderKind::Limit { "side-tab buy-active" } else { "side-tab" },
                        onclick: move |_| order_kind.set(OrderKind::Limit),
                        "Limit"
                    }
                    div {
                        class: if current_kind == OrderKind::Market { "side-tab buy-active" } else { "side-tab" },
                        onclick: move |_| order_kind.set(OrderKind::Market),
                        "Market"
                    }
                }

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
                    span { class: "input-label", if current_kind == OrderKind::Market { "Protection Price" } else { "Price" } }
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
                        span { class: "input-suffix", "{NATIVE_TOKEN}" }
                    }
                }

                // Total
                div { class: "total-row",
                    span { class: "total-label", "Total" }
                    span { class: "total-value", "{total_str}" }
                }

                // Spendable notes
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

                // Locked collateral (open orders)
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

/// Full order submission: sync the pool tree, prove send_order, persist
/// the wallet records FIRST (persist-before-publish), then submit. Returns
/// `(order_id, confirmed_submitted)`. A definite rejection rolls the
/// records back (Err); an UNCERTAIN outcome (timeout, broken connection)
/// KEEPS them and returns `confirmed_submitted = false` — the transaction
/// may have landed, and the poller reconciles against the chain.
#[cfg(not(target_os = "android"))]
#[allow(clippy::too_many_arguments)]
async fn submit_order(
    client: &Arc<ChainClient>,
    mut note_store: Signal<NoteStore>,
    mut order_store: Signal<OrderStore>,
    collateral_notes: Vec<NoteRecord>,
    fee_notes: Vec<NoteRecord>,
    lock_token: String,
    subject: (String, String),
    trade_type: TradeType,
    kind: OrderKind,
    price: u64,
    q: u64,
    fee: u64,
) -> Result<(OrderID, bool), String> {
    // Fresh anchor + Merkle paths from the chain head.
    let tree = client
        .fetch_note_tree()
        .await
        .map_err(|e| format!("syncing note tree: {e}"))?;

    let chain_id = client.chain_id();
    let prepared = tokio::task::block_in_place(|| {
        prepare_order(
            chain_id,
            &tree,
            &collateral_notes,
            &fee_notes,
            &lock_token,
            subject,
            trade_type,
            kind,
            price,
            q,
            fee,
        )
    })?;

    {
        let mut notes = note_store.write();
        let mut orders = order_store.write();
        persist_prepared(&mut notes, &mut orders, &prepared)?;
    }

    let order_id = prepared.params.id.clone();
    match client.send_order(prepared.params.clone()).await {
        Ok(()) => {
            eprintln!("[trade] order submitted successfully: {order_id}");
            Ok((order_id, true))
        }
        Err(err) => {
            let rolled_back = {
                let mut notes = note_store.write();
                let mut orders = order_store.write();
                apply_submit_failure(&mut notes, &mut orders, &prepared, &err)
            };
            if rolled_back {
                Err(err.to_string())
            } else {
                // Uncertain: keep everything; the reconciler completes or
                // rolls back once the chain answers.
                eprintln!("[trade] submission outcome uncertain for {order_id}: {err}");
                Ok((order_id, false))
            }
        }
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod submit_tests {
    use super::*;
    use invisibook_lib::note_store::NOTE_PENDING_SPEND;

    fn tmp_stores(tag: &str) -> (NoteStore, OrderStore) {
        let dir =
            std::env::temp_dir().join(format!("trade_form_test_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (
            NoteStore::load(dir.join("notes.json")),
            OrderStore::load(dir.join("orders.json")),
        )
    }

    fn sample_prepared(order_id: &str, input_cm: &str) -> PreparedOrder {
        PreparedOrder {
            params: SendOrderParams {
                id: order_id.into(),
                kind: 0,
                trade_type: 0,
                subject: TradePairJson {
                    token1: "ETH".into(),
                    token2: "USDT".into(),
                },
                price: Some(3),
                protection_price: None,
                pubkey: String::new(),
                signature: String::new(),
                anchor: "bb".repeat(32),
                collateral_nullifiers: vec!["cc".repeat(32), "dd".repeat(32)],
                fee_nullifiers: vec!["11".repeat(32), "22".repeat(32)],
                locked_commitment: "ee".repeat(32),
                fee: 0,
                collateral_change_commitment: "ff".repeat(32),
                fee_change_commitment: "aa".repeat(32),
                zk_proof: "{}".into(),
            },
            opening: OrderOpening {
                order_id: order_id.into(),
                q: 2,
                locked_amount: 6,
                r_locked: "22".repeat(32),
                lock_token: "USDT".into(),
            },
            spent: vec![(input_cm.to_string(), "cc".repeat(32))],
            changes: vec![NoteRecord {
                cm: "ff".repeat(32),
                token: "USDT".into(),
                amount: 4,
                r: "33".repeat(32),
                key_index: 0,
                sk: "44".repeat(32),
                leaf_index: 0,
                status: NOTE_PENDING_MINT,
                nf: String::new(),
                pending_order: order_id.into(),
            }],
        }
    }

    fn seeded_input(cm: &str) -> NoteRecord {
        NoteRecord {
            cm: cm.into(),
            token: "USDT".into(),
            amount: 10,
            r: "55".repeat(32),
            key_index: 0,
            sk: "66".repeat(32),
            leaf_index: 0,
            status: NOTE_UNSPENT,
            nf: String::new(),
            pending_order: String::new(),
        }
    }

    /// P1-7 regression: an UNCERTAIN outcome (the server may have received
    /// the transaction, the client timed out) must keep every wallet
    /// record — spent markers, change note, and the order opening.
    #[test]
    fn uncertain_submit_error_keeps_all_records() {
        let (mut notes, mut orders) = tmp_stores("uncertain");
        let input_cm = "ab".repeat(32);
        notes.upsert(seeded_input(&input_cm));
        let prepared = sample_prepared("order-x", &input_cm);
        persist_prepared(&mut notes, &mut orders, &prepared).unwrap();

        let err = SubmitError::Uncertain("operation timed out".into());
        let rolled = apply_submit_failure(&mut notes, &mut orders, &prepared, &err);

        assert!(!rolled, "uncertain outcomes must never roll back");
        let input = notes.find(&input_cm).unwrap();
        assert_eq!(
            input.status, NOTE_PENDING_SPEND,
            "input stays pending-spend"
        );
        assert!(!input.nf.is_empty(), "nullifier stays recorded");
        assert_eq!(input.pending_order, "order-x");
        assert!(
            notes.find(&"ff".repeat(32)).is_some(),
            "change note must be kept"
        );
        assert!(
            orders.find("order-x").is_some(),
            "order opening must be kept"
        );
    }

    /// A DEFINITE rejection rolls everything back: the input returns to
    /// UNSPENT and the stillborn records disappear.
    #[test]
    fn rejected_submit_error_rolls_back() {
        let (mut notes, mut orders) = tmp_stores("rejected");
        let input_cm = "cd".repeat(32);
        notes.upsert(seeded_input(&input_cm));
        let prepared = sample_prepared("order-y", &input_cm);
        persist_prepared(&mut notes, &mut orders, &prepared).unwrap();

        let err = SubmitError::Rejected("writing failed (400)".into());
        let rolled = apply_submit_failure(&mut notes, &mut orders, &prepared, &err);

        assert!(rolled);
        let input = notes.find(&input_cm).unwrap();
        assert_eq!(input.status, NOTE_UNSPENT);
        assert!(input.nf.is_empty());
        assert!(input.pending_order.is_empty());
        assert!(
            notes.find(&"ff".repeat(32)).is_none(),
            "change note dropped"
        );
        assert!(orders.find("order-y").is_none(), "order opening dropped");
    }
}
