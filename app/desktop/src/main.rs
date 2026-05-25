use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use dioxus::{
    desktop::{Config, LogicalSize, WindowBuilder},
    prelude::*,
};
use futures_util::StreamExt;

use hex;
use invisibook_lib::{
    cash_store::{CashRecord, CashStore},
    chain::{ChainClient, OrderEvent},
    config::ClientConfig,
    hd, orderbook,
    types::*,
};
use invisibook_ui::{
    components::{Header, KeyImport, OrderBook, Toast, TradeForm},
    settle,
    style::CSS,
};

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

#[component]
fn App() -> Element {
    // ── Load config & try reading mnemonic from data_dir/mnemonic ──
    let cfg = ClientConfig::load_with_args();
    let (initial_client, initial_address, init_imported, initial_seed) = {
        let mnemonic = std::fs::read_to_string(cfg.mnemonic_path()).ok();
        if let Some(mnemonic) = mnemonic {
            let mnemonic = mnemonic.trim().to_string();
            match hd::mnemonic_to_ed25519_key(&mnemonic, 60, 0) {
                Ok(seed) => {
                    let kp = ClientConfig::keypair_from_seed(&seed).unwrap();
                    let pubkey = hex::encode(kp.pubkey_bytes());
                    let c = ChainClient::new(
                        &cfg.chain.http_url,
                        &cfg.chain.ws_url,
                        seed,
                        cfg.chain.chain_id,
                    );
                    (Some(Arc::new(c)), pubkey, true, Some(seed))
                }
                Err(_) => (None, String::new(), false, None),
            }
        } else {
            (None, String::new(), false, None)
        }
    };

    let client: Signal<Option<Arc<ChainClient>>> = use_signal(|| initial_client);
    let my_address: Signal<String> = use_signal(|| initial_address);
    let seed_signal: Signal<Option<[u8; 32]>> = use_signal(|| initial_seed);

    let mut orders = use_signal(Vec::<Order>::new);
    let mut own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let expanded = use_signal(|| None::<usize>);
    let mut message: Signal<Option<(String, bool)>> = use_signal(|| None);
    let cash_path = cfg.cash_path();
    let mut cash_store = use_signal(|| CashStore::load(cash_path.clone()));
    let mut show_key_import = use_signal(|| false);
    let key_imported = use_signal(|| init_imported);
    let mut settling_ids: Signal<HashSet<OrderID>> = use_signal(HashSet::new);

    // ── Settle coroutine: receives order IDs to settle ──
    let settle_coro = use_coroutine(move |mut rx: UnboundedReceiver<OrderID>| {
        async move {
            while let Some(order_id) = rx.next().await {
                let c = match client.read().clone() {
                    Some(c) => c,
                    None => {
                        message.set(Some(("✗ No chain client".into(), true)));
                        continue;
                    }
                };
                // Find my order and counter order from the order list.
                let (my_order, counter_order) = {
                    let list = orders.read();
                    let my = list.iter().find(|o| o.id == order_id).cloned();
                    let counter = my.as_ref().and_then(|m| {
                        m.match_order
                            .as_ref()
                            .and_then(|mid| list.iter().find(|o| &o.id == mid).cloned())
                    });
                    match (my, counter) {
                        (Some(m), Some(co)) => (m, co),
                        _ => {
                            message.set(Some(("✗ Order or counterparty not found".into(), true)));
                            settling_ids.write().remove(&order_id);
                            continue;
                        }
                    }
                };

                // Mark as settling in the UI.
                settling_ids.write().insert(order_id.clone());

                // Read cash records from the in-memory signal (always up-to-date).
                let records_snapshot: Vec<_> = cash_store.read().records().to_vec();

                let mut msg_signal = message;
                let settle_order_id = order_id.clone();
                let result = settle::run_settle(
                    &c,
                    &my_order,
                    &counter_order,
                    &records_snapshot,
                    |status| {
                        let short = orderbook::short_id(&settle_order_id);
                        msg_signal.set(Some((format!("[{short}] {status}"), false)));
                    },
                )
                .await;

                match result {
                    Ok(outcome) => {
                        // Update local CashStore: mark locked cash as spent, add received cash.
                        {
                            let mut store = cash_store.write();
                            let spent = settle::spent_cash_ids(&my_order);
                            for rec in store.records_mut().iter_mut() {
                                if spent.contains(&rec.cash_id) {
                                    rec.status = CASH_SPENT;
                                }
                            }
                            store.records_mut().push(CashRecord {
                                cash_id: outcome.recv_cash_id,
                                token: outcome.recv_token.clone(),
                                amount: outcome.recv_amount,
                                random: outcome.recv_random_hex,
                                status: CASH_ACTIVE,
                            });
                            // Persist change cash for the larger party.
                            if let (Some(ref cid), Some(ref ctk), Some(camt), Some(ref crnd)) = (
                                &outcome.change_cash_id,
                                &outcome.change_token,
                                outcome.change_amount,
                                &outcome.change_random_hex,
                            ) {
                                if camt > 0 {
                                    store.records_mut().push(CashRecord {
                                        cash_id: cid.clone(),
                                        token: ctk.clone(),
                                        amount: camt,
                                        random: crnd.clone(),
                                        status: CASH_ACTIVE,
                                    });
                                }
                            }
                            let _ = store.flush();
                        }

                        let short = orderbook::short_id(&order_id);
                        message.set(Some((
                            format!(
                                "✓ Settled {short}: received {} {}",
                                outcome.recv_amount, outcome.recv_token
                            ),
                            false,
                        )));

                        // Auto-repost remainder order if larger party has change.
                        if let (
                            Some(ref change_cash_id),
                            Some(ref _change_token),
                            Some(change_amount),
                            Some(ref change_random_hex),
                            Some(ref _change_commit),
                        ) = (
                            &outcome.change_cash_id,
                            &outcome.change_token,
                            outcome.change_amount,
                            &outcome.change_random_hex,
                            &outcome.change_commitment_hex,
                        ) {
                            if change_amount > 0 {
                                // Compute user-facing amount (in token1, e.g. ETH).
                                // change_amount is in the lock token:
                                //   Buy locks token2 (USDT) → display = change / price (ETH)
                                //   Sell locks token1 (ETH)  → display = change (ETH)
                                let price = my_order.price.unwrap_or(1).max(1);
                                let display_amount = match my_order.trade_type {
                                    TradeType::Buy => change_amount / price,
                                    TradeType::Sell => change_amount,
                                };

                                // Generate fresh blinding factor and commitment for the repost order.
                                // The input cash is the on-chain change cash (change_cash_id),
                                // NOT a freshly computed ID.
                                let (repost_cipher, _, repost_random_hex) =
                                    orderbook::encrypt_amount_with_info(&change_amount.to_string());

                                // Update CashStore: update random for the existing change cash
                                // so MPC can use the new commitment's random later.
                                {
                                    let mut store = cash_store.write();
                                    for rec in store.records_mut().iter_mut() {
                                        if &rec.cash_id == change_cash_id {
                                            rec.random = repost_random_hex.clone();
                                            rec.status = CASH_LOCKED;
                                        }
                                    }
                                    let _ = store.flush();
                                }

                                let repost_order_id =
                                    orderbook::compute_order_id(&[change_cash_id.clone()]);
                                let pubkey = c.pubkey_hex().to_string();
                                let repost_order = Order {
                                    id: repost_order_id.clone(),
                                    trade_type: my_order.trade_type.clone(),
                                    subject: my_order.subject.clone(),
                                    price: my_order.price,
                                    amount: repost_cipher,
                                    pubkey: pubkey.clone(),
                                    input_cash_ids: vec![change_cash_id.clone()],
                                    handling_fee: my_order.handling_fee.clone(),
                                    block_height: 0,
                                    status: OrderStatus::Pending,
                                    match_order: None,
                                    is_smaller: false,
                                };

                                match c.send_order(&repost_order, None, None).await {
                                    Ok(()) => {
                                        own_order_ids.write().insert(
                                            repost_order_id.clone(),
                                            display_amount.to_string(),
                                        );
                                        let short_r = orderbook::short_id(&repost_order_id);
                                        message.set(Some((
                                            format!(
                                                "✓ Re-posted remainder {short_r}: {} {}",
                                                display_amount, my_order.subject.token1
                                            ),
                                            false,
                                        )));
                                    }
                                    Err(e) => {
                                        // Rollback: restore change cash to active.
                                        let mut store = cash_store.write();
                                        for rec in store.records_mut().iter_mut() {
                                            if &rec.cash_id == change_cash_id {
                                                rec.random = change_random_hex.clone();
                                                rec.status = CASH_ACTIVE;
                                            }
                                        }
                                        let _ = store.flush();
                                        let short_r = orderbook::short_id(&order_id);
                                        message
                                            .set(Some((format!("✗ Repost {short_r}: {e}"), true)));
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let short = orderbook::short_id(&order_id);
                        message.set(Some((format!("✗ Settle {short}: {e}"), true)));
                    }
                }

                settling_ids.write().remove(&order_id);
            }
        }
    });

    // ── Poll order list from chain every 3 seconds (≈ 1 block) ──
    use_coroutine(move |_: UnboundedReceiver<()>| async move {
        loop {
            let c = client.read().clone();
            if let Some(c) = c {
                match c
                    .query_orders(None, None, None, None, None, Some(100), Some(0))
                    .await
                {
                    Ok(mut chain_orders) => {
                        orderbook::sort_orders(&mut chain_orders);
                        orders.set(chain_orders.clone());

                        // Auto-settle fallback: catch matched orders missed by WS
                        for order in &chain_orders {
                            if order.status == OrderStatus::Matched
                                && order.match_order.is_some()
                                && own_order_ids.read().contains_key(&order.id)
                                && !settling_ids.read().contains(&order.id)
                            {
                                settle_coro.send(order.id.clone());
                            }
                        }
                    }
                    Err(e) => {
                        message.set(Some((format!("✗ Failed to fetch orders: {e}"), true)));
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });

    // ── Background coroutine: subscribe to chain events via WebSocket ──
    // Waits for a client, subscribes, and auto-reconnects on drop.
    use_coroutine(move |_: UnboundedReceiver<()>| async move {
        loop {
            // Wait until a client is available (may not exist until key import)
            let c = loop {
                if let Some(c) = client.read().clone() {
                    break c;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            };

            match c.subscribe_order_events().await {
                Ok((mut rx, _handle)) => {
                    while let Some(event) = rx.recv().await {
                        match event {
                            OrderEvent::Confirmed(order) => {
                                let short = order.id[..order.id.len().min(7)].to_string();
                                let status_str = order.status.to_string();
                                let order_id = order.id.clone();
                                let order_status = order.status.clone();
                                let has_match = order.match_order.is_some();
                                {
                                    let mut o = orders.write();
                                    if let Some(existing) = o.iter_mut().find(|x| x.id == order.id)
                                    {
                                        *existing = order;
                                    } else {
                                        o.push(order);
                                        orderbook::sort_orders(&mut *o);
                                    }
                                }
                                message
                                    .set(Some((format!("✓ Order {short} [{status_str}]"), false)));

                                // Auto-settle: if it's our matched order, trigger settle
                                if order_status == OrderStatus::Matched
                                    && has_match
                                    && own_order_ids.read().contains_key(&order_id)
                                    && !settling_ids.read().contains(&order_id)
                                {
                                    settle_coro.send(order_id);
                                }
                            }
                            OrderEvent::Error(e) => {
                                message.set(Some((format!("✗ Chain event error: {e}"), true)));
                            }
                        }
                    }
                    // WS connection dropped — retry after short delay
                    eprintln!("[ws] connection dropped, reconnecting in 3s...");
                }
                Err(e) => {
                    eprintln!("[ws] subscribe failed: {e}, retrying in 5s...");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });

    let (t1, t2) = {
        let list = orders.read();
        if let Some(first) = list.first() {
            (first.subject.token1.clone(), first.subject.token2.clone())
        } else {
            ("ETH".into(), "USDT".into())
        }
    };

    rsx! {
        style { {CSS} }
        div { class: "app",
            div { class: "app-topbar",
                Header { token1: t1, token2: t2 }
                if !*key_imported.read() {
                    button {
                        class: "import-key-btn",
                        onclick: move |_| show_key_import.set(true),
                        "Import Key"
                    }
                } else {
                    div { class: "address-badge",
                        {
                            let addr = my_address.read();
                            let n = addr.len();
                            if n >= 10 { format!("{}...{}", &addr[..10], &addr[n-4..]) }
                            else { addr.clone() }
                        }
                    }
                }
            }
            div { class: "main",
                OrderBook {
                    orders,
                    own_order_ids,
                    selected,
                    expanded,
                    settling_ids,
                    on_settle: move |order_id: OrderID| {
                        settle_coro.send(order_id);
                    },
                }
                TradeForm { orders, own_order_ids, expanded, message, chain_client: client, my_address, cash_store }
            }
            Toast { message }
            KeyImport {
                chain_client: client,
                my_address,
                message,
                cash_store,
                visible: show_key_import,
                key_imported,
                seed_signal,
                data_dir: cfg.data_dir.clone(),
            }
        }
    }
}
