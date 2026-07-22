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
    // Pairs that can never settle via co-zk (cross-price, self-match) — never retried.
    let mut unsettleable_ids: Signal<HashSet<OrderID>> = use_signal(HashSet::new);
    // Transient failures: do not re-dispatch the order until this instant.
    let mut retry_after: Signal<HashMap<OrderID, std::time::Instant>> = use_signal(HashMap::new);

    // Prover binary + data-dir subpaths (the app links no crypto; the
    // collaborative proof runs in the settle2p_session subprocess).
    let settle2p_bin = cfg.settle2p_bin();
    let settle2p_keys_dir = cfg.settle2p_keys_dir();
    let settle2p_sessions_dir = cfg.settle2p_sessions_dir();

    // ── Settle coroutine: receives order IDs to settle (strictly serial) ──
    let settle_coro = use_coroutine({
        let settle2p_bin = settle2p_bin.clone();
        let settle2p_keys_dir = settle2p_keys_dir.clone();
        let settle2p_sessions_dir = settle2p_sessions_dir.clone();
        move |mut rx: UnboundedReceiver<OrderID>| {
            let settle2p_bin = settle2p_bin.clone();
            let settle2p_keys_dir = settle2p_keys_dir.clone();
            let settle2p_sessions_dir = settle2p_sessions_dir.clone();
            async move {
                while let Some(order_id) = rx.next().await {
                    // Receive-time guards: skip permanently-unsettleable and
                    // not-yet-due retries (a duplicate may have queued before
                    // the flag was set).
                    if unsettleable_ids.read().contains(&order_id) {
                        continue;
                    }
                    if let Some(t) = retry_after.read().get(&order_id) {
                        if std::time::Instant::now() < *t {
                            continue;
                        }
                    }

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
                                message
                                    .set(Some(("✗ Order or counterparty not found".into(), true)));
                                continue;
                            }
                        }
                    };

                    let deps = match &settle2p_bin {
                        Some(bin) => settle::SettleDeps {
                            bin: bin.clone(),
                            keys_dir: settle2p_keys_dir.clone(),
                            sessions_dir: settle2p_sessions_dir.clone(),
                        },
                        None => {
                            message.set(Some((
                                "✗ settle2p_session prover not found (set INVISIBOOK_SETTLE2P_BIN)"
                                    .into(),
                                true,
                            )));
                            continue;
                        }
                    };

                    // Mark as settling in the UI (cleared LAST, after persist).
                    settling_ids.write().insert(order_id.clone());
                    let records_snapshot: Vec<_> = cash_store.read().records().to_vec();

                    let mut msg_signal = message;
                    let settle_order_id = order_id.clone();
                    let result = settle::run_settle(
                        &c,
                        &my_order,
                        &counter_order,
                        &records_snapshot,
                        &deps,
                        |status| {
                            let short = orderbook::short_id(&settle_order_id);
                            msg_signal.set(Some((format!("[{short}] {status}"), false)));
                        },
                    )
                    .await;

                    let short = orderbook::short_id(&order_id).to_string();
                    match result {
                        Ok(outcome) => {
                            // Persist AFTER on-chain confirmation: spend inputs,
                            // add recv, and (survivor) the relisted locked cash.
                            {
                                let mut store = cash_store.write();
                                let spent = settle::spent_cash_ids(&my_order);
                                for rec in store.records_mut().iter_mut() {
                                    if spent.contains(&rec.cash_id) {
                                        rec.status = CASH_SPENT;
                                    }
                                }
                                let recv = &outcome.recv;
                                if !store.records().iter().any(|r| r.cash_id == recv.cash_id) {
                                    store.records_mut().push(CashRecord {
                                        cash_id: recv.cash_id.clone(),
                                        token: recv.token.clone(),
                                        amount: recv.amount,
                                        random: recv.random_hex.clone(),
                                        status: CASH_ACTIVE,
                                        order_amount: None,
                                        order_random: None,
                                    });
                                }
                                if let Some(rem) = &outcome.remainder {
                                    let l = &rem.locked;
                                    if !store.records().iter().any(|r| r.cash_id == l.cash_id) {
                                        store.records_mut().push(CashRecord {
                                            cash_id: l.cash_id.clone(),
                                            token: l.token.clone(),
                                            amount: l.amount,
                                            random: l.random_hex.clone(),
                                            status: CASH_LOCKED,
                                            order_amount: Some(rem.order_amount),
                                            order_random: Some(rem.order_random_hex.clone()),
                                        });
                                    }
                                }
                                let _ = store.flush();
                            }
                            // The chain relisted the survivor in place (same id,
                            // block height); the poller drives its next round.
                            let _ = std::fs::remove_dir_all(&outcome.session_dir);
                            retry_after.write().remove(&order_id);
                            message.set(Some((
                                format!(
                                    "✓ Settled {short}: received {} {}",
                                    outcome.recv.amount, outcome.recv.token
                                ),
                                false,
                            )));
                        }
                        Err(settle::SettleError::CrossPrice(_)) => {
                            unsettleable_ids.write().insert(order_id.clone());
                            message.set(Some((
                                format!("⚠ {short}: cross-price match not yet supported"),
                                true,
                            )));
                        }
                        Err(settle::SettleError::SelfMatch) => {
                            unsettleable_ids.write().insert(order_id.clone());
                            message.set(Some((
                                format!("⚠ {short}: self-matched, cannot settle"),
                                true,
                            )));
                        }
                        Err(e) => {
                            retry_after.write().insert(
                                order_id.clone(),
                                std::time::Instant::now() + std::time::Duration::from_secs(30),
                            );
                            message.set(Some((format!("✗ Settle {short}: {e}"), true)));
                        }
                    }

                    settling_ids.write().remove(&order_id);
                }
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
                                && !unsettleable_ids.read().contains(&order.id)
                                && retry_after
                                    .read()
                                    .get(&order.id)
                                    .is_none_or(|t| std::time::Instant::now() >= *t)
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
                                    && !unsettleable_ids.read().contains(&order_id)
                                    && retry_after
                                        .read()
                                        .get(&order_id)
                                        .is_none_or(|t| std::time::Instant::now() >= *t)
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

    // ── Startup: warm the proving keys, then recover any unpersisted sessions ──
    use_coroutine({
        let bin = settle2p_bin.clone();
        let keys_dir = settle2p_keys_dir.clone();
        let sessions_dir = settle2p_sessions_dir.clone();
        move |_: UnboundedReceiver<()>| {
            let bin = bin.clone();
            let keys_dir = keys_dir.clone();
            let sessions_dir = sessions_dir.clone();
            async move {
                // Generate the proving-key cache off the settlement path
                // (~1 min cold) so the first real settle is not blocked on it.
                if let Some(bin) = bin.clone() {
                    let _ = tokio::process::Command::new(&bin)
                        .arg("--warm-keys")
                        .arg("--keys-dir")
                        .arg(&keys_dir)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await;
                }
                // Recover sessions that landed on chain but crashed before the
                // wallet persisted their UTXOs.
                let c = loop {
                    if let Some(c) = client.read().clone() {
                        break c;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                };
                let recovered = settle::recover_all_sessions(&c, &sessions_dir).await;
                for rec in recovered {
                    {
                        let mut store = cash_store.write();
                        for id in &rec.spent_ids {
                            for r in store.records_mut().iter_mut() {
                                if &r.cash_id == id {
                                    r.status = CASH_SPENT;
                                }
                            }
                        }
                        for add in &rec.add {
                            if !store.records().iter().any(|r| r.cash_id == add.cash_id) {
                                store.records_mut().push(add.clone());
                            }
                        }
                        let _ = store.flush();
                    }
                    let _ = std::fs::remove_dir_all(&rec.dir);
                }
            }
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
