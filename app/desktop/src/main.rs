use std::collections::HashMap;
use std::sync::Arc;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;

use hex;
use invisibook_lib::cash_store::CashStore;
use invisibook_lib::chain::{ChainClient, OrderEvent};
use invisibook_lib::config::ClientConfig;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;
use invisibook_ui::components::{Header, KeyImport, OrderBook, Toast, TradeForm};
use invisibook_ui::style::CSS;

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
    // ── Load config & create chain client ──
    let (initial_client, initial_address, init_error) = {
        let cfg = ClientConfig::load_with_args();
        match cfg.seed() {
            Ok(seed) => {
                let kp = invisibook_lib::config::ClientConfig::keypair_from_seed(&seed).unwrap();
                let pubkey = hex::encode(kp.pubkey_bytes());
                let c = ChainClient::new(&cfg.chain.http_url, &cfg.chain.ws_url, seed, cfg.chain.chain_id);
                (Some(Arc::new(c)), pubkey, None)
            }
            Err(e) => {
                (None, String::new(), Some(format!("✗ Failed to parse keypair: {e}")))
            }
        }
    };

    // Clone for the WS coroutine before moving into the signal
    let client_for_ws = initial_client.clone();

    let client: Signal<Option<Arc<ChainClient>>> = use_signal(|| initial_client);
    let my_address: Signal<String> = use_signal(|| initial_address);

    let mut orders = use_signal(Vec::<Order>::new);
    let own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let expanded = use_signal(|| None::<usize>);
    let mut message = use_signal(|| init_error.map(|e| (e, true)));
    let cash_store = use_signal(|| CashStore::load(CashStore::default_path()));
    let mut show_key_import = use_signal(|| false);
    let key_imported = use_signal(|| false);

    // ── Poll order list from chain every 3 seconds (≈ 1 block) ──
    use_coroutine(move |_: UnboundedReceiver<()>| async move {
        loop {
            let c = client.read().clone();
            if let Some(c) = c {
                match c.query_orders(None, None, None, None, None, Some(100), Some(0)).await {
                    Ok(mut chain_orders) => {
                        orderbook::sort_orders(&mut chain_orders);
                        orders.set(chain_orders);
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
    // When SendOrder is confirmed on-chain, upsert the order into the book.
    use_coroutine(move |_: UnboundedReceiver<()>| {
        // Clone here so the FnMut closure can yield the value into the async block.
        let c = client_for_ws.clone();
        async move {
        let Some(c) = c else { return };
        let Ok((mut rx, _handle)) = c.subscribe_order_events().await else {
            message.set(Some(("✗ Failed to subscribe to chain events".into(), true)));
            return;
        };
        while let Some(event) = rx.recv().await {
            match event {
                OrderEvent::Confirmed(order) => {
                    let short = order.id[..order.id.len().min(7)].to_string();
                    {
                        let mut o = orders.write();
                        if let Some(existing) = o.iter_mut().find(|x| x.id == order.id) {
                            *existing = order;
                        } else {
                            o.push(order);
                            orderbook::sort_orders(&mut *o);
                        }
                    }
                    message.set(Some((format!("✓ Order {short} confirmed on chain"), false)));
                }
                OrderEvent::Error(e) => {
                    message.set(Some((format!("✗ Chain error: {e}"), true)));
                }
            }
        }
        } // end async move
    }); // end use_coroutine

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
                OrderBook { orders, own_order_ids, selected, expanded }
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
            }
        }
    }
}
