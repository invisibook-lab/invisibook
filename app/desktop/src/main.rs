use std::collections::HashMap;
use std::sync::Arc;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;

use invisibook_lib::chain::ChainClient;
use invisibook_lib::config::ClientConfig;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;
use invisibook_ui::components::{Header, OrderBook, Toast, TradeForm};
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
    let (initial_client, initial_address) = {
        let cfg = ClientConfig::load_with_args();
        match cfg.keypair() {
            Ok(kp) => {
                let addr = kp.address();
                let c = ChainClient::new(&cfg.chain.http_url, &cfg.chain.ws_url, kp);
                (Some(Arc::new(c)), addr)
            }
            Err(e) => {
                eprintln!("Failed to parse keypair: {}", e);
                (None, String::new())
            }
        }
    };
    let client: Signal<Option<Arc<ChainClient>>> = use_signal(|| initial_client);
    let my_address: Signal<String> = use_signal(|| initial_address);

    let mut orders = use_signal(Vec::<Order>::new);
    let own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let expanded = use_signal(|| None::<usize>);
    let message = use_signal(|| None::<(String, bool)>);

    // ── Fetch orders from chain on mount ──
    let _fetch = use_resource(move || {
        let client = client.read().clone();
        async move {
            if let Some(c) = client {
                match c.query_orders(None, None, None, None, None, Some(100), Some(0)).await {
                    Ok(mut chain_orders) => {
                        orderbook::sort_orders(&mut chain_orders);
                        orders.set(chain_orders);
                    }
                    Err(e) => {
                        eprintln!("Failed to fetch orders: {}", e);
                        // Fall back to sample orders
                        let mut o = orderbook::sample_orders();
                        orderbook::sort_orders(&mut o);
                        orders.set(o);
                    }
                }
            } else {
                // No chain client — use sample data
                let mut o = orderbook::sample_orders();
                orderbook::sort_orders(&mut o);
                orders.set(o);
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
            Header { token1: t1, token2: t2 }
            div { class: "main",
                OrderBook { orders, own_order_ids, selected, expanded }
                TradeForm { orders, own_order_ids, expanded, message, chain_client: client, my_address }
            }
            Toast { message }
        }
    }
}
