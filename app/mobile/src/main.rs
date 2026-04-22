use std::collections::HashMap;
use std::sync::Arc;

use dioxus::prelude::*;

use invisibook_lib::chain::ChainClient;
use invisibook_lib::config::ClientConfig;
use invisibook_lib::orderbook;
use invisibook_lib::types::*;
use invisibook_ui::components::{Header, OrderBook, Toast, TradeForm};
use invisibook_ui::style_mobile::CSS_MOBILE;

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    OrderBook,
    Trade,
}

#[component]
fn App() -> Element {
    let (initial_client, initial_address) = {
        let cfg = ClientConfig::load(None);
        match cfg.keypair() {
            Ok(kp) => {
                let addr = kp.address();
                let c = ChainClient::new(&cfg.chain.http_url, &cfg.chain.ws_url, kp, cfg.chain.chain_id);
                (Some(Arc::new(c)), addr)
            }
            Err(_) => (None, String::new()),
        }
    };
    let client: Signal<Option<Arc<ChainClient>>> = use_signal(|| initial_client);
    let my_address: Signal<String> = use_signal(|| initial_address);

    let mut orders = use_signal(Vec::<Order>::new);
    let own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let expanded = use_signal(|| None::<usize>);
    let message = use_signal(|| None::<(String, bool)>);
    let mut active_tab = use_signal(|| Tab::OrderBook);

    let _fetch = use_resource(move || {
        let client = client.read().clone();
        async move {
            if let Some(c) = client {
                match c.query_orders(None, None, None, None, None, Some(100), Some(0)).await {
                    Ok(mut chain_orders) => {
                        orderbook::sort_orders(&mut chain_orders);
                        orders.set(chain_orders);
                    }
                    Err(_) => {
                        let mut o = orderbook::sample_orders();
                        orderbook::sort_orders(&mut o);
                        orders.set(o);
                    }
                }
            } else {
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
        document::Meta {
            name: "viewport",
            content: "width=device-width, initial-scale=1.0, viewport-fit=cover"
        }
        style { {CSS_MOBILE} }
        div { class: "app",
            Header { token1: t1, token2: t2 }

            div { class: "main",
                if *active_tab.read() == Tab::OrderBook {
                    OrderBook { orders, own_order_ids, selected, expanded }
                } else {
                    TradeForm { orders, own_order_ids, expanded, message, chain_client: client, my_address }
                }
            }

            // ── Bottom Tab Bar ──
            div { class: "tab-bar",
                div {
                    class: if *active_tab.read() == Tab::OrderBook { "tab-btn active" } else { "tab-btn" },
                    onclick: move |_| active_tab.set(Tab::OrderBook),
                    "Order Book"
                }
                div {
                    class: if *active_tab.read() == Tab::Trade { "tab-btn active" } else { "tab-btn" },
                    onclick: move |_| active_tab.set(Tab::Trade),
                    "Trade"
                }
            }

            Toast { message }
        }
    }
}
