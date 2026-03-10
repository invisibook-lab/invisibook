use std::collections::HashMap;

use dioxus::prelude::*;

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
    let orders = use_signal(|| {
        let mut o = orderbook::sample_orders();
        orderbook::sort_orders(&mut o);
        o
    });
    let own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let expanded = use_signal(|| None::<usize>);
    let message = use_signal(|| None::<(String, bool)>);
    let mut active_tab = use_signal(|| Tab::OrderBook);

    let (t1, t2) = {
        let list = orders.read();
        if let Some(first) = list.first() {
            (first.subject.token1.clone(), first.subject.token2.clone())
        } else {
            ("ETH".into(), "USDT".into())
        }
    };

    rsx! {
        style { {CSS_MOBILE} }
        div { class: "app",
            Header { token1: t1, token2: t2 }

            div { class: "main",
                if *active_tab.read() == Tab::OrderBook {
                    OrderBook { orders, own_order_ids, selected, expanded }
                } else {
                    TradeForm { orders, own_order_ids, expanded, message }
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
