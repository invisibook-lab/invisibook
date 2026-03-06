mod components;
mod constants;
mod style;

use std::collections::HashMap;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;

use invisibook_lib::orderbook;
use invisibook_lib::types::*;

use components::{Header, OrderBook, Toast, TradeForm};
use style::CSS;

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
    // ── Shared state ──
    let orders = use_signal(|| {
        let mut o = orderbook::sample_orders();
        orderbook::sort_orders(&mut o);
        o
    });
    let own_order_ids = use_signal(HashMap::<OrderID, String>::new);
    let selected = use_signal(|| None::<usize>);
    let expanded = use_signal(|| None::<usize>);
    let message = use_signal(|| None::<(String, bool)>);

    // ── Derive display pair from first order or default ──
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
                OrderBook {
                    orders,
                    own_order_ids,
                    selected,
                    expanded,
                }
                TradeForm {
                    orders,
                    own_order_ids,
                    expanded,
                    message,
                }
            }

            Toast { message }
        }
    }
}
