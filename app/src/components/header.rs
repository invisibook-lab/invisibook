use dioxus::prelude::*;

#[component]
pub fn Header(token1: String, token2: String) -> Element {
    rsx! {
        div { class: "header",
            span { class: "header-logo", "INVISIBOOK" }
            span { class: "header-pair", "{token1}/{token2}" }
        }
    }
}
