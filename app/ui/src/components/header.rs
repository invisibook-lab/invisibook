use dioxus::prelude::*;

#[component]
pub fn Header(token1: String, token2: String) -> Element {
    let _ = (token1, token2);
    rsx! {
        div { class: "header",
            div { class: "header-logo",
                img { src: asset!("/assets/logo.png"), class: "header-logo-img", alt: "logo" }
                span { "INVISIBOOK" }
            }
        }
    }
}
