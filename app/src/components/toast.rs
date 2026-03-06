use dioxus::prelude::*;

/// A fixed-position toast notification at the bottom of the screen.
#[component]
pub fn Toast(message: Signal<Option<(String, bool)>>) -> Element {
    if let Some((ref msg, ref is_err)) = *message.read() {
        rsx! {
            div {
                class: if *is_err { "toast error" } else { "toast success" },
                "{msg}"
            }
        }
    } else {
        rsx! {}
    }
}
