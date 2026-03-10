use dioxus::prelude::*;

/// A fixed-position toast notification that auto-dismisses after 2.5 seconds.
#[component]
pub fn Toast(mut message: Signal<Option<(String, bool)>>) -> Element {
    // Spawn a dismiss task whenever a new message appears.
    use_effect(move || {
        if message.read().is_some() {
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
                message.set(None);
            });
        }
    });

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
