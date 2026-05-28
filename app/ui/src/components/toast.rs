use dioxus::prelude::*;

/// A fixed-position toast notification that auto-dismisses after 2.5 seconds.
#[component]
pub fn Toast(mut message: Signal<Option<(String, bool)>>) -> Element {
    // Spawn a dismiss task whenever a new message appears.
    // Errors stay visible twice as long (5s) so the user can read them.
    use_effect(move || {
        if let Some((_, is_err)) = message.read().clone() {
            let duration = if is_err { 5000 } else { 2500 };
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(duration)).await;
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
