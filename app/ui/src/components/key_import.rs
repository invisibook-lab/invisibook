use std::path::PathBuf;
use std::sync::Arc;

use dioxus::html::HasFileData;
use dioxus::prelude::*;

use invisibook_lib::cash_store::CashStore;
use invisibook_lib::chain::ChainClient;
use invisibook_lib::config::ClientConfig;

/// Modal panel for importing a BIP-39 mnemonic phrase and optionally a cash file.
#[component]
pub fn KeyImport(
    chain_client: Signal<Option<Arc<ChainClient>>>,
    my_address: Signal<String>,
    message: Signal<Option<(String, bool)>>,
    cash_store: Signal<CashStore>,
    visible: Signal<bool>,
    key_imported: Signal<bool>,
) -> Element {
    let mut mnemonic_input = use_signal(String::new);
    let mut cash_file_input = use_signal(String::new);
    let mut drag_over = use_signal(|| false);

    if !*visible.read() {
        return rsx! {};
    }

    let on_import = move |_| {
        let mnemonic_text = mnemonic_input.read().trim().to_string();
        if mnemonic_text.is_empty() {
            message.set(Some(("✗ Mnemonic cannot be empty".into(), true)));
            return;
        }

        // Parse, validate, and derive ed25519 seed at m/44'/60'/0'/0'/0'
        let seed = match invisibook_lib::hd::mnemonic_to_ed25519_key(&mnemonic_text, 60, 0) {
            Ok(s) => s,
            Err(e) => {
                message.set(Some((
                    format!("✗ Invalid mnemonic: {}", e),
                    true,
                )));
                return;
            }
        };

        let cfg = ClientConfig::load(None);
        let kp = ClientConfig::keypair_from_seed(&seed).unwrap();
        let pubkey = hex::encode(kp.pubkey_bytes());
        let new_client = Arc::new(ChainClient::new(
            &cfg.chain.http_url,
            &cfg.chain.ws_url,
            seed,
            cfg.chain.chain_id,
        ));

        chain_client.set(Some(new_client));
        my_address.set(pubkey.clone());
        key_imported.set(true);

        // Optionally import cash file
        let cash_file = cash_file_input.read().trim().to_string();
        if !cash_file.is_empty() {
            let path = PathBuf::from(&cash_file);
            match cash_store.write().load_from_file(&path) {
                Ok(n) => message.set(Some((
                    format!("✓ Key imported ({}) — {} cash records loaded", &pubkey[..10], n),
                    false,
                ))),
                Err(e) => message.set(Some((
                    format!("✓ Key imported ({}) — cash file error: {}", &pubkey[..10], e),
                    true,
                ))),
            }
        } else {
            message.set(Some((
                format!("✓ Key imported ({})", &pubkey[..10]),
                false,
            )));
        }

        mnemonic_input.set(String::new());
        cash_file_input.set(String::new());
        visible.set(false);
    };

    let on_cancel = move |_| {
        mnemonic_input.set(String::new());
        cash_file_input.set(String::new());
        visible.set(false);
    };

    let has_cash_file = !cash_file_input.read().is_empty();

    rsx! {
        div { class: "modal-overlay",
            div { class: "modal",
                h3 { class: "modal-title", "Import Mnemonic" }

                div { class: "input-group",
                    span { class: "input-label", "Mnemonic Phrase" }
                    input {
                        class: "input-field",
                        r#type: "text",
                        placeholder: "12 or 24 words separated by spaces",
                        value: "{mnemonic_input}",
                        oninput: move |evt: Event<FormData>| mnemonic_input.set(evt.value()),
                    }
                }

                div { class: "input-group",
                    span { class: "input-label", "Cash File (optional)" }
                    div {
                        class: if *drag_over.read() { "drop-zone drag-over" } else { "drop-zone" },
                        ondragover: move |evt: Event<DragData>| {
                            evt.prevent_default();
                            drag_over.set(true);
                        },
                        ondragleave: move |_| drag_over.set(false),
                        ondrop: move |evt: Event<DragData>| {
                            drag_over.set(false);
                            if let Some(file) = evt.files().into_iter().next() {
                                if let Some(pb) = file.inner().downcast_ref::<PathBuf>() {
                                    cash_file_input.set(pb.to_string_lossy().into_owned());
                                }
                            }
                        },
                        if !has_cash_file {
                            div { class: "drop-hint",
                                span { class: "drop-hint-icon", "📂" }
                                span { class: "drop-hint-text", "Drop cash.json here" }
                            }
                        } else {
                            div { class: "drop-content",
                                span { class: "drop-filename", "{cash_file_input}" }
                                button {
                                    class: "drop-clear",
                                    onclick: move |_| cash_file_input.set(String::new()),
                                    "×"
                                }
                            }
                        }
                    }
                }

                div { class: "modal-actions",
                    button {
                        class: "submit-btn buy",
                        onclick: on_import,
                        "Import"
                    }
                    button {
                        class: "submit-btn",
                        onclick: on_cancel,
                        "Cancel"
                    }
                }
            }
        }
    }
}
