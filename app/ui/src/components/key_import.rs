use std::{fs, path::PathBuf, sync::Arc};

use dioxus::{html::HasFileData, prelude::*};

use invisibook_lib::{
    chain::ChainClient,
    config::ClientConfig,
    note_store::{NoteRecord, NoteStore},
};

/// Modal panel for importing a BIP-39 mnemonic phrase and optionally a
/// notes file (the wallet's note ledger — see `note_store`).
#[component]
pub fn KeyImport(
    chain_client: Signal<Option<Arc<ChainClient>>>,
    my_address: Signal<String>,
    message: Signal<Option<(String, bool)>>,
    note_store: Signal<NoteStore>,
    visible: Signal<bool>,
    key_imported: Signal<bool>,
    seed_signal: Signal<Option<[u8; 32]>>,
    data_dir: PathBuf,
) -> Element {
    let mut mnemonic_input = use_signal(String::new);
    let mut notes_file_input = use_signal(String::new);
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
                message.set(Some((format!("✗ Invalid mnemonic: {}", e), true)));
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
        seed_signal.set(Some(seed));

        // Persist mnemonic to data_dir/mnemonic for auto-login on next launch.
        let _ = fs::create_dir_all(&data_dir);
        let _ = fs::write(data_dir.join("mnemonic"), &mnemonic_text);

        // Optionally import a notes file: upsert every record by commitment.
        let notes_file = notes_file_input.read().trim().to_string();
        if !notes_file.is_empty() {
            let imported: Result<Vec<NoteRecord>, String> = fs::read_to_string(&notes_file)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()));
            match imported {
                Ok(records) => {
                    let n = records.len();
                    let mut store = note_store.write();
                    for rec in records {
                        store.upsert(rec);
                    }
                    match store.save() {
                        Ok(()) => message.set(Some((
                            format!(
                                "✓ Key imported ({}) — {} note records loaded",
                                &pubkey[..10],
                                n
                            ),
                            false,
                        ))),
                        Err(e) => message.set(Some((
                            format!(
                                "✓ Key imported ({}) — notes save error: {}",
                                &pubkey[..10],
                                e
                            ),
                            true,
                        ))),
                    }
                }
                Err(e) => message.set(Some((
                    format!(
                        "✓ Key imported ({}) — notes file error: {}",
                        &pubkey[..10],
                        e
                    ),
                    true,
                ))),
            }
        } else {
            message.set(Some((format!("✓ Key imported ({})", &pubkey[..10]), false)));
        }

        mnemonic_input.set(String::new());
        notes_file_input.set(String::new());
        visible.set(false);
    };

    let on_cancel = move |_| {
        mnemonic_input.set(String::new());
        notes_file_input.set(String::new());
        visible.set(false);
    };

    let has_notes_file = !notes_file_input.read().is_empty();

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
                    span { class: "input-label", "Notes File (optional)" }
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
                                    notes_file_input.set(pb.to_string_lossy().into_owned());
                                }
                            }
                        },
                        if !has_notes_file {
                            div { class: "drop-hint",
                                span { class: "drop-hint-icon", "📂" }
                                span { class: "drop-hint-text", "Drop notes.json here" }
                            }
                        } else {
                            div { class: "drop-content",
                                span { class: "drop-filename", "{notes_file_input}" }
                                button {
                                    class: "drop-clear",
                                    onclick: move |_| notes_file_input.set(String::new()),
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
