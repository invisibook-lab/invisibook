//! Regenerate the dev/test wallet data for the note model: the four genesis
//! pool notes (alice/bob × ETH/USDT) as a `[[account.genesis_note]]` TOML
//! block for `chain/cfg/core.toml`, plus the matching wallet ledgers
//! `alice_notes.json` / `bob_notes.json` for `chain/cfg/tests/`.
//!
//! Secrets are FIXED public constants — dev/test only, never real funds.
//!
//! Usage: cargo run -p invisibook-lib --example dump_dev_notes -- <out-dir>

use std::{env, fs, path::PathBuf};

use invisibook_lib::{
    note::{asset_id, fr_from_be_bytes, note_commit, note_fr_to_hex, npk_from_sk},
    note_store::{NOTE_UNSPENT, NoteRecord},
};

/// One dev note spec: owner tag, fixed secret bytes, token, value.
struct Spec {
    owner: &'static str,
    sk_byte: u8,
    r_byte: u8,
    token: &'static str,
    amount: u64,
}

/// The canonical dev funding set (leaves 0..3 in listing order).
const SPECS: [Spec; 4] = [
    Spec {
        owner: "alice",
        sk_byte: 0xA1,
        r_byte: 0xA2,
        token: "ETH",
        amount: 2000,
    },
    Spec {
        owner: "alice",
        sk_byte: 0xA3,
        r_byte: 0xA4,
        token: "USDT",
        amount: 800_000,
    },
    Spec {
        owner: "bob",
        sk_byte: 0xB1,
        r_byte: 0xB2,
        token: "ETH",
        amount: 1500,
    },
    Spec {
        owner: "bob",
        sk_byte: 0xB3,
        r_byte: 0xB4,
        token: "USDT",
        amount: 600_000,
    },
];

/// Build the NoteRecord for one spec at `leaf`.
fn record(spec: &Spec, leaf: u64) -> NoteRecord {
    let sk = [spec.sk_byte; 32];
    let r = [spec.r_byte; 32];
    let cm = note_commit(
        npk_from_sk(fr_from_be_bytes(&sk)),
        asset_id(spec.token).expect("token symbol"),
        spec.amount,
        fr_from_be_bytes(&r),
    );
    NoteRecord {
        cm: note_fr_to_hex(&cm),
        token: spec.token.into(),
        amount: spec.amount,
        r: hex::encode(r),
        key_index: 0,
        sk: hex::encode(sk),
        leaf_index: leaf,
        status: NOTE_UNSPENT,
        nf: String::new(),
        pending_order: String::new(),
    }
}

fn main() {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut toml = String::new();
    let mut alice = Vec::new();
    let mut bob = Vec::new();
    for (leaf, spec) in SPECS.iter().enumerate() {
        let rec = record(spec, leaf as u64);
        toml.push_str(&format!(
            "[[account.genesis_note]]\ncm   = \"{}\"\nmemo = \"{} {} {}\"\n\n",
            rec.cm, spec.owner, spec.amount, spec.token
        ));
        if spec.owner == "alice" {
            alice.push(rec);
        } else {
            bob.push(rec);
        }
    }

    fs::write(
        out_dir.join("genesis_notes.toml"),
        toml.trim_end().to_string() + "\n",
    )
    .expect("write toml");
    fs::write(
        out_dir.join("alice_notes.json"),
        serde_json::to_string_pretty(&alice).unwrap(),
    )
    .expect("write alice notes");
    fs::write(
        out_dir.join("bob_notes.json"),
        serde_json::to_string_pretty(&bob).unwrap(),
    )
    .expect("write bob notes");
    println!(
        "wrote genesis_notes.toml, alice_notes.json, bob_notes.json to {}",
        out_dir.display()
    );
}
