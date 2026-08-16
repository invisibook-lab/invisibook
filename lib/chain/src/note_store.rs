//! The wallet's local note ledger — with no on-chain note ciphertexts,
//! **this file IS the money**: every note the wallet owns is recorded here
//! with its full opening (value, blinding, tree position). Lose it and the
//! funds are unrecoverable; the mnemonic alone cannot rebuild it.
//!
//! Protocol rule (persist-before-publish): a record for an incoming note
//! MUST be durably written (`save` fsyncs) BEFORE the transaction that
//! creates the note is submitted to the chain.

use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

/// Lifecycle of a locally-tracked note.
pub const NOTE_UNSPENT: u8 = 0;
/// A spend referencing this note has been submitted but not yet confirmed.
pub const NOTE_PENDING_SPEND: u8 = 1;
/// The note's nullifier is on chain.
pub const NOTE_SPENT: u8 = 2;
/// The mint transaction was submitted but the leaf index is not yet known.
pub const NOTE_PENDING_MINT: u8 = 3;

/// One owned note's full opening plus its chain position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteRecord {
    /// 64-char hex commitment — the note's identity in the tree.
    pub cm: String,
    pub token: String,
    pub amount: u64,
    /// 64-char hex blinding (big-endian Fr bytes).
    pub r: String,
    /// Key index of the spending secret (SLIP-0010 note path index).
    pub key_index: u32,
    /// Leaf index in the tree; meaningful once status leaves PENDING_MINT.
    #[serde(default)]
    pub leaf_index: u64,
    pub status: u8,
    /// The nullifier this wallet computed when spending (64-char hex);
    /// empty until a spend is attempted.
    #[serde(default)]
    pub nf: String,
}

/// Persistent JSON store for owned notes. Backed by one file on disk;
/// `save` writes via a temp file + rename and fsyncs, so a crash never
/// leaves a truncated ledger.
pub struct NoteStore {
    path: PathBuf,
    records: Vec<NoteRecord>,
}

impl NoteStore {
    /// Load from `path`; an absent file is an empty store.
    pub fn load(path: PathBuf) -> Self {
        let records = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, records }
    }

    /// Default location: `~/.invisibook/notes.json`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".invisibook")
            .join("notes.json")
    }

    /// Load from a file next to a config-specified data dir.
    pub fn load_from_file(path: PathBuf) -> Self {
        Self::load(path)
    }

    /// Durably persist the ledger: temp file, fsync, atomic rename.
    /// MUST succeed before any note-creating transaction is submitted.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let data = serde_json::to_string_pretty(&self.records)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }

    pub fn records(&self) -> &[NoteRecord] {
        &self.records
    }

    /// Insert or replace by commitment.
    pub fn upsert(&mut self, rec: NoteRecord) {
        if let Some(existing) = self.records.iter_mut().find(|r| r.cm == rec.cm) {
            *existing = rec;
        } else {
            self.records.push(rec);
        }
    }

    /// Find a record by commitment.
    pub fn find(&self, cm: &str) -> Option<&NoteRecord> {
        self.records.iter().find(|r| r.cm == cm)
    }

    /// Mutable lookup by commitment.
    pub fn find_mut(&mut self, cm: &str) -> Option<&mut NoteRecord> {
        self.records.iter_mut().find(|r| r.cm == cm)
    }

    /// All unspent notes of `token`, largest first (coin selection order).
    pub fn unspent(&self, token: &str) -> Vec<&NoteRecord> {
        let mut out: Vec<&NoteRecord> = self
            .records
            .iter()
            .filter(|r| r.token == token && r.status == NOTE_UNSPENT)
            .collect();
        out.sort_by(|a, b| b.amount.cmp(&a.amount));
        out
    }

    /// Spendable balance per token.
    pub fn balance(&self, token: &str) -> u64 {
        self.unspent(token).iter().map(|r| r.amount).sum()
    }

    /// Mark the notes behind `nfs` spent once their nullifiers appear on
    /// chain; returns how many records changed.
    pub fn mark_spent(&mut self, nfs: &[String]) -> usize {
        let mut changed = 0;
        for r in &mut self.records {
            if !r.nf.is_empty() && nfs.contains(&r.nf) && r.status != NOTE_SPENT {
                r.status = NOTE_SPENT;
                changed += 1;
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip_and_balance() {
        let dir = std::env::temp_dir().join(format!("note_store_test_{}", std::process::id()));
        let path = dir.join("notes.json");
        let mut store = NoteStore::load(path.clone());
        store.upsert(NoteRecord {
            cm: "aa".into(),
            token: "ETH".into(),
            amount: 7,
            r: "33".into(),
            key_index: 0,
            leaf_index: 0,
            status: NOTE_UNSPENT,
            nf: String::new(),
        });
        store.upsert(NoteRecord {
            cm: "bb".into(),
            token: "ETH".into(),
            amount: 5,
            r: "35".into(),
            key_index: 0,
            leaf_index: 2,
            status: NOTE_UNSPENT,
            nf: String::new(),
        });
        store.save().unwrap();

        let reloaded = NoteStore::load(path);
        assert_eq!(reloaded.records().len(), 2);
        assert_eq!(reloaded.balance("ETH"), 12);
        assert_eq!(reloaded.unspent("ETH")[0].amount, 7, "largest first");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mark_spent_by_nullifier() {
        let dir = std::env::temp_dir().join(format!("note_store_test2_{}", std::process::id()));
        let mut store = NoteStore::load(dir.join("notes.json"));
        store.upsert(NoteRecord {
            cm: "aa".into(),
            token: "ETH".into(),
            amount: 7,
            r: "33".into(),
            key_index: 0,
            leaf_index: 0,
            status: NOTE_PENDING_SPEND,
            nf: "deadbeef".into(),
        });
        assert_eq!(store.mark_spent(&["deadbeef".to_string()]), 1);
        assert_eq!(store.balance("ETH"), 0);
        let _ = fs::remove_dir_all(dir);
    }
}
