//! The wallet's local order-opening ledger. The chain stores an order's
//! quantity and collateral only as commitments (`Order.Amount` = cm_q,
//! `Order.LockedCommitment`); the plaintext values and blindings exist
//! ONLY here. Settlement cannot open the on-chain rows without this file.
//!
//! Protocol rule (persist-before-publish): the opening for a new order
//! MUST be durably written (`save` fsyncs) BEFORE the SendOrder that
//! creates the order is submitted. On a relist, the residual opening MUST
//! be written before the SettlePair that swaps the on-chain commitments.

use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

/// One order's full opening: everything needed to open its on-chain
/// quantity and collateral commitments at settle time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderOpening {
    /// The on-chain order id (SHA-256 over the input nullifiers).
    pub order_id: String,
    /// Hidden order quantity q (token1 units) that `Order.Amount` commits to.
    pub q: u64,
    /// 64-char hex blinding of the cm_q commitment.
    pub r_q: String,
    /// Hidden collateral value `Order.LockedCommitment` commits to
    /// (= q for a sell, q·price for a buy).
    pub locked_amount: u64,
    /// 64-char hex blinding of the collateral commitment.
    pub r_locked: String,
    /// Token the collateral is denominated in (Buy → token2, Sell → token1).
    pub lock_token: String,
}

/// Persistent JSON store for order openings. Backed by one file on disk;
/// `save` writes via a temp file + rename and fsyncs, so a crash never
/// leaves a truncated ledger.
pub struct OrderStore {
    path: PathBuf,
    records: Vec<OrderOpening>,
}

impl OrderStore {
    /// Load from `path`; an absent file is an empty store.
    pub fn load(path: PathBuf) -> Self {
        let records = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, records }
    }

    /// Durably persist the ledger: temp file, fsync, atomic rename.
    /// MUST succeed before the order-creating transaction is submitted.
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

    pub fn records(&self) -> &[OrderOpening] {
        &self.records
    }

    /// Insert or replace by order id (a relist REPLACES the opening with
    /// the residual one — the old blindings are useless once the chain row
    /// carries the residual commitments).
    pub fn upsert(&mut self, rec: OrderOpening) {
        if let Some(existing) = self.records.iter_mut().find(|r| r.order_id == rec.order_id) {
            *existing = rec;
        } else {
            self.records.push(rec);
        }
    }

    /// Find an opening by order id.
    pub fn find(&self, order_id: &str) -> Option<&OrderOpening> {
        self.records.iter().find(|r| r.order_id == order_id)
    }

    /// Drop an opening once its order is Done (nothing left to open).
    /// Returns true when a record was removed.
    pub fn remove(&mut self, order_id: &str) -> bool {
        let before = self.records.len();
        self.records.retain(|r| r.order_id != order_id);
        self.records.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store(tag: &str) -> OrderStore {
        let dir =
            std::env::temp_dir().join(format!("order_store_test_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        OrderStore::load(dir.join("orders.json"))
    }

    fn rec(id: &str, q: u64) -> OrderOpening {
        OrderOpening {
            order_id: id.into(),
            q,
            r_q: "aa".repeat(32),
            locked_amount: q * 3,
            r_locked: "bb".repeat(32),
            lock_token: "USDT".into(),
        }
    }

    /// Save/load round trip; upsert replaces in place (the relist path).
    #[test]
    fn round_trip_and_relist_upsert() {
        let mut store = tmp_store("rt");
        store.upsert(rec("order-1", 10));
        store.upsert(rec("order-2", 20));
        // Relist: same id, residual quantity — must replace, not append.
        store.upsert(rec("order-1", 4));
        store.save().unwrap();

        let reloaded = OrderStore::load(store.path.clone());
        assert_eq!(reloaded.records().len(), 2);
        assert_eq!(reloaded.find("order-1").unwrap().q, 4);
        assert!(reloaded.find("missing").is_none());
        let _ = fs::remove_dir_all(store.path.parent().unwrap());
    }

    /// Remove drops exactly the named order.
    #[test]
    fn remove_done_order() {
        let mut store = tmp_store("rm");
        store.upsert(rec("order-1", 10));
        assert!(store.remove("order-1"));
        assert!(!store.remove("order-1"));
        assert!(store.records().is_empty());
    }
}
