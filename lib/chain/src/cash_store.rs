use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A locally-kept record of a cash output the client owns.
/// The chain stores only `amount = poseidon(amount_plaintext, random)`;
/// plaintext and random are never sent to the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashRecord {
    pub cash_id: String,
    pub token: String,
    pub amount: u64,
    pub random: String, // hex-encoded 32-byte random
    pub status: u8,     // 0 = Active, 1 = Locked, 2 = Spent
}

/// Persistent store for (cashID, amount, random) tuples.
/// Backed by a JSON file on disk.
pub struct CashStore {
    path: PathBuf,
    records: Vec<CashRecord>,
}

impl CashStore {
    /// Load from `path`, creating an empty store if the file does not exist.
    pub fn load(path: PathBuf) -> Self {
        let records = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, records }
    }

    /// Default path: `~/.invisibook/cash.json`
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".invisibook")
            .join("cash.json")
    }

    pub fn records(&self) -> &[CashRecord] {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut Vec<CashRecord> {
        &mut self.records
    }

    /// Add a record and persist to disk.
    pub fn add(&mut self, record: CashRecord) -> Result<(), Box<dyn std::error::Error>> {
        self.records.push(record);
        self.save()
    }

    /// Import records from a JSON file, replacing any existing records for the
    /// same tokens. This prevents stale cash IDs (from old sessions or old
    /// pubkeys) from being mixed with fresh ones.
    /// Returns the number of records loaded from the file.
    pub fn load_from_file(
        &mut self,
        path: &PathBuf,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let incoming: Vec<CashRecord> = serde_json::from_str(&content)?;
        // Collect the tokens present in the file
        let tokens: std::collections::HashSet<&str> =
            incoming.iter().map(|r| r.token.as_str()).collect();
        // Drop all existing records for those tokens
        self.records.retain(|r| !tokens.contains(r.token.as_str()));
        // Insert the fresh records
        let n = incoming.len();
        self.records.extend(incoming);
        self.save()?;
        Ok(n)
    }

    /// Persist current records to disk. Call after mutating via `records_mut()`.
    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.save()
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.records)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}
