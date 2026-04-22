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

    /// Add a record and persist to disk.
    pub fn add(&mut self, record: CashRecord) -> Result<(), Box<dyn std::error::Error>> {
        self.records.push(record);
        self.save()
    }

    /// Merge records from another JSON file.
    /// Returns the number of new records added.
    pub fn merge_from_file(
        &mut self,
        path: &PathBuf,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let incoming: Vec<CashRecord> = serde_json::from_str(&content)?;
        let before = self.records.len();
        for rec in incoming {
            if !self.records.iter().any(|r| r.cash_id == rec.cash_id) {
                self.records.push(rec);
            }
        }
        self.save()?;
        Ok(self.records.len() - before)
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
