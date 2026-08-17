//! Grep-gate for the Phase 5 cash→note migration: the deleted cash-model
//! identifiers must NEVER reappear in source, and the Poseidon(0,0)
//! zero-commitment constant may exist ONLY where it pads the order's
//! 2-slot collateral shape. Runs as a plain test so a regression fails CI
//! without any extra tooling.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Identifiers of the deleted cash model. A hit anywhere in scanned source
/// is a migration regression.
const FORBIDDEN: &[&str] = &[
    "computeCashID",
    "compute_cash_id",
    "CashStore",
    "CashRecord",
    "CashScheme",
    "CashSelection",
    "select_cash",
    "genesis_cash",
    "GenesisCash",
    "split.circom",
    "prove_split",
    "SplitWitness",
    "encrypt_amount",
    "genesis_encrypt",
    "cash.json",
    "GetAccountRequest",
    "FindNonSpentCash",
];

/// Files allowed to mention the Poseidon(0,0) zero commitment — exactly
/// the definition sites and the collateral-pad users.
const ZERO_COMMITMENT_ALLOWED: &[&str] = &[
    // Go: constant definition + the 2-slot collateral pad + its unit test.
    "chain/core/zkverify.go",
    "chain/core/orderbook.go",
    "chain/core/zkverify_test.go",
    // Rust: the app-side pad constant and the session-side pad check.
    "app/ui/src/settle.rs",
    "cozk2p/src/session.rs",
    "cozk2p/src/poseidon.rs",
    // The spend circuits treat the padded slot as a spent-nothing input.
    "lib/zk/templates/commitments.circom",
    // Wallet-side helper rendering of Poseidon(0,0) (dev utility).
    "lib/zk/examples/show_zero_commit.rs",
    // Chain client docs referencing the pad convention.
    "lib/chain/src/chain.rs",
];

/// Source sub-trees to scan, relative to the repo root.
const SCAN_ROOTS: &[&str] = &[
    "chain/core",
    "chain/test",
    "chain/consensus",
    "lib/chain/src",
    "lib/chain/examples",
    "lib/zk/src",
    "lib/zk/examples",
    "lib/zk/templates",
    "app/ui/src",
    "app/ui/tests",
    "app/desktop/src",
    "app/mobile/src",
    "cozk2p/src",
    "cozk2p/tests",
    "chain/cfg",
    "scripts",
];

/// Repo root, two levels up from this crate's manifest dir (`lib/chain`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// Recursively collect source files under `dir` (skips build outputs).
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if name == "target" || name == "data" || name.starts_with('.') {
                continue;
            }
            collect(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "go" | "circom" | "toml" | "sh" | "json")
        ) {
            out.push(path);
        }
    }
}

/// Every scanned file, with its repo-relative slash path.
fn scan_files() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    for sub in SCAN_ROOTS {
        collect(&root.join(sub), &mut files);
    }
    files
        .into_iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(&root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let content = fs::read_to_string(&p).ok()?;
            Some((rel, content))
        })
        .collect()
}

/// No deleted cash-model identifier may reappear anywhere in source.
#[test]
fn cash_model_identifiers_are_gone() {
    let mut hits = Vec::new();
    for (rel, content) in scan_files() {
        // The gate itself names the forbidden strings.
        if rel.ends_with("tests/model_gate.rs") {
            continue;
        }
        for needle in FORBIDDEN {
            if content.contains(needle) {
                hits.push(format!("{rel}: contains {needle:?}"));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "cash-model identifiers resurfaced:\n{}",
        hits.join("\n")
    );
}

/// The Poseidon(0,0) zero commitment exists ONLY as the collateral pad
/// (definition sites + 2-slot pad users). Any new use needs an explicit
/// allow-list entry AND a design reason.
#[test]
fn zero_commitment_only_pads_collateral() {
    // The constant in both of its renderings (decimal and hex).
    let needles = [
        "PoseidonZeroCommitment",
        "POSEIDON_ZERO_COMMITMENT",
        "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
        "14744269619966411208579211824598458697587494354926760081771325075741142829156",
    ];
    let mut hits = Vec::new();
    for (rel, content) in scan_files() {
        if rel.ends_with("tests/model_gate.rs") {
            continue;
        }
        if ZERO_COMMITMENT_ALLOWED.iter().any(|a| rel == *a) {
            continue;
        }
        for needle in needles {
            if content.contains(needle) {
                hits.push(format!("{rel}: contains {needle:?}"));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "zero-commitment constant used outside the collateral pad:\n{}",
        hits.join("\n")
    );
}
