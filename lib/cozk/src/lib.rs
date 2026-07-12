//! Collaborative zero-knowledge settlement proving (Protocol 1, "PPS based on
//! mpc-co-zk") on top of the co-snarks stack.
//!
//! Two matched traders jointly generate ONE Groth16 proof for the
//! `settle_cozk` circuit without revealing their hidden amounts to each other.
//! The MPC runs as REP3 replicated secret sharing over exactly three nodes:
//!
//! - node 0 — trader A (the maker),
//! - node 1 — trader B (the taker),
//! - node 2 — a neutral helper (assumed not to collude with either trader).
//!
//! Each trader splits its private circuit inputs into three share maps
//! ([`split_trader_input`]) and hands one map to every node. Each node merges
//! the two maps it received, runs MPC witness extension, collaborative
//! Groth16 proving, and finally verifies the proof locally before releasing
//! it ([`prove_party`]) — a non-verifying proof must never be published
//! because proofs over invalid witnesses leak information about the honest
//! trader's witness (see docs/cozk_design.md §7).
//!
//! The resulting proof is byte-compatible with snarkjs / go-rapidsnark: the
//! chain verifies it exactly like the single-prover proofs.

pub mod artifacts;
pub mod local;
pub mod net;
pub mod protocol;

pub use artifacts::{SettleArtifacts, default_circuit_path, default_link_dir, load_artifacts};
pub use local::{LocalSettleOutcome, run_local_settle};
pub use net::tcp_networks;
pub use protocol::{
    PartyOutput, PhaseStats, Role, peak_rss_bytes, prove_party, split_trader_input,
};
