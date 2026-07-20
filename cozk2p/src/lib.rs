//! # cozk2p — 2-party collaborative-ZK settlement
//!
//! A TWO-party (no helper node) collaborative prover for invisibook's
//! privacy-preserving settlement, built on renegade-fi's `mpc-jellyfish`
//! (collaborative TurboPlonk) over `ark-mpc` (malicious-secure 2-party
//! SPDZ). The two matched traders jointly prove the same settlement
//! statement as the 3-party `lib/cozk` path (open both order commitments,
//! public `cmp = sign(a-b)`, remainder updates, collateral/receive
//! commitments) without either learning the other's amounts.
//!
//! This workspace is intentionally separate from `lib/` — it pins an older
//! nightly (see `rust-toolchain.toml`) because `ark-mpc` relies on the
//! unstable `inherent_associated_types` feature that regressed on newer
//! toolchains, and it uses the ark 0.4 ecosystem while `lib/` is on 0.5.
//!
//! Trust caveats (dev/testnet): the KZG SRS is derived from a public seed
//! (`setup.rs`) and the demo binaries use `PartyIDBeaverSource` mock Beaver
//! triples; production needs a ceremony SRS and a real SPDZ offline phase
//! (e.g. `ark-mpc-offline`'s LowGear).

pub mod constants;
pub mod gadgets;
pub mod net;
pub mod poseidon;
pub mod prove;
pub mod relation;
pub mod setup;
pub mod stats;

pub use prove::{
    build_mpc_circuit, build_single_prover_circuit, prove_collaborative, prove_single,
    verify_settle,
};
pub use relation::{SettlePublic, SidePrivate, compute_public};
pub use setup::{default_cache_dir, dev_keys, sample_trade};
