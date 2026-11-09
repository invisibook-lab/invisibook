//! # cozk2p — 2-party collaborative-ZK settlement
//!
//! A TWO-party (no helper node) collaborative prover for invisibook's
//! settlement prototype, built on renegade-fi's `mpc-jellyfish`
//! (collaborative TurboPlonk) over `ark-mpc` (2-party SPDZ machinery). The two
//! matched traders jointly prove the comparison statement of the single-prover
//! `settle_cozk.circom` (locked-only model: open both collateral commitments
//! via `needed(q, side)`, public `cmp = sign(q_a - q_b)`).
//!
//! This workspace is intentionally separate from `lib/` — it pins an older
//! nightly (see `rust-toolchain.toml`) because `ark-mpc` relies on the
//! unstable `inherent_associated_types` feature that regressed on newer
//! toolchains, and it uses the ark 0.4 ecosystem while `lib/` is on 0.5.
//!
//! Trust caveats (dev/testnet): the KZG SRS is derived from a public seed
//! (`setup.rs`) and the demo binaries use `PartyIDBeaverSource`, whose
//! predictable input masks let a counterparty recover the other input. The
//! configured demo therefore provides neither input privacy nor proof zero
//! knowledge. Production needs a ceremony SRS, a real SPDZ offline phase
//! (e.g. `ark-mpc-offline`'s LowGear), and complete MAC checks for every
//! authenticated opening.

pub mod constants;
pub mod ffi;
pub mod gadgets;
pub mod mpc_compare;
pub mod mpc_poseidon;
pub mod net;
pub mod poseidon;
pub mod proof_share;
pub mod prove;
pub mod relation;
pub mod session;
pub mod setup;
pub mod stats;

pub use proof_share::{
    CompareProofShare, combine_compare_proof_shares, decode_compare_proof_share_hex,
    deserialize_compare_proof_share, encode_compare_proof_share_hex, serialize_compare_proof_share,
};
pub use prove::{
    build_mpc_circuit, build_single_prover_circuit, prove_collaborative,
    prove_collaborative_share_timed, prove_single, verify_settle,
};
pub use relation::{SettlePublic, SidePrivate, compute_public, needed_collateral};
pub use setup::{default_cache_dir, dev_keys, sample_trade};
