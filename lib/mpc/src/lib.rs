//! MPC (Multi-Party Computation) library for Invisibook.
//!
//! Provides privacy-preserving comparison of two `u64` values using:
//! - 1-out-of-2 Oblivious Transfer (CO15 "Simplest OT")
//! - Beaver AND triples generated via OT
//! - EdaBits-style bit decomposition for secure `u64` comparison

pub mod beaver;
pub mod edabits;
pub mod error;
pub mod ot;

pub use edabits::compare_uint64;
pub use error::MpcError;
