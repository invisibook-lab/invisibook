//! MPC (Multi-Party Computation) library for Invisibook.
//!
//! Provides privacy-preserving comparison of two `u64` values.
//!
//! # Backend
//! The implementation will be built on top of **emp-ag2pc** (2-party garbled circuits).
//! The stubs below define the public interface; the internals are TODO.

pub mod error;

pub use error::MpcError;

/// Securely compare two secret `u64` values.
///
/// P0 provides `x`, P1 provides `y`. Returns `true` if `x > y`.
///
/// In a real deployment P0 and P1 run on separate machines and communicate
/// via the emp-ag2pc protocol; neither party learns the other's value.
///
/// # Errors
/// Returns [`MpcError`] if the underlying protocol fails.
///
/// TODO: implement with emp-ag2pc.
pub fn compare_uint64(_x: u64, _y: u64) -> Result<bool, MpcError> {
    Err(MpcError::NotImplemented)
}

/// Same as [`compare_uint64`] but returns raw XOR output shares `(share0, share1)`.
///
/// `share0 XOR share1 == true` iff `x > y`. Each party receives only their
/// own share, so neither learns the result directly.
///
/// TODO: implement with emp-ag2pc.
pub fn compare_uint64_shares(_x: u64, _y: u64) -> Result<(bool, bool), MpcError> {
    Err(MpcError::NotImplemented)
}
