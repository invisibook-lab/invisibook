use std::io;

use thiserror::Error;

/// Errors produced by the MPC protocol layer.
#[derive(Error, Debug)]
pub enum MpcError {
    /// Low-level networking or IO failure while setting up the QUIC transport.
    #[error("network error: {0}")]
    Network(String),

    /// SPDZ MAC authentication failure during an authenticated open.
    ///
    /// Returned whenever a counterparty deviates from the protocol in a way
    /// that breaks the linear MAC relation `mac = key * value`.
    #[error("authentication (MAC) failure")]
    Auth,

    /// The public Poseidon hash passed in does not match the value computed
    /// inside the MPC circuit against the shared input.
    #[error("poseidon hash mismatch for party {0}")]
    HashMismatch(u64),

    /// Failure inside the preprocessing / beaver triple source.
    #[error("beaver source error: {0}")]
    Beaver(String),

    /// A generic protocol-level failure not covered by the other variants.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Wrapped `std::io::Error` for transport / file IO.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}
