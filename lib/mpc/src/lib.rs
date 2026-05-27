//! MPC (Multi-Party Computation) library for Invisibook.
//!
//! Pure Rust implementation of the settlement protocol using `ark-mpc`
//! (SPDZ-style 2-party computation over BN254).
//!
//! Architecture:
//! ```text
//! ┌─────────────┐       QUIC        ┌─────────────┐
//! │ Rust App    │◄──────────────────►│ Rust App    │
//! │ (Alice)     │                    │ (Bob)       │
//! │ settle()    │                    │ settle()    │
//! └─────────────┘                    └─────────────┘
//! ```
//!
//! # Usage
//! ```ignore
//! let result = mpc::settle(
//!     &SettleConfig {
//!         local_addr: "0.0.0.0:9000".parse()?,
//!         peer_addr: "192.168.1.101:9000".parse()?,
//!     },
//!     Side::Buy,
//!     my_value,
//!     my_random,
//!     c1, c2,
//! ).await?;
//! ```

pub mod compare;
pub mod constants;
pub mod error;
pub mod poseidon;
pub mod settle;

pub use error::MpcError;
pub use settle::{SettleConfig, SettleShare, Side, settle};
