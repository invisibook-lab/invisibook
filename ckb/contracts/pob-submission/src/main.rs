//! Commit cell type script.
//!
//! A bid reaches L1 as a commitment and nothing else, because a transaction's
//! witness is as visible to an L1 block producer as its data is: anything the
//! script could check, a censor could read. So L1 verifies no VRF proof, no
//! `goal`, no identity and no zero-knowledge proof — it timestamps an opaque
//! 32-byte value, and the L2 nodes do every check once the opening reaches
//! them over the L2 network. `docs/ckb_layout.md` §5 has the reasoning, §6 the
//! checks that live off chain.
//!
//! That leaves this script one rule, R5.1: a cell it guards carries exactly 32
//! bytes. Spending is governed by the lock alone (R5.2), so a miner reclaims
//! the capacity once its height is decided and this script has nothing to say
//! about it.

#![no_std]
#![cfg_attr(not(test), no_main)]

// Under `entry!` the ckb-std macro declares `extern crate alloc` itself, so
// this one is only needed when that macro is compiled out.
#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

use ckb_std::ckb_constants::Source;
use ckb_std::high_level::{load_cell_data, QueryIter};

/// Length of the commitment a commit cell carries: SHA256 output.
const COMMITMENT_LEN: usize = 32;

/// Returned when a guarded output carries anything but a 32-byte commitment.
const ERR_BAD_COMMITMENT_LEN: i8 = 1;

/// Entry point: enforces R5.1 over the outputs this script guards.
///
/// Only `GroupOutput` is examined. Inputs are deliberately left alone — a
/// commit cell is spent under its own lock when the miner reclaims the
/// capacity, and this script has no business gating that (R5.2).
pub fn program_entry() -> i8 {
    for data in QueryIter::new(load_cell_data, Source::GroupOutput) {
        if data.len() != COMMITMENT_LEN {
            return ERR_BAD_COMMITMENT_LEN;
        }
    }
    0
}
