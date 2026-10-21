//! Commit cell type script.
//!
//! A commit cell carries one L2 block header in the clear, in yu's protobuf
//! encoding. L1 records it and verifies nothing about it — no VRF proof, no
//! `goal`, no identity: the L2 nodes decode the header, recompute the block
//! hash from it and run every check themselves. `docs/ckb_layout.md` §5 has
//! the reasoning, §6 the checks that live off chain.
//!
//! That leaves this script one rule, R5.1: a cell it guards carries a
//! non-empty header of at most `MAX_HEADER_LEN` bytes. The cap keeps commit
//! cells from being used to park arbitrary data on L1. Spending is governed by
//! the lock alone (R5.2), so a miner reclaims the capacity once its height is
//! decided and this script has nothing to say about it.

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
use ckb_std::high_level::{QueryIter, load_cell_data};

/// Largest header a commit cell may carry. Must match
/// `consensus.MaxHeaderLen` on the L2 side.
const MAX_HEADER_LEN: usize = 4096;

/// Returned when a guarded output carries no data, or more than
/// `MAX_HEADER_LEN` bytes.
const ERR_BAD_HEADER_LEN: i8 = 1;

/// Entry point: enforces R5.1 over the outputs this script guards.
///
/// Only `GroupOutput` is examined. Inputs are deliberately left alone — a
/// commit cell is spent under its own lock when the miner reclaims the
/// capacity, and this script has no business gating that (R5.2).
pub fn program_entry() -> i8 {
    for data in QueryIter::new(load_cell_data, Source::GroupOutput) {
        if data.is_empty() || data.len() > MAX_HEADER_LEN {
            return ERR_BAD_HEADER_LEN;
        }
    }
    0
}
