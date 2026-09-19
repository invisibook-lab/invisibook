//! Commit cell type script.
//!
//! A bid reaches L1 as a commitment and nothing else, because a transaction's
//! witness is as visible to an L1 block producer as its data is: anything the
//! script could check, a censor could read. So L1 verifies no VRF proof, no
//! `goal`, no identity and no zero-knowledge proof — it timestamps an opaque
//! 32-byte value, and the L2 nodes do every check once the opening reaches
//! them over the L2 network. `docs/ckb_layout.md` §4 has the reasoning, §5 the
//! checks that moved off chain.
//!
//! That leaves this script with exactly one rule, R4.1: the cell's data is 32
//! bytes. Spending is governed by the lock alone (R4.2), so a miner reclaims
//! the capacity once its height is decided.
//!
//! Not implemented yet, so the script refuses everything. A type script that
//! returned success while checking nothing would accept any transaction at
//! all, which is a far worse thing to leave lying around than one that plainly
//! does not work.

#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

/// Returned while the rules are unimplemented, so the script fails closed.
const ERR_UNIMPLEMENTED: i8 = 1;

/// Entry point.
///
/// TODO: split this crate in two. The commit script only enforces R3.1. The
/// reveal script consumes the commit cell, reads the opening from the witness,
/// loads the budget cell and the anchor through `cell_deps` and the commit
/// cell's block through `header_deps`, then enforces R4.1 through R4.7.
/// `ckb_vrf::verify` supplies the VRF half of R4.3 and is already cross-checked
/// against the L2 prover.
pub fn program_entry() -> i8 {
    ERR_UNIMPLEMENTED
}
