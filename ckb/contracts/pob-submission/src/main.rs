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
/// TODO: enforce R4.1 — the created cell's data is exactly 32 bytes — and
/// nothing else. Spending is left to the lock (R4.2), so there is no branch
/// for it here. The budget cell's own rules (R3.1~R3.4) belong to a separate
/// `budget_type_script` that does not exist yet.
pub fn program_entry() -> i8 {
    ERR_UNIMPLEMENTED
}
