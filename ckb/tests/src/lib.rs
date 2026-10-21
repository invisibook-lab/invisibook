//! Test-only crate: the rule tests for the CKB contracts live in `tests/`.
//!
//! It carries no code of its own. The contracts are RISC-V binaries that the
//! tests load from disk and execute inside a transaction, so nothing here is
//! ever linked against them.
