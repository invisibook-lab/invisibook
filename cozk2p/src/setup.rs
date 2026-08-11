//! Dev key generation for the 2-party settlement relation.
//!
//! The KZG SRS is generated from a FIXED seed so both traders derive the
//! identical proving/verifying key without exchanging files. Like the
//! 3-party path's snarkjs dev setup, this is a **dev-only trusted setup**
//! (the toxic tau is derivable from the public seed); a production
//! deployment must swap in a real ceremony SRS (e.g. a Perpetual Powers of
//! Tau export).

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use ark_bn254::Bn254;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mpc_plonk::proof_system::{
    PlonkKzgSnark, UniversalSNARK,
    structs::{ProvingKey, VerifyingKey},
};
use mpc_relation::traits::Circuit;
use rand::{SeedableRng, rngs::StdRng};

use crate::{
    prove::build_single_prover_circuit,
    relation::{SidePrivate, compute_public},
};

/// Max SRS degree — the settlement circuit is ~9k gates, so 32768 leaves
/// ample headroom for the padded evaluation domain.
pub const MAX_DEGREE: usize = 1 << 15;

/// Fixed dev-SRS seed. Public and reproducible — DEV ONLY, see module docs.
const DEV_SRS_SEED: u64 = 0x1B00C_C02C;

/// Print a one-time warning that these keys come from a publicly reproducible
/// dev SRS (forgeable). Guarded by `Once` so repeated `dev_keys` calls (the
/// app and both party processes all call it) emit it at most once per process.
fn warn_dev_srs_once() {
    use std::sync::Once;
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "WARNING [cozk2p]: using the fixed-seed dev KZG SRS — the toxic tau \
             is publicly recomputable and any proof can be forged. DEV/TESTNET \
             ONLY; swap in a ceremony SRS before touching real value."
        );
    });
}

/// A sample well-formed trade used only to instantiate the circuit shape for
/// key generation (witness values are irrelevant to `preprocess`; only the
/// gate/permutation structure matters). Also reused by tests and benches.
pub fn sample_trade() -> (SidePrivate, SidePrivate, u64, bool) {
    let a = SidePrivate {
        order_amount: 80,
        r_order: [0xA1; 32],
        r_order_new: [0xA2; 32],
        locked: vec![(80, [0xA3; 32])],
        r_locked_new: [0xA4; 32],
        r_recv: [0xA5; 32],
    };
    let b = SidePrivate {
        order_amount: 60,
        r_order: [0xB1; 32],
        r_order_new: [0xB2; 32],
        locked: vec![(180, [0xB3; 32])],
        r_locked_new: [0xB4; 32],
        r_recv: [0xB5; 32],
    };
    (a, b, 3, true)
}

/// Bump when the relation changes in a way that keeps the same gate count
/// (the cache filename already includes gates/inputs, which move on
/// virtually any edit; this covers the rest).
///
/// v2: added the 64-bit cap on each side's locked-collateral sum. The padded
/// gate count stayed at 8192, so the cache tag would otherwise have been
/// unchanged and a stale key silently reused.
const RELATION_VERSION: u32 = 2;

/// Generate (or load from `cache_dir`) the proving and verifying keys.
/// Deterministic across machines: fixed-seed SRS + fixed circuit shape.
/// The cache filename is fingerprinted by the circuit shape so a stale
/// cache from an older relation can never be silently loaded (the two
/// parties proving — and locally verifying — against outdated keys would
/// otherwise succeed while attesting the wrong statement).
pub fn dev_keys(cache_dir: &Path) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    warn_dev_srs_once();
    // Build the (cheap) keygen circuit first: its shape keys the cache.
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller)?;
    let circuit = build_single_prover_circuit(&a, &b, &public)?;
    let tag = format!(
        "settle2p-{}x{}-{:x}-v{}",
        circuit.num_gates(),
        15,
        DEV_SRS_SEED,
        RELATION_VERSION
    );
    let pk_path = cache_dir.join(format!("{tag}.pk"));
    let vk_path = cache_dir.join(format!("{tag}.vk"));
    if pk_path.exists() && vk_path.exists() {
        let pk =
            ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(fs::read(&pk_path)?.as_slice())
                .map_err(|e| anyhow!("parsing cached pk: {e}"))?;
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(
            fs::read(&vk_path)?.as_slice(),
        )
        .map_err(|e| anyhow!("parsing cached vk: {e}"))?;
        return Ok((pk, vk));
    }

    let mut rng = StdRng::seed_from_u64(DEV_SRS_SEED);
    let srs = PlonkKzgSnark::<Bn254>::universal_setup_for_testing(MAX_DEGREE, &mut rng)
        .map_err(|e| anyhow!("dev SRS generation: {e}"))?;

    let (pk, vk) = PlonkKzgSnark::<Bn254>::preprocess(&srs, &circuit)
        .map_err(|e| anyhow!("preprocess: {e}"))?;

    fs::create_dir_all(cache_dir).context("creating key cache dir")?;
    // Write via temp file + rename so two concurrently cold-starting party
    // processes sharing the cache dir cannot tear each other's files.
    let write_atomic = |path: &Path, buf: &[u8]| -> Result<()> {
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp, buf)?;
        fs::rename(&tmp, path)?;
        Ok(())
    };
    let mut buf = Vec::new();
    pk.serialize_uncompressed(&mut buf)
        .map_err(|e| anyhow!("serializing pk: {e}"))?;
    write_atomic(&pk_path, &buf)?;
    buf.clear();
    vk.serialize_uncompressed(&mut buf)
        .map_err(|e| anyhow!("serializing vk: {e}"))?;
    write_atomic(&vk_path, &buf)?;

    Ok((pk, vk))
}

/// Default key cache directory: `<workspace>/target/settle2p-keys`.
pub fn default_cache_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/settle2p-keys")
}

/// Number of constraints in the settlement circuit (for reporting).
pub fn circuit_size() -> Result<usize> {
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller)?;
    let circuit = build_single_prover_circuit(&a, &b, &public)?;
    Ok(circuit.num_gates())
}
