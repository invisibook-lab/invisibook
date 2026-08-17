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
    prove_pair::build_pair_single_prover_circuit,
    relation::{SidePrivate, compute_public},
    relation_pair::{PAIR_PUBLIC_LEN, PairSidePrivate, PairStatementInputs, compute_pair_public},
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
    // A (maker) SELLS 80 token1 at price 3 (locks 80); B BUYS 60
    // (locks 180). Both flags/price ARE part of the statement now.
    let a = SidePrivate {
        order_amount: 80,
        r_locked: [0xA1; 32],
    };
    let b = SidePrivate {
        order_amount: 60,
        r_locked: [0xB1; 32],
    };
    (a, b, 3, true)
}

/// Bump when the relation changes in a way that keeps the same gate count
/// (the cache filename already includes gates/inputs, which move on
/// virtually any edit; this covers the rest).
///
/// v4: locked-only model — orders commit ONLY collateral; the statement is
/// [cmp, locked_a, locked_b, price, a_is_seller] and each quantity opens
/// its collateral via needed(q, side) in-circuit.
/// v5: the PUBLIC price and side flag are used as they are — their
/// in-circuit range/booleanity re-checks are gone.
const RELATION_VERSION: u32 = 5;

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
        5,
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

// ────────────────────── Merged (pair) relation keys ──────────────────────

/// A sample well-formed trade for the MERGED relation's keygen circuit
/// shape (values are irrelevant to `preprocess`). A sells 80 ETH at price
/// 3, B buys 60: A receives USDT, B receives ETH. Reused by tests/benches.
pub fn sample_pair_trade() -> (PairSidePrivate, PairSidePrivate, PairStatementInputs) {
    use crate::poseidon::asset_fr;
    let a = PairSidePrivate {
        order_amount: 80,
        r_order: [0xA1; 32],
        r_locked: [0xA2; 32],
        r_q_res: [0xA3; 32],
        r_locked_res: [0xA4; 32],
        recv_npk: ark_bn254::Fr::from(0xA5u64),
        r_note: [0xA6; 32],
    };
    let b = PairSidePrivate {
        order_amount: 60,
        r_order: [0xB1; 32],
        r_locked: [0xB2; 32],
        r_q_res: [0xB3; 32],
        r_locked_res: [0xB4; 32],
        recv_npk: ark_bn254::Fr::from(0xB5u64),
        r_note: [0xB6; 32],
    };
    let inputs = PairStatementInputs {
        price: 3,
        a_is_seller: true,
        asset_recv_a: asset_fr("USDT").expect("static symbol"),
        asset_recv_b: asset_fr("ETH").expect("static symbol"),
    };
    (a, b, inputs)
}

/// Bump when the merged relation changes without moving the gate count.
/// v1: initial merged statement (15 publics: cmp + payout notes +
/// residual pairs + order/collateral opens + trade parameters).
const PAIR_RELATION_VERSION: u32 = 1;

/// Generate (or load from `cache_dir`) the proving/verifying keys of the
/// MERGED relation. Same dev-SRS caveats as [`dev_keys`]; the two relations
/// share the SRS seed but have separate cache tags, so both key pairs can
/// coexist in one cache dir.
pub fn dev_keys_pair(cache_dir: &Path) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    warn_dev_srs_once();
    let (a, b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs);
    let circuit = build_pair_single_prover_circuit(&a, &b, &public)?;
    let tag = format!(
        "settlepair2p-{}x{}-{:x}-v{}",
        circuit.num_gates(),
        PAIR_PUBLIC_LEN,
        DEV_SRS_SEED,
        PAIR_RELATION_VERSION
    );
    let pk_path = cache_dir.join(format!("{tag}.pk"));
    let vk_path = cache_dir.join(format!("{tag}.vk"));
    if pk_path.exists() && vk_path.exists() {
        let pk =
            ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(fs::read(&pk_path)?.as_slice())
                .map_err(|e| anyhow!("parsing cached pair pk: {e}"))?;
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(
            fs::read(&vk_path)?.as_slice(),
        )
        .map_err(|e| anyhow!("parsing cached pair vk: {e}"))?;
        return Ok((pk, vk));
    }

    // The padded evaluation domain must fit the SRS: srs_size = domain + 2,
    // and `num_gates()` after finalize IS the padded domain size.
    anyhow::ensure!(
        circuit.num_gates() + 2 <= MAX_DEGREE,
        "merged relation ({} gates) exceeds the dev SRS (MAX_DEGREE = {}); bump MAX_DEGREE",
        circuit.num_gates(),
        MAX_DEGREE
    );

    let mut rng = StdRng::seed_from_u64(DEV_SRS_SEED);
    let srs = PlonkKzgSnark::<Bn254>::universal_setup_for_testing(MAX_DEGREE, &mut rng)
        .map_err(|e| anyhow!("dev SRS generation: {e}"))?;

    let (pk, vk) = PlonkKzgSnark::<Bn254>::preprocess(&srs, &circuit)
        .map_err(|e| anyhow!("preprocess: {e}"))?;

    fs::create_dir_all(cache_dir).context("creating key cache dir")?;
    let write_atomic = |path: &Path, buf: &[u8]| -> Result<()> {
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&tmp, buf)?;
        fs::rename(&tmp, path)?;
        Ok(())
    };
    let mut buf = Vec::new();
    pk.serialize_uncompressed(&mut buf)
        .map_err(|e| anyhow!("serializing pair pk: {e}"))?;
    write_atomic(&pk_path, &buf)?;
    buf.clear();
    vk.serialize_uncompressed(&mut buf)
        .map_err(|e| anyhow!("serializing pair vk: {e}"))?;
    write_atomic(&vk_path, &buf)?;

    Ok((pk, vk))
}

/// Number of constraints in the merged settlement circuit (for reporting).
pub fn pair_circuit_size() -> Result<usize> {
    let (a, b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs);
    let circuit = build_pair_single_prover_circuit(&a, &b, &public)?;
    Ok(circuit.num_gates())
}

/// Number of constraints in the settlement circuit (for reporting).
pub fn circuit_size() -> Result<usize> {
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller)?;
    let circuit = build_single_prover_circuit(&a, &b, &public)?;
    Ok(circuit.num_gates())
}
