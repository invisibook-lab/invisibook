//! Loading of the artifacts every MPC node needs: the MPC-compiled circuit,
//! the snarkjs Groth16 proving key, and the verifying key.

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use ark_bn254::{Bn254, Fr};
use ark_groth16::VerifyingKey;
use co_circom::{
    CheckElement, CoCircomCompiler, CoCircomCompilerParsed, CompilerConfig, ConstraintMatrices,
    Groth16JsonVerificationKey, Groth16ZKey, ProvingKey, SimplificationLevel,
};

/// Everything one MPC node needs to run collaborative settlement proving.
/// All three nodes must load byte-identical artifacts (same circuit source,
/// same compiler settings, same zkey) or the shared witness will not match
/// the proving key's constraint matrices.
pub struct SettleArtifacts {
    /// The circuit parsed by the co-circom MPC compiler (used by the MPC
    /// witness-extension VM).
    pub circuit: CoCircomCompilerParsed<Fr>,
    /// Names of the circuit's public input signals, in declaration order.
    pub public_input_names: Vec<String>,
    /// Groth16 proving key converted from the snarkjs zkey.
    pub pkey: ProvingKey<Bn254>,
    /// R1CS matrices converted from the snarkjs zkey.
    pub matrices: ConstraintMatrices<Fr>,
    /// Verifying key for the mandatory verify-before-release check.
    pub vk: VerifyingKey<Bn254>,
}

/// Path of the `settle_cozk` circom source inside this repository.
pub fn default_circuit_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zk/templates/settle_cozk.circom")
}

/// Directory holding the circomlib helper templates the circuit includes.
pub fn default_link_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zk/templates")
}

/// Compiler settings that MUST mirror how the snarkjs zkey was produced:
/// `lib/zk` compiles `settle_cozk` with `circom --O2` (full constraint
/// simplification), so the MPC compiler runs at O2 as well — otherwise the
/// extended witness layout would not satisfy the zkey's matrices.
fn compiler_config(link_dir: &Path) -> CompilerConfig {
    CompilerConfig {
        version: "2.2.3".to_owned(),
        link_library: vec![link_dir.to_path_buf()],
        simplification: SimplificationLevel::O2(usize::MAX),
        ..Default::default()
    }
}

/// Load all proving artifacts for one MPC node. `circuit_path` must point at
/// `settle_cozk.circom`, `link_dir` at the templates directory it includes
/// from, `zkey_path`/`vk_json_path` at the snarkjs `groth16 setup` outputs
/// for the exact same (O2-compiled) circuit.
pub fn load_artifacts(
    circuit_path: &Path,
    link_dir: &Path,
    zkey_path: &Path,
    vk_json_path: &Path,
) -> Result<SettleArtifacts> {
    let public_input_names =
        CoCircomCompiler::<Bn254>::get_public_inputs(circuit_path, compiler_config(link_dir))
            .map_err(|e| anyhow!("reading circuit public inputs: {e}"))?;
    let circuit = CoCircomCompiler::<Bn254>::parse(circuit_path, compiler_config(link_dir))
        .map_err(|e| anyhow!("parsing circuit for MPC: {e}"))?;

    let zkey_file =
        File::open(zkey_path).with_context(|| format!("opening zkey {}", zkey_path.display()))?;
    let zkey = Groth16ZKey::<Bn254>::from_reader(BufReader::new(zkey_file), CheckElement::No)
        .map_err(|e| anyhow!("parsing zkey: {e}"))?;
    let (matrices, pkey) = zkey.into();

    let vk_file = File::open(vk_json_path)
        .with_context(|| format!("opening vk {}", vk_json_path.display()))?;
    let vk_json: Groth16JsonVerificationKey<Bn254> =
        serde_json::from_reader(BufReader::new(vk_file)).context("parsing vk.json")?;
    let vk: VerifyingKey<Bn254> = vk_json.into();

    Ok(SettleArtifacts {
        circuit,
        public_input_names,
        pkey,
        matrices,
        vk,
    })
}
