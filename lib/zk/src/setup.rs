//! Trusted-setup helpers built around snarkjs (Node.js CLI).
//!
//! Production deployments must replace `dev_setup_snarkjs` with a real Powers
//! of Tau ceremony. This module exists so `cargo test` and local development
//! can produce a self-contained zkey + vk.json per circuit without external
//! ceremony coordination.

use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};

use crate::compile_circuit;

/// Filesystem artifacts produced by a single-circuit dev setup.
///
/// All three paths are needed at runtime:
/// * `zkey` — proving key, fed to `rapidsnark` together with the witness.
/// * `vk_json` — verification key in snarkjs JSON format, consumed by
///   go-rapidsnark on the chain side.
/// * `r1cs` — kept around so the caller can hand the same compiled circuit to
///   `TestCircuitHandle::from_compiled` for witness generation.
#[derive(Debug, Clone)]
pub struct DevSetup {
    pub circuit_name: String,
    pub circuit_dir: PathBuf,
    pub r1cs: PathBuf,
    pub zkey: PathBuf,
    pub vk_json: PathBuf,
}

/// Run snarkjs to produce a fresh zkey + vk.json for `circuit_name`. The
/// resulting Powers of Tau is held in this process's memory of the ceremony,
/// so the toxic waste is *not* destroyed — fine for tests, fatal for prod.
///
/// Output is cached under `lib/target/circuit-build/<name>/` so repeated test
/// runs do not pay the ~5s setup cost per circuit. Re-running this function
/// after deleting the cache regenerates everything from scratch.
///
/// Requires `snarkjs` available in `$PATH` (install via `npm i -g snarkjs`).
pub fn dev_setup_snarkjs(circuit_name: &str) -> Result<DevSetup> {
    let circuit_dir = compile_circuit(circuit_name)?;
    let r1cs = circuit_dir.join(format!("{circuit_name}.r1cs"));
    ensure!(
        r1cs.exists(),
        "r1cs file missing after circom compile: {r1cs:?}"
    );

    let zkey = circuit_dir.join(format!("{circuit_name}.zkey"));
    let vk_json = circuit_dir.join("vk.json");

    // Skip if both artifacts already exist — snarkjs setup is non-deterministic
    // and hashing the r1cs would bloat this helper without any practical win.
    if zkey.exists() && vk_json.exists() {
        return Ok(DevSetup {
            circuit_name: circuit_name.to_string(),
            circuit_dir,
            r1cs,
            zkey,
            vk_json,
        });
    }

    let ptau = ensure_dev_ptau(&circuit_dir)?;

    // groth16 setup: r1cs + ptau → zkey
    snarkjs(&[
        "groth16",
        "setup",
        r1cs.to_str().unwrap(),
        ptau.to_str().unwrap(),
        zkey.to_str().unwrap(),
    ])
    .context("snarkjs groth16 setup failed")?;

    // export verification key as JSON (consumed by go-rapidsnark verifier)
    snarkjs(&[
        "zkey",
        "export",
        "verificationkey",
        zkey.to_str().unwrap(),
        vk_json.to_str().unwrap(),
    ])
    .context("snarkjs zkey export verificationkey failed")?;

    Ok(DevSetup {
        circuit_name: circuit_name.to_string(),
        circuit_dir,
        r1cs,
        zkey,
        vk_json,
    })
}

/// log2 of the dev Powers-of-Tau constraint capacity. 2^15 = 32768 covers
/// the depth-20 spend circuits (~14k constraints); bump when a circuit
/// outgrows it. Regenerate by deleting `lib/target/circuit-build/_ptau/`.
const DEV_PTAU_POWER: &str = "15";

/// Generate a Powers of Tau file with 2^DEV_PTAU_POWER constraint capacity
/// and cache it under `lib/target/circuit-build/_ptau/`. Reused across all
/// dev setups.
fn ensure_dev_ptau(circuit_dir: &Path) -> Result<PathBuf> {
    let ptau_dir = circuit_dir
        .parent()
        .context("circuit dir has no parent")?
        .join("_ptau");
    create_dir_all(&ptau_dir)?;
    let final_ptau = ptau_dir.join(format!("pot{DEV_PTAU_POWER}_final.ptau"));
    if final_ptau.exists() {
        return Ok(final_ptau);
    }

    // 1) new — empty ceremony at curve bn128
    let p0 = ptau_dir.join(format!("pot{DEV_PTAU_POWER}_0000.ptau"));
    snarkjs(&[
        "powersoftau",
        "new",
        "bn128",
        DEV_PTAU_POWER,
        p0.to_str().unwrap(),
        "-v",
    ])?;

    // 2) contribute — single (insecure) entropy injection
    let p1 = ptau_dir.join(format!("pot{DEV_PTAU_POWER}_0001.ptau"));
    snarkjs(&[
        "powersoftau",
        "contribute",
        p0.to_str().unwrap(),
        p1.to_str().unwrap(),
        "--name=dev",
        "-v",
        "-e=invisibook-dev-only",
    ])?;

    // 3) prepare phase 2 — must run before any circuit-specific groth16 setup
    snarkjs(&[
        "powersoftau",
        "prepare",
        "phase2",
        p1.to_str().unwrap(),
        final_ptau.to_str().unwrap(),
        "-v",
    ])?;

    Ok(final_ptau)
}

fn snarkjs(args: &[&str]) -> Result<()> {
    let output = Command::new("snarkjs")
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "spawning `snarkjs {}` failed; install with `npm i -g snarkjs`",
                args.join(" ")
            )
        })?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "snarkjs {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            stdout,
            stderr
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn note_deposit_dev_setup_produces_zkey_and_vk() {
        let setup = super::dev_setup_snarkjs("note_deposit").expect("snarkjs setup must succeed");
        assert!(setup.zkey.exists(), "zkey should exist at {:?}", setup.zkey);
        assert!(
            setup.vk_json.exists(),
            "vk.json should exist at {:?}",
            setup.vk_json
        );

        // vk.json must be valid snarkjs format with the fields go-rapidsnark expects
        let vk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&setup.vk_json).unwrap()).unwrap();
        assert_eq!(vk["protocol"], "groth16");
        assert_eq!(vk["curve"], "bn128");
        // note_deposit.circom has 4 public signals:
        // [bridge_commitment, asset_id, cm_out, bind].
        assert_eq!(vk["nPublic"].as_u64(), Some(4));
        assert!(vk["IC"].is_array(), "IC array required for verification");
    }
}
