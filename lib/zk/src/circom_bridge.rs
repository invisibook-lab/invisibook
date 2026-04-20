//! Bridge between circom's R1CS/witness file formats and arkworks' Groth16.
//!
//! Parses `.r1cs` and `.wtns` binary files and provides an `ark_relations::ConstraintSynthesizer`
//! implementation that can be used with `ark-groth16` for proof generation.

use std::{fs, path::Path};

use anyhow::{Context, ensure};
use ark_bn254::Fr;
use ark_ff::{BigInteger256, PrimeField};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
};
use num_bigint::BigUint;
use r1cs_file::{FieldElement as R1csFieldElement, R1csFile};
use wtns_file::{FieldElement as WtnsFieldElement, WtnsFile};

/// BN254 field element size in bytes.
const FIELD_SIZE: usize = 32;

/// A circom circuit loaded from R1CS and (optionally) a witness file.
/// Implements `ConstraintSynthesizer` for use with ark-groth16.
#[derive(Clone)]
pub struct CircomCircuit {
    r1cs: R1csData,
    witness: Option<Vec<Fr>>,
}

#[derive(Clone)]
struct R1csData {
    n_pub_out: u32,
    n_pub_in: u32,
    n_wires: u32,
    constraints: Vec<(
        Vec<(Fr, u32)>, // A
        Vec<(Fr, u32)>, // B
        Vec<(Fr, u32)>, // C
    )>,
}

impl CircomCircuit {
    /// Load from R1CS file only (for trusted setup — no witness).
    pub fn from_r1cs(r1cs_path: &Path, _witness: Option<Vec<Fr>>) -> anyhow::Result<Self> {
        let r1cs_data = load_r1cs(r1cs_path)?;
        Ok(CircomCircuit {
            r1cs: r1cs_data,
            witness: None,
        })
    }

    /// Load from R1CS file and witness file (for proof generation).
    pub fn from_r1cs_and_wtns(r1cs_path: &Path, wtns_path: &Path) -> anyhow::Result<Self> {
        let r1cs_data = load_r1cs(r1cs_path)?;
        let witness = load_witness(wtns_path)?;
        Ok(CircomCircuit {
            r1cs: r1cs_data,
            witness: Some(witness),
        })
    }

    /// Extract public inputs from the witness.
    /// In circom's R1CS format, public inputs are witness indices 1..=(n_pub_out + n_pub_in).
    /// Wire 0 is always the constant 1.
    pub fn public_inputs(&self) -> Vec<Fr> {
        let witness = self.witness.as_ref().expect("No witness loaded");
        let n_public = (self.r1cs.n_pub_out + self.r1cs.n_pub_in) as usize;
        witness[1..=n_public].to_vec()
    }
}

impl ConstraintSynthesizer<Fr> for CircomCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let n_public = (self.r1cs.n_pub_out + self.r1cs.n_pub_in) as usize;
        let n_wires = self.r1cs.n_wires as usize;

        // Allocate all variables
        // Wire 0 = constant 1 (handled by cs automatically as Variable::One)
        // Wires 1..=n_public = public inputs (instance variables)
        // Wires (n_public+1)..n_wires = private inputs (witness variables)
        let mut vars = Vec::with_capacity(n_wires);
        vars.push(Variable::One); // wire 0

        for i in 1..=n_public {
            let val = self.witness.as_ref().map(|w| w[i]);
            let var = cs.new_input_variable(|| val.ok_or(SynthesisError::AssignmentMissing))?;
            vars.push(var);
        }

        for i in (n_public + 1)..n_wires {
            let val = self.witness.as_ref().map(|w| w[i]);
            let var = cs.new_witness_variable(|| val.ok_or(SynthesisError::AssignmentMissing))?;
            vars.push(var);
        }

        // Add constraints: A * B = C
        for (a_terms, b_terms, c_terms) in &self.r1cs.constraints {
            let a_lc = build_lc(a_terms, &vars);
            let b_lc = build_lc(b_terms, &vars);
            let c_lc = build_lc(c_terms, &vars);
            cs.enforce_constraint(a_lc, b_lc, c_lc)?;
        }

        Ok(())
    }
}

/// Build a linear combination from a list of (coefficient, wire_index) pairs.
fn build_lc(terms: &[(Fr, u32)], vars: &[Variable]) -> LinearCombination<Fr> {
    let mut lc_val = lc!();
    for &(coeff, wire_idx) in terms {
        lc_val += (coeff, vars[wire_idx as usize]);
    }
    lc_val
}

/// Parse an R1CS binary file into our internal representation.
fn load_r1cs(path: &Path) -> anyhow::Result<R1csData> {
    let data = fs::read(path).context("Failed to read R1CS file")?;
    let r1cs = R1csFile::<FIELD_SIZE>::read(data.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse R1CS: {e}"))?;

    let mut constraints = Vec::with_capacity(r1cs.constraints.0.len());
    for c in &r1cs.constraints.0 {
        let a =
            c.0.iter()
                .map(|(fe, idx)| (field_element_to_fr(fe), *idx))
                .collect();
        let b =
            c.1.iter()
                .map(|(fe, idx)| (field_element_to_fr(fe), *idx))
                .collect();
        let c =
            c.2.iter()
                .map(|(fe, idx)| (field_element_to_fr(fe), *idx))
                .collect();
        constraints.push((a, b, c));
    }

    Ok(R1csData {
        n_pub_out: r1cs.header.n_pub_out,
        n_pub_in: r1cs.header.n_pub_in,
        n_wires: r1cs.header.n_wires,
        constraints,
    })
}

/// Parse a `.wtns` binary file into a vector of Fr elements.
fn load_witness(path: &Path) -> anyhow::Result<Vec<Fr>> {
    let data = fs::read(path).context("Failed to read witness file")?;
    let wtns = WtnsFile::<FIELD_SIZE>::read(data.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse witness: {e}"))?;

    ensure!(
        !wtns.witness.0.is_empty(),
        "Witness file contains no elements"
    );

    Ok(wtns
        .witness
        .0
        .iter()
        .map(|fe| wtns_field_element_to_fr(fe))
        .collect())
}

/// Convert a `wtns_file::FieldElement` to `ark_bn254::Fr`.
pub fn wtns_field_element_to_fr(fe: &WtnsFieldElement<FIELD_SIZE>) -> Fr {
    let bytes: &[u8] = fe.as_ref();
    bytes_to_fr(bytes)
}

/// Convert an `r1cs_file::FieldElement` to `ark_bn254::Fr`.
pub fn field_element_to_fr(fe: &R1csFieldElement<FIELD_SIZE>) -> Fr {
    let bytes: &[u8; 32] = fe;
    bytes_to_fr(bytes)
}

/// Convert 32 little-endian bytes to `Fr`.
fn bytes_to_fr(bytes: &[u8]) -> Fr {
    let limbs = [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ];
    Fr::from_bigint(BigInteger256::new(limbs)).expect("Invalid field element")
}

/// Convert `Fr` to decimal string (for circom JSON input format).
pub fn fr_to_decimal_string(f: &Fr) -> String {
    let repr = f.into_bigint();
    // Convert limbs to u32 pairs (low, high) for BigUint
    let bi = BigUint::new(
        repr.0
            .iter()
            .flat_map(|&x| vec![(x & 0xFFFFFFFF) as u32, (x >> 32) as u32])
            .collect(),
    );
    bi.to_string()
}
