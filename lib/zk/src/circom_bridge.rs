//! Bridge between circom's R1CS/witness file formats and arkworks' Groth16.
//!
//! Parses `.r1cs` and `.wtns` binary files and provides an `ark_relations::ConstraintSynthesizer`
//! implementation that can be used with `ark-groth16` for proof generation.

use std::{any::TypeId, fs::read, path::Path};

use anyhow::{Context, ensure};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
};
use num_bigint::BigUint;
use r1cs_file::{FieldElement as R1csFieldElement, R1csFile};
use wtns_file::{FieldElement as WtnsFieldElement, WtnsFile};

/// BN254 field element size in bytes. circom only emits 32-byte field elements,
/// so any code path that parses an R1CS or witness file is BN254-only.
const FIELD_SIZE: usize = 32;

/// Asserts at runtime that `E` is BN254. Used as a guard in functions whose
/// implementations are tied to BN254-specific file layouts even though their
/// signatures are generic over the pairing curve.
fn assert_bn254<E: 'static>() {
    assert_eq!(
        TypeId::of::<E>(),
        TypeId::of::<Bn254>(),
        "circom_bridge currently supports only BN254"
    );
}

/// A circom circuit loaded from R1CS and (optionally) a witness file.
/// Implements `ConstraintSynthesizer` for use with ark-groth16.
#[derive(Clone)]
pub struct CircomCircuit<E: Pairing> {
    r1cs: R1csData<E>,
    witness: Option<Vec<E::ScalarField>>,
}

#[derive(Clone)]
struct R1csData<E: Pairing> {
    n_pub_out: u32,
    n_pub_in: u32,
    n_wires: u32,
    constraints: Vec<(
        Vec<(E::ScalarField, u32)>, // A
        Vec<(E::ScalarField, u32)>, // B
        Vec<(E::ScalarField, u32)>, // C
    )>,
}

impl<E: Pairing + 'static> CircomCircuit<E> {
    /// Load from R1CS file only (for trusted setup — no witness).
    /// `E` must be BN254 — circom emits BN254-format R1CS.
    pub fn from_r1cs(
        r1cs_path: &Path,
        _witness: Option<Vec<E::ScalarField>>,
    ) -> anyhow::Result<Self> {
        assert_bn254::<E>();
        let r1cs_data = load_r1cs::<E>(r1cs_path)?;
        Ok(CircomCircuit {
            r1cs: r1cs_data,
            witness: None,
        })
    }

    /// Load from R1CS file and witness file (for proof generation).
    /// `E` must be BN254 — circom emits BN254-format R1CS and witnesses.
    pub fn from_r1cs_and_wtns(r1cs_path: &Path, wtns_path: &Path) -> anyhow::Result<Self> {
        assert_bn254::<E>();
        let r1cs_data = load_r1cs::<E>(r1cs_path)?;
        let witness = load_witness::<E>(wtns_path)?;
        Ok(CircomCircuit {
            r1cs: r1cs_data,
            witness: Some(witness),
        })
    }

    /// Extract public inputs from the witness.
    /// In circom's R1CS format, public inputs are witness indices 1..=(n_pub_out + n_pub_in).
    /// Wire 0 is always the constant 1.
    pub fn public_inputs(&self) -> Vec<E::ScalarField> {
        let witness = self.witness.as_ref().expect("No witness loaded");
        let n_public = (self.r1cs.n_pub_out + self.r1cs.n_pub_in) as usize;
        witness[1..=n_public].to_vec()
    }
}

impl<E: Pairing> ConstraintSynthesizer<E::ScalarField> for CircomCircuit<E> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
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
            let a_lc = build_lc::<E::ScalarField>(a_terms, &vars);
            let b_lc = build_lc::<E::ScalarField>(b_terms, &vars);
            let c_lc = build_lc::<E::ScalarField>(c_terms, &vars);
            cs.enforce_constraint(a_lc, b_lc, c_lc)?;
        }

        Ok(())
    }
}

/// Build a linear combination from a list of (coefficient, wire_index) pairs.
fn build_lc<F: PrimeField>(terms: &[(F, u32)], vars: &[Variable]) -> LinearCombination<F> {
    let mut lc_val = lc!();
    for &(coeff, wire_idx) in terms {
        lc_val += (coeff, vars[wire_idx as usize]);
    }
    lc_val
}

/// Parse an R1CS binary file into our internal representation.
/// `E` must be BN254 — the parser hardcodes a 32-byte field element layout.
fn load_r1cs<E: Pairing + 'static>(path: &Path) -> anyhow::Result<R1csData<E>> {
    assert_bn254::<E>();
    let data = read(path).context("Failed to read R1CS file")?;
    let r1cs = R1csFile::<FIELD_SIZE>::read(data.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse R1CS: {e}"))?;

    let mut constraints = Vec::with_capacity(r1cs.constraints.0.len());
    for c in &r1cs.constraints.0 {
        let a =
            c.0.iter()
                .map(|(fe, idx)| (field_element_to_fr::<E::ScalarField>(fe), *idx))
                .collect();
        let b =
            c.1.iter()
                .map(|(fe, idx)| (field_element_to_fr::<E::ScalarField>(fe), *idx))
                .collect();
        let c =
            c.2.iter()
                .map(|(fe, idx)| (field_element_to_fr::<E::ScalarField>(fe), *idx))
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

/// Parse a `.wtns` binary file into a vector of field elements.
/// `E` must be BN254 — the parser hardcodes a 32-byte field element layout.
fn load_witness<E: Pairing + 'static>(path: &Path) -> anyhow::Result<Vec<E::ScalarField>> {
    assert_bn254::<E>();
    let data = read(path).context("Failed to read witness file")?;
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
        .map(|fe| wtns_field_element_to_fr::<E::ScalarField>(fe))
        .collect())
}

/// Convert a `wtns_file::FieldElement` to a prime-field scalar.
/// Bytes are interpreted as little-endian; values exceeding the field
/// modulus are reduced. `FIELD_SIZE = 32` is BN254-specific, so this is
/// only meaningful when `F` is BN254's scalar field.
pub fn wtns_field_element_to_fr<F: PrimeField>(fe: &WtnsFieldElement<FIELD_SIZE>) -> F {
    let bytes: &[u8] = fe.as_ref();
    bytes_to_fr::<F>(bytes)
}

/// Convert an `r1cs_file::FieldElement` to a prime-field scalar.
/// Bytes are interpreted as little-endian; values exceeding the field
/// modulus are reduced. `FIELD_SIZE = 32` is BN254-specific, so this is
/// only meaningful when `F` is BN254's scalar field.
pub fn field_element_to_fr<F: PrimeField>(fe: &R1csFieldElement<FIELD_SIZE>) -> F {
    let bytes: &[u8; FIELD_SIZE] = fe;
    bytes_to_fr::<F>(bytes)
}

/// Convert little-endian bytes to a prime-field scalar, reducing modulo
/// the field characteristic.
fn bytes_to_fr<F: PrimeField>(bytes: &[u8]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

/// Convert a prime-field scalar to its decimal-string representation
/// (the format circom expects in its JSON input files).
pub fn fr_to_decimal_string<F: PrimeField>(f: &F) -> String {
    let repr = f.into_bigint();
    let bi = BigUint::from_bytes_le(&repr.to_bytes_le());
    bi.to_string()
}
