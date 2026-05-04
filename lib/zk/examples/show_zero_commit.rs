// Compute Poseidon(0, 0) — the constant zero-commitment that wallet circuits
// use to pad unused output/input slots. Chain Go verifier needs this value to
// rebuild the public-input vector for circuits that use M=2 with one real slot.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

fn main() {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("circom(2) Poseidon params");
    let r = h
        .hash(&[Fr::from(0u64), Fr::from(0u64)])
        .expect("Poseidon hash");
    let bytes = r.into_bigint().to_bytes_be();

    let bi = num_bigint::BigUint::from_bytes_be(&bytes);
    println!("Poseidon(0, 0) decimal: {}", bi.to_str_radix(10));

    print!("Poseidon(0, 0) hex:     ");
    for _ in 0..(32 - bytes.len()) {
        print!("00");
    }
    for b in bytes {
        print!("{:02x}", b);
    }
    println!();
}
