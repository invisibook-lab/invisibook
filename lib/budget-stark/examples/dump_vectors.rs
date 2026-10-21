//! Prints commitment test vectors for the Go port of the Poseidon2 payment
//! commitment (`chain/consensus/poseidon2_test.go`).
//!
//! cargo run -p budget-stark --example dump_vectors

use budget_stark::hash::{Random, commit, digest_to_bytes, permutation};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;

/// Encodes a blinding factor as the Go side stores it: 8 × u32 LE, hex.
fn random_hex(random: &Random) -> String {
    random
        .iter()
        .flat_map(|x| x.as_canonical_u32().to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hex of 32 bytes.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // The bare permutation on [0, 1, ..., 15].
    let state: [KoalaBear; 16] = core::array::from_fn(|i| KoalaBear::from_u32(i as u32));
    let out = permutation().permute(state);
    let words: Vec<String> = out
        .iter()
        .map(|x| format!("0x{:08x}", x.as_canonical_u32()))
        .collect();
    println!("permutation([0..16]) = {{{}}}", words.join(", "));

    let cases: [(u64, Random); 4] = [
        (0, [KoalaBear::ZERO; 8]),
        (
            10_000_000_000,
            core::array::from_fn(|i| KoalaBear::from_u32(i as u32 + 1)),
        ),
        (u64::MAX, [KoalaBear::from_u32(0x7f00_0000); 8]),
        (
            0x0123_4567_89ab_cdef,
            core::array::from_fn(|i| {
                KoalaBear::from_u32(0x1234_5678u32.wrapping_mul(i as u32 + 3) % 0x7f00_0001)
            }),
        ),
    ];
    for (amount, random) in cases {
        println!(
            "{{{amount}, \"{}\", \"{}\"}},",
            random_hex(&random),
            hex(&digest_to_bytes(&commit(amount, &random)))
        );
    }
}
