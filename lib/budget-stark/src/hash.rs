//! Native Poseidon2 over KoalaBear: the payment commitment, and the hash
//! chain that binds a whole allocation table to eight public values.
//!
//! Both are the width-16 permutation truncated to its first eight elements
//! (Plonky3's `TruncatedPermutation`), with the standard Grain-LFSR round
//! constants Plonky3 ships.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_symmetric::Permutation;

/// Permutation width.
pub const WIDTH: usize = 16;
/// Field elements in a commitment or chain digest (~248 bits).
pub const DIGEST_LEN: usize = 8;
/// Field elements of blinding in a commitment (~248 bits).
pub const RANDOM_LEN: usize = 8;
/// A u64 amount enters the hash as this many 16-bit limbs.
pub const LIMBS: usize = 4;
/// Bits per limb.
pub const LIMB_BITS: usize = 16;

/// A commitment or chain digest.
pub type Digest = [KoalaBear; DIGEST_LEN];
/// A commitment's blinding factor.
pub type Random = [KoalaBear; RANDOM_LEN];

/// Returns the permutation. Cheap to build: it only copies constant tables.
pub fn permutation() -> Poseidon2KoalaBear<WIDTH> {
    default_koalabear_poseidon2_16()
}

/// Splits `amount` into little-endian 16-bit limbs.
pub fn limbs(amount: u64) -> [u32; LIMBS] {
    core::array::from_fn(|j| ((amount >> (LIMB_BITS * j)) & 0xffff) as u32)
}

/// The permutation input of a commitment:
/// `[limb_0..limb_3, random_0..random_7, 0, 0, 0, 0]`.
pub fn commit_input(amount: u64, random: &Random) -> [KoalaBear; WIDTH] {
    let mut state = [KoalaBear::ZERO; WIDTH];
    for (slot, limb) in state.iter_mut().zip(limbs(amount)) {
        *slot = KoalaBear::from_u32(limb);
    }
    state[LIMBS..LIMBS + RANDOM_LEN].copy_from_slice(random);
    state
}

/// Commits to `amount` under `random`.
pub fn commit(amount: u64, random: &Random) -> Digest {
    truncate(permutation().permute(commit_input(amount, random)))
}

/// The commitment standing in for each padding row: amount 0, random 0.
pub fn padding_commitment() -> Digest {
    commit(0, &[KoalaBear::ZERO; RANDOM_LEN])
}

/// The chain step's permutation input: `[acc, commitment]`.
pub fn chain_input(acc: &Digest, commitment: &Digest) -> [KoalaBear; WIDTH] {
    let mut state = [KoalaBear::ZERO; WIDTH];
    state[..DIGEST_LEN].copy_from_slice(acc);
    state[DIGEST_LEN..].copy_from_slice(commitment);
    state
}

/// Folds `commitments`, then padding commitments up to `rows` in total, into
/// one digest: `acc_0 = 0`, `acc_{i+1} = H(acc_i, c_i)`.
///
/// `rows` must be at least `commitments.len()`.
pub fn chain_digest(commitments: &[Digest], rows: usize) -> Digest {
    let perm = permutation();
    let pad = padding_commitment();
    let mut acc = [KoalaBear::ZERO; DIGEST_LEN];
    for i in 0..rows {
        let c = commitments.get(i).unwrap_or(&pad);
        acc = truncate(perm.permute(chain_input(&acc, c)));
    }
    acc
}

/// Keeps the first `DIGEST_LEN` elements of a permutation output.
pub fn truncate(state: [KoalaBear; WIDTH]) -> Digest {
    core::array::from_fn(|i| state[i])
}

/// Encodes a digest as 32 bytes: each element as a little-endian u32.
pub fn digest_to_bytes(digest: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, x) in out.chunks_exact_mut(4).zip(digest) {
        chunk.copy_from_slice(&x.as_canonical_u32().to_le_bytes());
    }
    out
}

/// Decodes 32 bytes into a digest, or `None` if any element is not below the
/// field order. Commitments are hash outputs, so a non-canonical one is not a
/// commitment at all.
pub fn digest_from_bytes(bytes: &[u8; 32]) -> Option<Digest> {
    let mut out = [KoalaBear::ZERO; DIGEST_LEN];
    for (slot, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        let raw = u32::from_le_bytes(chunk.try_into().ok()?);
        if raw >= KoalaBear::ORDER_U32 {
            return None;
        }
        *slot = KoalaBear::from_u32(raw);
    }
    Some(out)
}
