//! Proving (host only).

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_S_BOX_DEGREE, KoalaBear};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_symmetric::Permutation;
use p3_uni_stark::prove as stark_prove;
use postcard::to_allocvec;
use rand::{TryRng, rngs::SysRng};

use crate::{
    Error,
    air::{
        BITS, BudgetAir, CARRIES, CARRY, CARRY_BITS, CHAIN, COMMIT, HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS, PERM_WIDTH, PermConstants, SBOX_REGISTERS, SUM, TRACE_WIDTH,
        perm_constants,
    },
    check_size,
    config::config,
    hash::{
        DIGEST_LEN, Digest, LIMB_BITS, LIMBS, RANDOM_LEN, Random, WIDTH, chain_input, commit_input,
        permutation, truncate,
    },
    public_values, rows_for,
};

/// Proves that the table `(amounts[i], randoms[i])` adds up to `Σ amounts`,
/// every amount being a u64. Returns that total, every entry's commitment
/// (what goes into the budget cell) and the postcard-encoded proof.
///
/// `amounts` and `randoms` must be the same length, 1 to MAX_ENTRIES.
pub fn prove(amounts: &[u64], randoms: &[Random]) -> Result<(u64, Vec<Digest>, Vec<u8>), Error> {
    check_size(amounts.len())?;
    if amounts.len() != randoms.len() {
        return Err(Error::LengthMismatch);
    }
    let prepaid = amounts
        .iter()
        .try_fold(0u64, |acc, a| acc.checked_add(*a))
        .ok_or(Error::Overflow)?;

    let rows = rows_for(amounts.len());
    let zero_random = [KoalaBear::ZERO; RANDOM_LEN];
    let entry = |i: usize| match amounts.get(i) {
        Some(a) => (*a, &randoms[i]),
        None => (0, &zero_random),
    };

    // Both permutations' inputs, computed natively row by row: each chain
    // step needs the previous step's output.
    let perm = permutation();
    let mut commit_inputs = Vec::with_capacity(rows);
    let mut chain_inputs = Vec::with_capacity(rows);
    let mut commitments = Vec::with_capacity(amounts.len());
    let mut acc: Digest = [KoalaBear::ZERO; DIGEST_LEN];
    for i in 0..rows {
        let (amount, random) = entry(i);
        let input = commit_input(amount, random);
        let commitment = truncate(perm.permute(input));
        if i < amounts.len() {
            commitments.push(commitment);
        }
        let step = chain_input(&acc, &commitment);
        acc = truncate(perm.permute(step));
        commit_inputs.push(input);
        chain_inputs.push(step);
    }

    let constants = perm_constants();
    let commit_trace = perm_trace(commit_inputs, &constants);
    let chain_trace = perm_trace(chain_inputs, &constants);

    let mut values = KoalaBear::zero_vec(rows * TRACE_WIDTH);
    let mut sums = [0u64; LIMBS];
    for (i, row) in values.chunks_exact_mut(TRACE_WIDTH).enumerate() {
        let (amount, _) = entry(i);
        row[COMMIT].copy_from_slice(&commit_trace[i * PERM_WIDTH..(i + 1) * PERM_WIDTH]);
        row[CHAIN].copy_from_slice(&chain_trace[i * PERM_WIDTH..(i + 1) * PERM_WIDTH]);
        for (k, bit) in row[BITS].iter_mut().enumerate() {
            *bit = KoalaBear::from_u64((amount >> k) & 1);
        }
        for (j, s) in sums.iter_mut().enumerate() {
            *s += (amount >> (LIMB_BITS * j)) & 0xffff;
        }
        for (slot, s) in row[SUM].iter_mut().zip(sums) {
            *slot = KoalaBear::from_u64(s);
        }
    }

    // Normalise the final sums against prepaid's limbs; see air.rs.
    let last = &mut values[(rows - 1) * TRACE_WIDTH..];
    let mut carry = 0u64;
    for j in 0..CARRIES {
        carry = (sums[j] + carry) >> LIMB_BITS;
        for t in 0..CARRY_BITS {
            last[CARRY.start + CARRY_BITS * j + t] = KoalaBear::from_u64((carry >> t) & 1);
        }
    }

    let trace = RowMajorMatrix::new(values, TRACE_WIDTH);
    let public = public_values(prepaid, &commitments);

    let mut seed = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed)
        .map_err(|_| Error::Entropy)?;
    let proof =
        stark_prove(&config(seed), &BudgetAir::new(), trace, &public).map_err(|_| Error::Prover)?;
    let bytes = to_allocvec(&proof).map_err(|_| Error::Prover)?;
    Ok((prepaid, commitments, bytes))
}

/// Lays out one permutation per row for `inputs`, whose length must be a
/// power of two.
fn perm_trace(inputs: Vec<[KoalaBear; WIDTH]>, constants: &PermConstants) -> Vec<KoalaBear> {
    generate_trace_rows::<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        KOALABEAR_S_BOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, constants, 0)
    .values
}
