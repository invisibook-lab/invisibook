//! End-to-end checks of the R3.2 balance proof.

use budget_stark::{
    Error,
    hash::{Digest, RANDOM_LEN, Random, commit, digest_from_bytes, digest_to_bytes},
    prove, verify,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use rand::{TryRng, rngs::SysRng};

/// Draws `n` uniformly random blinding factors.
fn randoms(n: usize) -> Vec<Random> {
    (0..n)
        .map(|_| {
            core::array::from_fn(|_| {
                let mut buf = [0u8; 4];
                SysRng.try_fill_bytes(&mut buf).unwrap();
                KoalaBear::from_u32(u32::from_le_bytes(buf) % 0x7f00_0001)
            })
        })
        .collect()
}

#[test]
fn honest_table_verifies() {
    let amounts = [10_000_000_000u64, 3, 0, u64::MAX / 4, 0xffff, 0x1_0000, 77];
    let rs = randoms(amounts.len());
    let (prepaid, commitments, proof) = prove(&amounts, &rs).unwrap();
    assert_eq!(prepaid, amounts.iter().sum::<u64>());
    for (i, c) in commitments.iter().enumerate() {
        assert_eq!(*c, commit(amounts[i], &rs[i]));
    }
    verify(prepaid, &commitments, &proof).unwrap();
}

#[test]
fn single_entry_and_full_u64() {
    let rs = randoms(1);
    let (prepaid, commitments, proof) = prove(&[u64::MAX], &rs).unwrap();
    assert_eq!(prepaid, u64::MAX);
    verify(prepaid, &commitments, &proof).unwrap();
}

#[test]
fn power_of_two_table() {
    let amounts: Vec<u64> = (0..16).map(|i| 1_000 * i).collect();
    let (prepaid, commitments, proof) = prove(&amounts, &randoms(16)).unwrap();
    verify(prepaid, &commitments, &proof).unwrap();
}

#[test]
fn wrong_total_is_rejected() {
    let amounts = [5u64, 5, 5];
    let (prepaid, commitments, proof) = prove(&amounts, &randoms(3)).unwrap();
    assert_eq!(
        verify(prepaid + 1, &commitments, &proof),
        Err(Error::Rejected)
    );
    assert_eq!(
        verify(prepaid - 1, &commitments, &proof),
        Err(Error::Rejected)
    );
    // Off by exactly one limb carry.
    assert_eq!(
        verify(prepaid + (1 << 16), &commitments, &proof),
        Err(Error::Rejected)
    );
}

#[test]
fn altered_table_is_rejected() {
    let amounts = [5u64, 5, 5];
    let rs = randoms(3);
    let (prepaid, commitments, proof) = prove(&amounts, &rs).unwrap();

    // A commitment to more money at one height, total unchanged.
    let mut inflated = commitments.clone();
    inflated[1] = commit(6, &rs[1]);
    assert_eq!(verify(prepaid, &inflated, &proof), Err(Error::Rejected));

    // Same commitments, different order.
    let mut reordered = commitments.clone();
    reordered.swap(0, 2);
    assert_eq!(verify(prepaid, &reordered, &proof), Err(Error::Rejected));

    // An extra entry, or a missing one.
    let mut longer = commitments.clone();
    longer.push(commit(0, &rs[0]));
    assert_eq!(verify(prepaid, &longer, &proof), Err(Error::Rejected));
    assert_eq!(
        verify(prepaid, &commitments[..2], &proof),
        Err(Error::Rejected)
    );
}

#[test]
fn tampered_proof_is_rejected() {
    let (prepaid, commitments, mut proof) = prove(&[1, 2, 3], &randoms(3)).unwrap();
    let mid = proof.len() / 2;
    proof[mid] ^= 1;
    assert!(verify(prepaid, &commitments, &proof).is_err());
    assert_eq!(verify(prepaid, &commitments, &[]), Err(Error::Malformed));
}

#[test]
fn input_errors() {
    assert_eq!(prove(&[], &[]).unwrap_err(), Error::Empty);
    assert_eq!(prove(&[1], &randoms(2)).unwrap_err(), Error::LengthMismatch);
    assert_eq!(
        prove(&[u64::MAX, 1], &randoms(2)).unwrap_err(),
        Error::Overflow
    );
}

#[test]
fn digest_encoding_round_trips_and_rejects_non_canonical() {
    let c = commit(42, &[KoalaBear::ONE; RANDOM_LEN]);
    let bytes = digest_to_bytes(&c);
    assert_eq!(digest_from_bytes(&bytes), Some(c));
    let mut bad = bytes;
    bad[..4].copy_from_slice(&0x7f00_0001u32.to_le_bytes());
    assert_eq!(digest_from_bytes(&bad), None::<Digest>);
}
