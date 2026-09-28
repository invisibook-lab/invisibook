//! STARK configuration shared by the prover and the on-chain verifier.
//!
//! Merkle trees and the Fiat-Shamir transcript hash with Keccak: on CKB-VM a
//! byte hash is far cheaper than an algebraic one, and the verifier's cost is
//! almost entirely Merkle paths. The PCS is the hiding variant (salted leaves,
//! random codewords), which is what keeps the amounts zero-knowledge.

use alloc::vec;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2Dit;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;
use rand::{SeedableRng, rngs::StdRng};

pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 4>;

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [Val; VECTOR_LEN],
    [u64; VECTOR_LEN],
    FieldHash,
    Compress,
    StdRng,
    2,
    4,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = Radix2Dit<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;

/// The configuration every budget proof is made and checked under.
pub type BudgetConfig = StarkConfig<Pcs, Challenge, Challenger>;

// Security parameters. Plonky3's estimator puts this set at 103 bits
// conjectured and 67 proven. Conjectured security plateaus around 103 here
// whatever the query count, so extra queries buy little; a larger blowup
// buys more bits per query (a smaller proof and fewer verifier cycles), and
// query grinding is the cheapest source of proven bits since it costs the
// prover alone. Measured at N = 100: 111 KB proof, ~49M cycles on CKB-VM.

/// log2 of the FRI blowup. The AIR's constraints are degree 3.
pub const LOG_BLOWUP: usize = 4;
/// FRI queries. Each is worth LOG_BLOWUP bits of conjectured security.
pub const NUM_QUERIES: usize = 24;
/// Grinding before the query phase: ~2^20 hashes (~0.1 s) for an honest
/// prover once, and for a forger once per attempt.
pub const QUERY_POW_BITS: usize = 20;
/// Random codewords the hiding PCS mixes in.
const NUM_RANDOM_CODEWORDS: usize = 4;

/// Builds the configuration. `seed` drives the hiding randomness (Merkle
/// salts, random codewords): it must come from a real entropy source when
/// proving, and is irrelevant when verifying.
pub fn config(seed: [u8; 32]) -> BudgetConfig {
    let u64_hash = U64Hash::new(KeccakF {});
    let val_mmcs = ValMmcs::new(
        FieldHash::new(u64_hash),
        Compress::new(u64_hash),
        0,
        StdRng::from_seed(seed),
    );
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    // A second, independent stream for the random codewords.
    let mut codeword_seed = seed;
    codeword_seed[0] ^= 0x01;
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        NUM_RANDOM_CODEWORDS,
        StdRng::from_seed(codeword_seed),
    );
    BudgetConfig::new(pcs, Challenger::from_hasher(vec![], ByteHash {}))
}
