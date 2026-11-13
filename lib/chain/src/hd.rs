//! BIP-32 hierarchical deterministic key derivation over secp256k1.
//!
//! One derived key serves every role an identity has on this chain: it owns
//! cash, signs orders, signs L2 blocks when the holder mines, and pays on CKB.
//! CKB's default lock is secp256k1, so that curve is fixed by the L1 choice and
//! propagates up to everything else.
//!
//! Both derivation modes are implemented, because secp256k1 supports both:
//!
//! * **Hardened** (`i'`) feeds the parent *private* key into the HMAC. A leaked
//!   child key reveals nothing about its parent or siblings, which is what
//!   isolates one account from another.
//! * **Normal** feeds the parent *public* key, so a child public key can be
//!   derived from an extended public key alone — watch-only address generation
//!   without the private key ever being present.
//!
//! The standard path shape follows from that split: `m/44'/coin'/0'/0/index`
//! hardens the account levels and leaves the address levels normal.

use hmac::{Hmac, Mac};
use k256::{PublicKey, Scalar, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// An extended key: the key material plus the chain code that seeds the HMAC
/// of its children.
#[derive(Clone, Copy)]
pub struct ExtendedKey {
    /// 32-byte secp256k1 private key.
    pub key: [u8; 32],
    /// 32-byte chain code.
    pub chain_code: [u8; 32],
}

/// An extended *public* key: enough to derive child public keys through normal
/// derivation, and nothing more.
#[derive(Clone, Copy)]
pub struct ExtendedPubkey {
    /// 33-byte compressed secp256k1 public key.
    pub pubkey: [u8; 33],
    /// 32-byte chain code.
    pub chain_code: [u8; 32],
}

/// Errors that derivation can report. Every variant here is astronomically
/// unlikely — BIP-32 defines them because the arithmetic permits them, not
/// because they are reachable in practice.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("derived key is not a valid secp256k1 scalar")]
    InvalidKey,
    #[error("public key is not a valid secp256k1 point")]
    InvalidPubkey,
    #[error("invalid mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),
}

/// Hardened child indices start here; `44'` is `44 + HARDENED_OFFSET`.
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// BIP-32's master-key domain string. It is the curve tag: secp256k1 uses
/// `"Bitcoin seed"`, where SLIP-0010 uses `"ed25519 seed"` for ed25519 and a
/// different child-key rule to go with it.
const MASTER_KEY_DOMAIN: &[u8] = b"Bitcoin seed";

/// Split an HMAC-SHA512 output into its left and right halves.
fn split(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&bytes[..32]);
    right.copy_from_slice(&bytes[32..]);
    (left, right)
}

/// Parse 32 bytes as a non-zero secp256k1 scalar, rejecting 0 and anything at
/// or above the curve order.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<SecretKey, HdError> {
    SecretKey::from_slice(bytes).map_err(|_| HdError::InvalidKey)
}

/// Compressed public key of a private key, the 33-byte form BIP-32 hashes and
/// the chain stores as an owner key.
fn compressed_pubkey(key: &SecretKey) -> [u8; 33] {
    let point = key.public_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

/// BIP-32 master key from a BIP-39 seed.
/// `seed` is the 64-byte output of BIP-39 mnemonic expansion.
pub fn master(seed: &[u8]) -> Result<ExtendedKey, HdError> {
    let mut mac = HmacSha512::new_from_slice(MASTER_KEY_DOMAIN).expect("HMAC accepts any key size");
    mac.update(seed);
    let (key, chain_code) = split(&mac.finalize().into_bytes());
    // Rejects the negligible case where the seed hashes outside the scalar field.
    scalar_from_bytes(&key)?;
    Ok(ExtendedKey { key, chain_code })
}

/// Derive one child private key.
///
/// `index` below [`HARDENED_OFFSET`] selects normal derivation, at or above it
/// hardened. The difference is only what goes into the HMAC — the parent public
/// key or the parent private key — but that is what decides whether the matching
/// public key can be derived without secrets.
pub fn derive_child(parent: &ExtendedKey, index: u32) -> Result<ExtendedKey, HdError> {
    let parent_key = scalar_from_bytes(&parent.key)?;

    let mut mac =
        HmacSha512::new_from_slice(&parent.chain_code).expect("HMAC accepts any key size");
    if index >= HARDENED_OFFSET {
        mac.update(&[0x00]);
        mac.update(&parent.key);
    } else {
        mac.update(&compressed_pubkey(&parent_key));
    }
    mac.update(&index.to_be_bytes());
    let (tweak, chain_code) = split(&mac.finalize().into_bytes());

    // child = (IL + parent) mod n. This is what makes normal derivation work on
    // the public side too: the same tweak added to the parent point.
    let tweak: Scalar = *scalar_from_bytes(&tweak)?.to_nonzero_scalar();
    let child = tweak + *parent_key.to_nonzero_scalar();
    let child_bytes: [u8; 32] = child.to_bytes().into();
    // from_slice rejects a zero scalar, the other case BIP-32 calls invalid.
    scalar_from_bytes(&child_bytes)?;

    Ok(ExtendedKey {
        key: child_bytes,
        chain_code,
    })
}

/// Derive one child *public* key from an extended public key, without any
/// private material. Only normal derivation can do this, so `index` must be
/// below [`HARDENED_OFFSET`].
pub fn derive_child_pubkey(parent: &ExtendedPubkey, index: u32) -> Result<ExtendedPubkey, HdError> {
    if index >= HARDENED_OFFSET {
        return Err(HdError::InvalidKey);
    }
    let parent_point =
        PublicKey::from_sec1_bytes(&parent.pubkey).map_err(|_| HdError::InvalidPubkey)?;

    let mut mac =
        HmacSha512::new_from_slice(&parent.chain_code).expect("HMAC accepts any key size");
    mac.update(&parent.pubkey);
    mac.update(&index.to_be_bytes());
    let (tweak, chain_code) = split(&mac.finalize().into_bytes());

    // child point = IL·G + parent point, the public-side mirror of the private
    // formula above.
    let tweak: Scalar = *scalar_from_bytes(&tweak)?.to_nonzero_scalar();
    let child_point = (k256::ProjectivePoint::GENERATOR * tweak) + parent_point.to_projective();
    let child =
        PublicKey::from_affine(child_point.to_affine()).map_err(|_| HdError::InvalidPubkey)?;

    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(child.to_encoded_point(true).as_bytes());
    Ok(ExtendedPubkey { pubkey, chain_code })
}

/// The extended public key of an account's address level, `m/44'/coin'/0'/0`.
///
/// This is the value safe to hand to a watch-only service: it can enumerate
/// every receiving key under the account through [`derive_child_pubkey`], and
/// can recover no private key at any index.
pub fn account_xpub(bip39_seed: &[u8], coin_type: u32) -> Result<ExtendedPubkey, HdError> {
    let account = derive_account(bip39_seed, coin_type)?;
    let key = scalar_from_bytes(&account.key)?;
    Ok(ExtendedPubkey {
        pubkey: compressed_pubkey(&key),
        chain_code: account.chain_code,
    })
}

/// Derive the account address level `m/44'/coin_type'/0'/0`.
fn derive_account(bip39_seed: &[u8], coin_type: u32) -> Result<ExtendedKey, HdError> {
    let mut node = master(bip39_seed)?;
    for segment in [
        44 + HARDENED_OFFSET,
        coin_type + HARDENED_OFFSET,
        HARDENED_OFFSET,
        0,
    ] {
        node = derive_child(&node, segment)?;
    }
    Ok(node)
}

/// Derive the 32-byte secp256k1 private key at `m/44'/coin_type'/0'/0/index`
/// from a 64-byte BIP-39 seed.
///
/// The account levels are hardened and the address level is not, which is what
/// lets [`account_xpub`] exist.
pub fn derive_key(bip39_seed: &[u8], coin_type: u32, index: u32) -> Result<[u8; 32], HdError> {
    let account = derive_account(bip39_seed, coin_type)?;
    Ok(derive_child(&account, index)?.key)
}

/// Parse a BIP-39 mnemonic and derive the private key at
/// `m/44'/coin_type'/0'/0/index`.
pub fn mnemonic_to_key(mnemonic: &str, coin_type: u32, index: u32) -> Result<[u8; 32], HdError> {
    let m = bip39::Mnemonic::parse(mnemonic)?;
    derive_key(&m.to_seed(""), coin_type, index)
}

/// The compressed public key of a private key, as the 66-char hex the chain
/// stores as an owner key.
pub fn pubkey_hex(key: &[u8; 32]) -> Result<String, HdError> {
    Ok(hex::encode(compressed_pubkey(&scalar_from_bytes(key)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk a path of raw child indices from a master key.
    fn walk(seed_hex: &str, path: &[u32]) -> ExtendedKey {
        let seed = hex::decode(seed_hex).unwrap();
        let mut node = master(&seed).unwrap();
        for &index in path {
            node = derive_child(&node, index).unwrap();
        }
        node
    }

    /// BIP-32 test vector 1. Pins the implementation to the spec rather than to
    /// itself: master domain string, hardened and normal child rules, and the
    /// `(IL + k_parent) mod n` addition all have to be right for these to match.
    #[test]
    fn matches_bip32_test_vector_1() {
        const SEED: &str = "000102030405060708090a0b0c0d0e0f";

        let m = walk(SEED, &[]);
        assert_eq!(
            hex::encode(m.key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(m.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );

        // m/0' — hardened
        let m0h = walk(SEED, &[HARDENED_OFFSET]);
        assert_eq!(
            hex::encode(m0h.key),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(m0h.chain_code),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );

        // m/0'/1 — normal, the mode ed25519 cannot do at all
        let m0h1 = walk(SEED, &[HARDENED_OFFSET, 1]);
        assert_eq!(
            hex::encode(m0h1.key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(
            hex::encode(m0h1.chain_code),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );
    }

    /// The payoff of normal derivation: an extended *public* key alone
    /// enumerates every receiving key, and the results agree with what the
    /// private side derives.
    #[test]
    fn xpub_derives_the_same_pubkeys_as_the_private_side() {
        let seed =
            bip39::Mnemonic::parse("test test test test test test test test test test test junk")
                .unwrap()
                .to_seed("");

        let xpub = account_xpub(&seed, 60).unwrap();
        for index in 0..5u32 {
            let from_private = pubkey_hex(&derive_key(&seed, 60, index).unwrap()).unwrap();
            let from_xpub = hex::encode(derive_child_pubkey(&xpub, index).unwrap().pubkey);
            assert_eq!(
                from_private, from_xpub,
                "index {index}: xpub derivation must match the private side"
            );
        }
    }

    /// Hardened indices have no public-only path, by construction.
    #[test]
    fn xpub_cannot_derive_hardened_children() {
        let seed =
            bip39::Mnemonic::parse("test test test test test test test test test test test junk")
                .unwrap()
                .to_seed("");
        let xpub = account_xpub(&seed, 60).unwrap();
        assert!(derive_child_pubkey(&xpub, HARDENED_OFFSET).is_err());
    }

    /// Cross-checks against tooling outside this project: `"test test … junk"`
    /// is the standard Hardhat/Anvil development mnemonic, and its account 0 at
    /// `m/44'/60'/0'/0/0` is a widely published key. Matching it proves the
    /// derivation interoperates with ordinary Ethereum wallets rather than just
    /// being self-consistent.
    #[test]
    fn matches_standard_ethereum_tooling() {
        let key = mnemonic_to_key(
            "test test test test test test test test test test test junk",
            60,
            0,
        )
        .unwrap();
        assert_eq!(
            hex::encode(key),
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        );
    }

    /// Prints the identities the chain's genesis fixtures are built from.
    #[test]
    fn print_test_identities() {
        for (label, phrase) in [
            (
                "alice",
                "test test test test test test test test test test test junk",
            ),
            (
                "bob",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ),
        ] {
            let key = mnemonic_to_key(phrase, 60, 0).unwrap();
            let pubkey = pubkey_hex(&key).unwrap();
            println!("{label} key:    {}", hex::encode(key));
            println!("{label} pubkey: {pubkey}");

            use sha2::{Digest, Sha256};
            for token in ["ETH", "USDT"] {
                let mut h = Sha256::new();
                h.update(format!("genesis:{pubkey}:{token}").as_bytes());
                println!(
                    "{label} {token} cash_id: {}",
                    hex::encode(&h.finalize()[..16])
                );
            }
        }
    }
}
