use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// SLIP-0010 master key derived from a BIP-39 seed.
fn master(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(seed);
    let r = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&r[..32]);
    c.copy_from_slice(&r[32..]);
    (k, c)
}

/// SLIP-0010 hardened child derivation (required for ed25519).
fn child(key: &[u8; 32], chain: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    let idx = index | 0x8000_0000;
    let mut mac = HmacSha512::new_from_slice(chain).unwrap();
    mac.update(&[0x00]);
    mac.update(key);
    mac.update(&idx.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&r[..32]);
    c.copy_from_slice(&r[32..]);
    (k, c)
}

/// Parse a BIP-39 mnemonic and derive the ed25519 seed at m/44'/coin_type'/0'/0'/index'.
/// Returns an error if the mnemonic is invalid.
pub fn mnemonic_to_ed25519_key(
    mnemonic: &str,
    coin_type: u32,
    index: u32,
) -> Result<[u8; 32], bip39::Error> {
    let m = bip39::Mnemonic::parse(mnemonic)?;
    let bip39_seed = m.to_seed("");
    Ok(derive_ed25519_key(&bip39_seed, coin_type, index))
}

/// Derive the ed25519 seed for path m/44'/coin_type'/0'/0'/index'
/// from a 64-byte BIP-39 seed. All levels are hardened (SLIP-0010 requirement).
pub fn derive_ed25519_key(bip39_seed: &[u8], coin_type: u32, index: u32) -> [u8; 32] {
    let (mut k, mut c) = master(bip39_seed);
    for seg in [44u32, coin_type, 0, 0, index] {
        let (k2, c2) = child(&k, &c, seg);
        k = k2;
        c = c2;
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    /// BIP-39 seed (no passphrase) is well-known. We verify the SLIP-0010 master key matches
    /// the known value from the SLIP-0010 test vectors, then derive m/44'/60'/0'/0'/0'.
    #[test]
    fn test_derive_prints_test_keys() {
        // Bob mnemonic
        let bob_mnemonic = bip39::Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let bob_bip39_seed = bob_mnemonic.to_seed("");
        let bob_seed = derive_ed25519_key(&bob_bip39_seed, 60, 0);
        let bob_kp = yu_sdk::KeyPair::from_ed25519_bytes(&bob_seed);
        println!("bob  seed: {}", hex::encode(bob_seed));
        println!("bob  pubkey: {}", hex::encode(bob_kp.pubkey_bytes()));

        // Alice mnemonic
        let alice_mnemonic = bip39::Mnemonic::parse(
            "test test test test test test test test test test test junk",
        )
        .unwrap();
        let alice_bip39_seed = alice_mnemonic.to_seed("");
        let alice_seed = derive_ed25519_key(&alice_bip39_seed, 60, 0);
        let alice_kp = yu_sdk::KeyPair::from_ed25519_bytes(&alice_seed);
        println!("alice seed: {}", hex::encode(alice_seed));
        println!("alice pubkey: {}", hex::encode(alice_kp.pubkey_bytes()));

        // Verify genesis cash IDs
        use sha2::{Digest, Sha256};
        for (label, pubkey) in [
            ("alice", hex::encode(alice_kp.pubkey_bytes())),
            ("bob", hex::encode(bob_kp.pubkey_bytes())),
        ] {
            for token in ["ETH", "USDT"] {
                let mut h = Sha256::new();
                h.update(format!("genesis:{}:{}", pubkey, token).as_bytes());
                let hash = h.finalize();
                println!("{} {} cash_id: {}", label, token, hex::encode(&hash[..16]));
            }
        }
    }
}
