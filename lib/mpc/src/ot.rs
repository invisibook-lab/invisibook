//! 1-out-of-2 Oblivious Transfer
//!
//! Implements the "Simplest OT" protocol (Chou & Orlandi, 2015)
//! using the Ristretto group over Curve25519.
//!
//! Protocol:
//!   Sender has (m0, m1); Receiver has choice bit c.
//!   After OT, Receiver learns m_c; Sender learns nothing about c.
//!
//! Setup (Sender):
//!   1. Sample scalar y; compute S = yG; send S.
//!
//! Response (Receiver with choice c):
//!   2. Sample scalar x.
//!      If c=0: R = xG; if c=1: R = S + xG. Send R.
//!
//! Encryption (Sender):
//!   3. k0 = H(yR), k1 = H(y(R−S)).
//!      Send e0 = m0 ⊕ k0, e1 = m1 ⊕ k1.
//!
//! Decryption (Receiver):
//!   4. k = H(xS). Output m_c = e_c ⊕ k.
//!
//! Correctness: H(xS) = H(xyG) = H(yR) when c=0; and = H(y·xG) = H(y(R−S)) when c=1.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// A 32-byte OT message.
pub type OtMsg = [u8; 32];

/// Sender's first-round setup: holds secret scalar and public point S.
pub struct OtSender {
    scalar: Scalar,
    /// S = yG, broadcast to receiver.
    pub point_s: CompressedRistretto,
}

/// Receiver's response after seeing the sender's point S.
pub struct OtReceiver {
    /// R sent to sender.
    pub point_r: CompressedRistretto,
    /// Derived decryption key H(xS).
    key: [u8; 32],
    /// The receiver's choice bit.
    pub choice: bool,
}

/// Sender's encrypted pair of messages.
pub struct OtEncrypted {
    pub e0: OtMsg,
    pub e1: OtMsg,
}

impl OtSender {
    /// Generate a new sender setup (step 1).
    pub fn new() -> Self {
        let scalar = Scalar::random(&mut OsRng);
        let point_s = (&scalar * RISTRETTO_BASEPOINT_POINT).compress();
        OtSender { scalar, point_s }
    }

    /// Encrypt two messages given the receiver's point R (step 3).
    pub fn encrypt(&self, point_r: &CompressedRistretto, m0: OtMsg, m1: OtMsg) -> OtEncrypted {
        let r = point_r.decompress().expect("invalid R point");
        let s = self.point_s.decompress().expect("invalid S point");

        let k0 = hash_point(&(&self.scalar * &r));
        let k1 = hash_point(&(&self.scalar * &(r - s)));

        OtEncrypted {
            e0: xor32(m0, k0),
            e1: xor32(m1, k1),
        }
    }
}

impl OtReceiver {
    /// Generate receiver response for choice bit `c` (step 2).
    pub fn new(point_s: &CompressedRistretto, choice: bool) -> Self {
        let x = Scalar::random(&mut OsRng);
        let s = point_s.decompress().expect("invalid S point");

        let point_r = if choice {
            s + &x * RISTRETTO_BASEPOINT_POINT
        } else {
            &x * RISTRETTO_BASEPOINT_POINT
        };

        let key = hash_point(&(&x * &s));

        OtReceiver {
            point_r: point_r.compress(),
            key,
            choice,
        }
    }

    /// Decrypt the chosen message (step 4).
    pub fn decrypt(&self, enc: &OtEncrypted) -> OtMsg {
        let e = if self.choice { enc.e1 } else { enc.e0 };
        xor32(e, self.key)
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn hash_point(p: &RistrettoPoint) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(p.compress().as_bytes());
    h.finalize().into()
}

fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

// ── simulation helpers ────────────────────────────────────────────────────────

/// Run a complete OT in simulation (both parties in-process).
/// Returns the message chosen by `choice`.
pub fn simulate_ot(m0: OtMsg, m1: OtMsg, choice: bool) -> OtMsg {
    let sender = OtSender::new();
    let receiver = OtReceiver::new(&sender.point_s, choice);
    let enc = sender.encrypt(&receiver.point_r, m0, m1);
    receiver.decrypt(&enc)
}

/// Single-bit OT: sender has bits (b0, b1), receiver chooses with `choice`.
pub fn simulate_bit_ot(b0: bool, b1: bool, choice: bool) -> bool {
    let result = simulate_ot(bit_to_msg(b0), bit_to_msg(b1), choice);
    result[0] & 1 == 1
}

fn bit_to_msg(b: bool) -> OtMsg {
    let mut m = [0u8; 32];
    m[0] = b as u8;
    m
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ot_choice_0() {
        let mut m0 = [0u8; 32];
        m0[0] = 42;
        let mut m1 = [0u8; 32];
        m1[0] = 99;
        let got = simulate_ot(m0, m1, false);
        assert_eq!(got[0], 42);
    }

    #[test]
    fn ot_choice_1() {
        let mut m0 = [0u8; 32];
        m0[0] = 42;
        let mut m1 = [0u8; 32];
        m1[0] = 99;
        let got = simulate_ot(m0, m1, true);
        assert_eq!(got[0], 99);
    }

    #[test]
    fn bit_ot_all_cases() {
        for b0 in [false, true] {
            for b1 in [false, true] {
                assert_eq!(simulate_bit_ot(b0, b1, false), b0);
                assert_eq!(simulate_bit_ot(b0, b1, true), b1);
            }
        }
    }
}
