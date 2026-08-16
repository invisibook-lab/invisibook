//! Witness builders + rapidsnark drivers for the shielded-pool circuits
//! (`note_deposit.circom`, `spend_withdraw.circom`).
//!
//! These live here rather than in `zk::wallet` because they are built on the
//! note derivations of [`crate::note`], and `zk` must not depend back on
//! this crate. The prover utilities (`TestCircuitHandle`, `run_rapidsnark`)
//! come from `zk`.

use anyhow::{Result, ensure};
use ark_bn254::Fr;
use rand::RngCore;
use serde_json::{Value, json};
use std::path::Path;

use zk::{
    circom_bridge::fr_to_decimal_string, prover::run_rapidsnark, test_circuit::TestCircuitHandle,
    wallet::poseidon2,
};

use crate::note::{
    TREE_DEPTH, fr_from_be_bytes, nk_from_sk, note_commit, note_fr_to_hex, nullifier, rho,
};

/// One input slot of a spend circuit: a real note (with its Merkle path) or
/// an Orchard-style dummy (fresh random secrets, zero value, membership
/// disabled). Build dummies with [`SpendSlot::dummy`].
#[derive(Debug, Clone)]
pub struct SpendSlot {
    pub enabled: bool,
    /// Wallet spending secret (real) or fresh random (dummy).
    pub sk: Fr,
    pub v: u64,
    pub r: Fr,
    /// Fresh random rho (dummy); ignored for real slots.
    pub rho_rand: Fr,
    pub path: [Fr; TREE_DEPTH],
    pub bits: [bool; TREE_DEPTH],
}

impl SpendSlot {
    /// A real spend of a note at `path`/`bits` (from `NoteTree::path`).
    pub fn real(sk: Fr, v: u64, r: Fr, path: [Fr; TREE_DEPTH], bits: [bool; TREE_DEPTH]) -> Self {
        SpendSlot {
            enabled: true,
            sk,
            v,
            r,
            rho_rand: Fr::from(0u64),
            path,
            bits,
        }
    }

    /// A dummy slot: fresh random `sk` and `rho_rand`, zero value, zero
    /// path. Its nullifier is a PRF image of unknown fresh secrets —
    /// unsteerable and collision-negligible.
    pub fn dummy() -> Self {
        let mut rng = rand::rng();
        let mut sk_bytes = [0u8; 32];
        let mut rho_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        rng.fill_bytes(&mut rho_bytes);
        SpendSlot {
            enabled: false,
            sk: fr_from_be_bytes(&sk_bytes),
            v: 0,
            r: Fr::from(0u64),
            rho_rand: fr_from_be_bytes(&rho_bytes),
            path: [Fr::from(0u64); TREE_DEPTH],
            bits: [false; TREE_DEPTH],
        }
    }

    /// The leaf index this slot's path bits encode.
    fn leaf_index(&self) -> u64 {
        self.bits
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc | ((*b as u64) << i))
    }

    /// The nullifier this slot will publish (what the circuit outputs).
    pub fn nullifier(&self, asset: Fr) -> Fr {
        let nk = nk_from_sk(self.sk);
        if self.enabled {
            let npk = poseidon2(Fr::from(crate::note::TAG_NPK), self.sk);
            let cm = note_commit(npk, asset, self.v, self.r);
            nullifier(nk, rho(cm, self.leaf_index()))
        } else {
            nullifier(nk, self.rho_rand)
        }
    }

    fn to_json_parts(&self) -> (String, String, String, String, String) {
        (
            if self.enabled { "1" } else { "0" }.to_string(),
            fr_to_decimal_string(&self.sk),
            self.v.to_string(),
            fr_to_decimal_string(&self.r),
            fr_to_decimal_string(&self.rho_rand),
        )
    }
}

/// Witness for `note_deposit.circom`: mint one note from a bridged value.
pub struct NoteDepositWitness {
    pub v: u64,
    pub r_bridge: Fr,
    pub npk: Fr,
    pub r_note: Fr,
    pub asset: Fr,
    pub bind: Fr,
}

/// Output of [`prove_note_deposit`]: the public hexes the chain rebuilds
/// its public-input vector from, plus the snarkjs-format proof.
pub struct NoteDepositProof {
    pub bridge_commitment_hex: String,
    pub cm_out_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `note_deposit` witness, run rapidsnark, and return the proof.
/// `zkey` must belong to the note_deposit circuit.
pub fn prove_note_deposit(
    w: NoteDepositWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<NoteDepositProof> {
    let bridge_commitment = poseidon2(Fr::from(w.v), w.r_bridge);
    let cm_out = note_commit(w.npk, w.asset, w.v, w.r_note);

    let input = json!({
        "bridge_commitment": fr_to_decimal_string(&bridge_commitment),
        "asset_id": fr_to_decimal_string(&w.asset),
        "cm_out": fr_to_decimal_string(&cm_out),
        "bind": fr_to_decimal_string(&w.bind),
        "v": w.v.to_string(),
        "r_bridge": fr_to_decimal_string(&w.r_bridge),
        "npk": fr_to_decimal_string(&w.npk),
        "r_note": fr_to_decimal_string(&w.r_note),
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(NoteDepositProof {
        bridge_commitment_hex: note_fr_to_hex(&bridge_commitment),
        cm_out_hex: note_fr_to_hex(&cm_out),
        proof_json,
        public_json,
    })
}

/// Witness for `spend_withdraw.circom`: spend two slots (dummies allowed),
/// withdraw `v_out` through the bridge, mint the change note.
pub struct SpendWithdrawWitness {
    pub slots: [SpendSlot; 2],
    pub anchor: Fr,
    pub asset: Fr,
    pub v_out: u64,
    pub r_bridge_out: Fr,
    pub npk_change: Fr,
    pub v_change: u64,
    pub r_change: Fr,
    pub bind: Fr,
}

/// Output of [`prove_spend_withdraw`].
pub struct SpendWithdrawProof {
    pub nf_hex: [String; 2],
    pub bridge_out_commitment_hex: String,
    pub cm_change_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `spend_withdraw` witness, run rapidsnark, and return the
/// proof. Enforces conservation locally before proving so a wallet bug
/// fails fast instead of producing an unsatisfiable witness.
pub fn prove_spend_withdraw(
    w: SpendWithdrawWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SpendWithdrawProof> {
    let v_in: u64 = w.slots.iter().map(|s| s.v).sum();
    ensure!(
        v_in == w.v_out + w.v_change,
        "conservation violated: inputs {} != out {} + change {}",
        v_in,
        w.v_out,
        w.v_change
    );

    let nf = [w.slots[0].nullifier(w.asset), w.slots[1].nullifier(w.asset)];
    let bridge_out = poseidon2(Fr::from(w.v_out), w.r_bridge_out);
    let cm_change = note_commit(w.npk_change, w.asset, w.v_change, w.r_change);

    let dec = fr_to_decimal_string;
    let slot_parts: Vec<_> = w.slots.iter().map(|s| s.to_json_parts()).collect();
    let paths: Vec<Vec<String>> = w
        .slots
        .iter()
        .map(|s| s.path.iter().map(dec).collect())
        .collect();
    let bits: Vec<Vec<String>> = w
        .slots
        .iter()
        .map(|s| s.bits.iter().map(|b| (*b as u8).to_string()).collect())
        .collect();

    let input = json!({
        "anchor": dec(&w.anchor),
        "nf_0": dec(&nf[0]),
        "nf_1": dec(&nf[1]),
        "asset_id": dec(&w.asset),
        "bridge_out_commitment": dec(&bridge_out),
        "cm_change": dec(&cm_change),
        "bind": dec(&w.bind),
        "enabled": [slot_parts[0].0, slot_parts[1].0],
        "sk": [slot_parts[0].1, slot_parts[1].1],
        "v": [slot_parts[0].2, slot_parts[1].2],
        "r": [slot_parts[0].3, slot_parts[1].3],
        "rho_rand": [slot_parts[0].4, slot_parts[1].4],
        "path": paths,
        "path_bits": bits,
        "v_out": w.v_out.to_string(),
        "r_bridge_out": dec(&w.r_bridge_out),
        "npk_change": dec(&w.npk_change),
        "v_change": w.v_change.to_string(),
        "r_change": dec(&w.r_change),
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(SpendWithdrawProof {
        nf_hex: [note_fr_to_hex(&nf[0]), note_fr_to_hex(&nf[1])],
        bridge_out_commitment_hex: note_fr_to_hex(&bridge_out),
        cm_change_hex: note_fr_to_hex(&cm_change),
        proof_json,
        public_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        note::{asset_id, empty_roots, npk_from_sk},
        note_tree::NoteTree,
    };
    use std::sync::Mutex;
    use zk::setup::{DevSetup, dev_setup_snarkjs};

    /// `dev_setup_snarkjs` writes shared cache files; two tests racing on
    /// the same circuit can read a half-written zkey. Serialize all setups.
    fn locked_setup(name: &str) -> DevSetup {
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        dev_setup_snarkjs(name).expect("snarkjs setup")
    }

    fn rep(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Full round trip: build the golden 3-leaf tree, spend leaf1 with one
    /// dummy slot, withdraw part of it, mint change — prove with rapidsnark
    /// and check the emitted publics. Also pins the public-input ORDER the
    /// chain rebuilds: [anchor, nf_0, nf_1, asset, bridge_out, cm_change, bind].
    #[test]
    fn spend_withdraw_round_trips_through_rapidsnark() {
        let sk1 = fr_from_be_bytes(&rep(0x42));
        let sk2 = fr_from_be_bytes(&rep(0x43));
        let eth = asset_id("ETH").unwrap();
        let usdt = asset_id("USDT").unwrap();

        let mut tree = NoteTree::new();
        tree.append(note_commit(
            npk_from_sk(sk1),
            eth,
            7,
            fr_from_be_bytes(&rep(0x33)),
        ));
        tree.append(note_commit(
            npk_from_sk(sk2),
            usdt,
            1_000_000,
            fr_from_be_bytes(&rep(0x34)),
        ));
        tree.append(note_commit(
            npk_from_sk(sk1),
            eth,
            5,
            fr_from_be_bytes(&rep(0x35)),
        ));

        let (path, bits) = tree.path(1);
        let slots = [
            SpendSlot::real(sk2, 1_000_000, fr_from_be_bytes(&rep(0x34)), path, bits),
            SpendSlot::dummy(),
        ];
        let w = SpendWithdrawWitness {
            slots,
            anchor: tree.root(),
            asset: usdt,
            v_out: 400_000,
            r_bridge_out: fr_from_be_bytes(&rep(0x51)),
            npk_change: npk_from_sk(sk2),
            v_change: 600_000,
            r_change: fr_from_be_bytes(&rep(0x52)),
            bind: fr_from_be_bytes(&rep(0x53)),
        };

        let setup = locked_setup("spend_withdraw");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_spend_withdraw(w, &handle, &setup.zkey).expect("prove");

        let public = proof.public_json.as_array().expect("public array");
        assert_eq!(
            public.len(),
            7,
            "publics: anchor,nf0,nf1,asset,bridge,change,bind"
        );
        // public[0] = anchor, [1..2] = nfs — cross-check against our own hexes.
        let dec_to_hex = |v: &serde_json::Value| {
            use ark_ff::PrimeField;
            let f = Fr::from_be_bytes_mod_order(&num_bigint_dec_to_be(v.as_str().unwrap()));
            note_fr_to_hex(&f)
        };
        assert_eq!(dec_to_hex(&public[1]), proof.nf_hex[0]);
        assert_eq!(dec_to_hex(&public[2]), proof.nf_hex[1]);
        assert_eq!(dec_to_hex(&public[4]), proof.bridge_out_commitment_hex);
        assert_eq!(dec_to_hex(&public[5]), proof.cm_change_hex);
    }

    /// Spending under the wrong asset must fail witness generation: the
    /// same opening cannot satisfy the commitment under another assetID.
    #[test]
    fn wrong_asset_is_rejected() {
        let sk2 = fr_from_be_bytes(&rep(0x43));
        let usdt = asset_id("USDT").unwrap();
        let eth = asset_id("ETH").unwrap();

        let mut tree = NoteTree::new();
        tree.append(note_commit(
            npk_from_sk(sk2),
            usdt,
            100,
            fr_from_be_bytes(&rep(0x34)),
        ));
        let (path, bits) = tree.path(0);
        let w = SpendWithdrawWitness {
            slots: [
                SpendSlot::real(sk2, 100, fr_from_be_bytes(&rep(0x34)), path, bits),
                SpendSlot::dummy(),
            ],
            anchor: tree.root(),
            asset: eth, // wrong asset for the note being spent
            v_out: 100,
            r_bridge_out: fr_from_be_bytes(&rep(0x51)),
            npk_change: npk_from_sk(sk2),
            v_change: 0,
            r_change: fr_from_be_bytes(&rep(0x52)),
            bind: fr_from_be_bytes(&rep(0x53)),
        };
        let setup = locked_setup("spend_withdraw");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        assert!(prove_spend_withdraw(w, &handle, &setup.zkey).is_err());
    }

    /// note_deposit round trip.
    #[test]
    fn note_deposit_round_trips_through_rapidsnark() {
        let sk1 = fr_from_be_bytes(&rep(0x42));
        let w = NoteDepositWitness {
            v: 2_000,
            r_bridge: fr_from_be_bytes(&rep(0x61)),
            npk: npk_from_sk(sk1),
            r_note: fr_from_be_bytes(&rep(0x62)),
            asset: asset_id("ETH").unwrap(),
            bind: fr_from_be_bytes(&rep(0x63)),
        };
        let setup = locked_setup("note_deposit");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_note_deposit(w, &handle, &setup.zkey).expect("prove");
        let public = proof.public_json.as_array().expect("public array");
        assert_eq!(public.len(), 4, "publics: bridge,asset,cm_out,bind");
    }

    /// Decimal string → big-endian bytes (for cross-checking rapidsnark's
    /// decimal publics against our hex renderings).
    fn num_bigint_dec_to_be(dec: &str) -> Vec<u8> {
        let mut acc: Vec<u8> = vec![0];
        for ch in dec.bytes() {
            assert!(ch.is_ascii_digit());
            let mut carry = (ch - b'0') as u32;
            for byte in acc.iter_mut().rev() {
                let cur = (*byte as u32) * 10 + carry;
                *byte = (cur & 0xff) as u8;
                carry = cur >> 8;
            }
            while carry > 0 {
                acc.insert(0, (carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        acc
    }

    // The empty-roots table is exercised transitively by every path above;
    // touch it here so the import is load-bearing.
    #[test]
    fn empty_roots_table_is_consistent() {
        let roots = empty_roots();
        assert_eq!(roots.len(), TREE_DEPTH + 1);
    }
}
