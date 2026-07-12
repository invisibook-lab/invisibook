//! In-process 3-node proving session over crossbeam channels. Used by tests
//! and by the benchmark harness; real deployments run one node per machine
//! via the `settle_cozk_party` binary instead.

use anyhow::{Result, ensure};
use ark_bn254::Fr;
use co_circom::Rep3SharedInput;
use mpc_net::local::LocalNetwork;
use serde_json::Value;

use crate::{
    artifacts::SettleArtifacts,
    protocol::{PartyOutput, PhaseStats, prove_party, split_trader_input},
};

/// Result of an in-process 3-node settlement proving session.
pub struct LocalSettleOutcome {
    /// snarkjs-format proof (identical across nodes; verified locally).
    pub proof_json: Value,
    /// Public signals as decimal strings (outputs then public inputs).
    pub public_json: Value,
    /// The public signals as field elements.
    pub public_inputs: Vec<Fr>,
    /// Per-node phase statistics, indexed by REP3 party id.
    pub per_party: [PhaseStats; 3],
}

/// Run the whole collaborative settlement proving flow in-process: split both
/// traders' inputs, hand each node its two share maps, and run the three
/// nodes on OS threads connected by in-memory channels.
///
/// `a_private`/`b_private` must come from `zk::wallet::settle_cozk_side_json`
/// (tags "a"/"b"); `public` from `zk::wallet::settle_cozk_public_json`.
pub fn run_local_settle(
    artifacts: &SettleArtifacts,
    a_private: &Value,
    b_private: &Value,
    public: &Value,
) -> Result<LocalSettleOutcome> {
    let a_shares = split_trader_input(a_private, public, &artifacts.public_input_names)?;
    let b_shares = split_trader_input(b_private, public, &artifacts.public_input_names)?;

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();

    let mut party_inputs: Vec<(Vec<Rep3SharedInput<Fr>>, LocalNetwork, LocalNetwork)> = a_shares
        .into_iter()
        .zip(b_shares)
        .zip(nets0.into_iter().zip(nets1))
        .map(|((a_share, b_share), (net0, net1))| (vec![a_share, b_share], net0, net1))
        .collect();

    let mut outputs: Vec<Result<PartyOutput>> = std::thread::scope(|scope| {
        let handles: Vec<_> = party_inputs
            .drain(..)
            .map(|(shares, net0, net1)| {
                scope.spawn(move || prove_party(artifacts, shares, &net0, &net1))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("party thread panicked"))
            .collect()
    });

    let party2 = outputs.pop().expect("three parties ran")?;
    let party1 = outputs.pop().expect("three parties ran")?;
    let party0 = outputs.pop().expect("three parties ran")?;

    // All nodes must have opened the identical proof and public vector.
    ensure!(
        party0.proof == party1.proof && party1.proof == party2.proof,
        "nodes disagree on the final proof"
    );
    ensure!(
        party0.public_inputs == party1.public_inputs
            && party1.public_inputs == party2.public_inputs,
        "nodes disagree on the public signals"
    );

    let proof_json = party0.proof_json.clone();
    let public_json = party0.public_json.clone();
    let public_inputs = party0.public_inputs.clone();
    Ok(LocalSettleOutcome {
        proof_json,
        public_json,
        public_inputs,
        per_party: [party0.stats, party1.stats, party2.stats],
    })
}
