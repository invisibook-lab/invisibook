//! The per-node collaborative proving protocol: input-share splitting and
//! merging, MPC witness extension, collaborative Groth16 proving, and the
//! mandatory verify-before-release check.

use std::time::Instant;

use anyhow::{Result, anyhow, ensure};
use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use co_circom::{
    CircomGroth16Proof, CircomReduction, Groth16, Rep3CoGroth16, Rep3SharedInput, VMConfig,
    generate_witness_rep3, merge_input_shares, split_input,
};
use mpc_net::Network;
use serde_json::{Map, Value};
use zk::circom_bridge::fr_to_decimal_string;

use crate::artifacts::SettleArtifacts;

/// The three REP3 node roles of the settlement MPC. The numeric value is the
/// REP3 party id (and the index into the share arrays).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Trader A — the maker (the earlier of the two matched orders).
    TraderA,
    /// Trader B — the taker.
    TraderB,
    /// Neutral helper node; contributes no inputs, only computation.
    Helper,
}

impl Role {
    /// REP3 party id of this role (0, 1, or 2).
    pub fn id(&self) -> usize {
        match self {
            Role::TraderA => 0,
            Role::TraderB => 1,
            Role::Helper => 2,
        }
    }
}

/// Wall-clock and communication statistics of one node's proving session.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhaseStats {
    /// MPC witness extension duration in milliseconds.
    pub witness_ms: f64,
    /// Collaborative Groth16 proving duration in milliseconds.
    pub prove_ms: f64,
    /// Local proof verification duration in milliseconds.
    pub verify_ms: f64,
    /// Bytes sent/received by this node during witness extension (both nets).
    pub witness_sent_bytes: usize,
    pub witness_recv_bytes: usize,
    /// Bytes sent/received by this node during proving (both nets).
    pub prove_sent_bytes: usize,
    pub prove_recv_bytes: usize,
}

impl PhaseStats {
    /// Total bytes this node sent across both phases.
    pub fn total_sent_bytes(&self) -> usize {
        self.witness_sent_bytes + self.prove_sent_bytes
    }

    /// Total bytes this node received across both phases.
    pub fn total_recv_bytes(&self) -> usize {
        self.witness_recv_bytes + self.prove_recv_bytes
    }
}

/// One node's result: the (already locally verified) proof in both arkworks
/// and snarkjs-JSON form, the public signals, and phase statistics.
pub struct PartyOutput {
    /// The Groth16 proof (identical on all three nodes).
    pub proof: Proof<Bn254>,
    /// snarkjs-format `proof.json` value (verifiable by go-rapidsnark).
    pub proof_json: Value,
    /// The circuit's public signals (outputs then public inputs), without the
    /// leading constant-1 wire.
    pub public_inputs: Vec<Fr>,
    /// The public signals as a JSON array of decimal strings, matching
    /// rapidsnark's `public.json` layout.
    pub public_json: Value,
    /// Timings and traffic of this node.
    pub stats: PhaseStats,
}

/// Split one trader's inputs into the three per-node REP3 share maps.
/// `private_side` must be the trader's own side from
/// `zk::wallet::settle_cozk_side_json`; `public` must be the shared map from
/// `zk::wallet::settle_cozk_public_json` (identical for both traders).
/// Share map `i` goes to REP3 node `i`.
pub fn split_trader_input(
    private_side: &Value,
    public: &Value,
    public_input_names: &[String],
) -> Result<[Rep3SharedInput<Fr>; 3]> {
    let mut input = Map::new();
    for part in [private_side, public] {
        let obj = part
            .as_object()
            .ok_or_else(|| anyhow!("input part is not a JSON object"))?;
        for (k, v) in obj {
            ensure!(
                input.insert(k.clone(), v.clone()).is_none(),
                "duplicate input signal {k}"
            );
        }
    }
    split_input::<Fr>(input, public_input_names).map_err(|e| anyhow!("splitting input: {e}"))
}

// NOTE on input distribution: the co-snarks MPC network (net0/net1) is owned
// exclusively by the co-snarks protocol — interleaving custom messages on it
// desynchronizes the protocol's per-channel framing and deadlocks witness
// extension. Input shares are therefore distributed OFFLINE: each trader
// splits its own input with `split_trader_input` and sends share `i` to node
// `i` over a side channel (exactly co-circom's `split-input` CLI step), then
// `prove_party` receives the already-distributed shares.

/// Peak resident set size (VmHWM) of this process in bytes. Linux-only;
/// returns 0 when /proc is unavailable.
pub fn peak_rss_bytes() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

/// Sum this node's (sent, received) bytes over all peers on both networks.
fn traffic<N: Network>(net0: &N, net1: &N) -> (usize, usize) {
    let mut sent = 0;
    let mut recv = 0;
    for net in [net0.get_connection_stats(), net1.get_connection_stats()] {
        for (_, (s, r)) in net.iter() {
            sent += s;
            recv += r;
        }
    }
    (sent, recv)
}

/// Run one node's full proving session: merge the input shares received from
/// the two traders, extend the witness under MPC, prove collaboratively, and
/// verify the proof locally. Returns an error (and MUST NOT publish anything)
/// if the proof does not verify — a proof over an invalid witness leaks
/// information about the honest trader's witness.
///
/// `input_shares` holds this node's share map from each input owner (trader A
/// and trader B, in any order). `net0`/`net1` must be two independent
/// channels to the same two peer nodes (REP3 requires both).
pub fn prove_party<N: Network>(
    artifacts: &SettleArtifacts,
    input_shares: Vec<Rep3SharedInput<Fr>>,
    net0: &N,
    net1: &N,
) -> Result<PartyOutput> {
    let merged = merge_input_shares(input_shares, &artifacts.public_input_names)
        .map_err(|e| anyhow!("merging input shares: {e}"))?;

    // Phase 1: MPC witness extension.
    let (sent0, recv0) = traffic(net0, net1);
    let witness_start = Instant::now();
    let witness =
        generate_witness_rep3::<Fr, N>(&artifacts.circuit, merged, VMConfig::default(), net0, net1)
            .map_err(|e| anyhow!("MPC witness extension: {e:?}"))?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1000.0;
    let public_with_const = witness.public_inputs.clone();

    // Phase 2: collaborative Groth16 proving.
    let (sent1, recv1) = traffic(net0, net1);
    let prove_start = Instant::now();
    let proof = Rep3CoGroth16::prove::<_, CircomReduction>(
        net0,
        net1,
        &artifacts.pkey,
        &artifacts.matrices,
        witness,
    )
    .map_err(|e| anyhow!("collaborative proving: {e:?}"))?;
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
    let (sent2, recv2) = traffic(net0, net1);

    // Phase 3: verify before release. public_inputs[0] is the constant 1.
    ensure!(
        !public_with_const.is_empty(),
        "witness has no public inputs"
    );
    let public_inputs = public_with_const[1..].to_vec();
    let verify_start = Instant::now();
    Groth16::<Bn254>::verify(&artifacts.vk, &proof, &public_inputs)
        .map_err(|e| anyhow!("proof failed local verification, refusing to release it: {e}"))?;
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let proof_json = serde_json::to_value(CircomGroth16Proof::from(proof.clone()))?;
    let public_json = Value::Array(
        public_inputs
            .iter()
            .map(|f| Value::String(fr_to_decimal_string(f)))
            .collect(),
    );

    Ok(PartyOutput {
        proof,
        proof_json,
        public_inputs,
        public_json,
        stats: PhaseStats {
            witness_ms,
            prove_ms,
            verify_ms,
            witness_sent_bytes: sent1 - sent0,
            witness_recv_bytes: recv1 - recv0,
            prove_sent_bytes: sent2 - sent1,
            prove_recv_bytes: recv2 - recv1,
        },
    })
}
