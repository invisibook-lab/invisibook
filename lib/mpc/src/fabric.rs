use std::future::Future;

use ark_bn254::G1Projective;
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    network::{MockNetwork, UnboundedDuplexStream},
    offline_prep::PartyIDBeaverSource,
};

/// BN254 curve used throughout the MPC crate. `Fr = <G1Projective as
/// CurveGroup>::ScalarField` is the same prime field as the one used by
/// lib/zk's Poseidon parameters, so hash outputs are compatible.
pub type Curve = G1Projective;

/// Run a two-party MPC in-process: spawn one task per party on tokio, wire
/// them together via an unbounded duplex stream (so no real network is
/// involved), and return both parties' outputs.
///
/// The beaver source is the deterministic `PartyIDBeaverSource`. That is
/// sufficient for correctness testing and for demonstrating the online phase;
/// it is **not** malicious-secure preprocessing and must be replaced with
/// LowGear / MP-SPDZ output for production use.
///
/// `f` is cloned-per-party to build each party's future. The caller's state
/// should be captured via `move` closures.
pub async fn run_two_party<T, S, F>(mut f: F) -> (T, T)
where
    T: Send + 'static,
    S: Future<Output = T> + Send + 'static,
    F: FnMut(MpcFabric<Curve>) -> S,
{
    // Duplex stream shared between the two party tasks.
    let (p0_stream, p1_stream) = UnboundedDuplexStream::new_duplex_pair();

    let p0_fabric = MpcFabric::new(
        MockNetwork::new(PARTY0, p0_stream),
        PartyIDBeaverSource::new(PARTY0),
    );
    let p1_fabric = MpcFabric::new(
        MockNetwork::new(PARTY1, p1_stream),
        PartyIDBeaverSource::new(PARTY1),
    );

    let fabric0 = p0_fabric.clone();
    let fabric1 = p1_fabric.clone();
    let t0 = tokio::spawn(f(fabric0));
    let t1 = tokio::spawn(f(fabric1));

    let out0 = t0.await.expect("party 0 task panicked");
    let out1 = t1.await.expect("party 1 task panicked");

    p0_fabric.shutdown();
    p1_fabric.shutdown();

    (out0, out1)
}
