//! QUIC networking for the two traders (no third node).
//!
//! `ark-mpc`'s `QuicTwoPartyNet` is asymmetric: PARTY0 (trader A) dials,
//! PARTY1 (trader B) listens. TLS uses an in-crate self-signed certificate
//! with a pass-through verifier — transport encryption without peer
//! authentication. Peers must authenticate at the application layer (the
//! settlement message is ed25519-signed by both traders before the chain
//! accepts it, and the SPDZ MACs abort on any in-protocol tampering).

use std::net::SocketAddr;

use anyhow::{Result, anyhow};
use ark_bn254::G1Projective;
use ark_mpc::network::QuicTwoPartyNet;

/// Connect the 2-party QUIC network. `party` is `PARTY0` (dials `peer`) or
/// `PARTY1` (listens on `local`). Blocks until the channel is established.
pub async fn connect(
    party: u64,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<QuicTwoPartyNet<G1Projective>> {
    let mut net = QuicTwoPartyNet::new(party, local, peer);
    net.connect()
        .await
        .map_err(|e| anyhow!("QUIC connect (party {party}): {e:?}"))?;
    Ok(net)
}
