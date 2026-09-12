//! QUIC networking for the two traders (no third node).
//!
//! `ark-mpc`'s `QuicTwoPartyNet` is asymmetric: PARTY0 (trader A) dials,
//! PARTY1 (trader B) listens. TLS uses an in-crate self-signed certificate
//! with a pass-through verifier — transport encryption without peer
//! authentication. Peers must authenticate at the application layer (the
//! settlement message is ed25519-signed by both traders before the chain
//! accepts it, and the SPDZ MACs abort on any in-protocol tampering).

use std::{net::SocketAddr, time::Duration};

use anyhow::{Result, anyhow};
use ark_bn254::G1Projective;
use ark_mpc::{PARTY0, network::QuicTwoPartyNet};
use tokio::time::{Instant, sleep, timeout};

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

/// Connect with spawn-order tolerance. The fork's `connect` makes exactly
/// ONE dial attempt for `PARTY0`, so a dialer that starts before the
/// listener would fail permanently; this retries the dial (recreating the
/// net each attempt) every 2 s until `deadline_secs` elapses. The listener
/// side makes a single accept bounded by the same deadline. `party` must be
/// `PARTY0` or `PARTY1`.
pub async fn connect_retry(
    party: u64,
    local: SocketAddr,
    peer: SocketAddr,
    deadline_secs: u64,
) -> Result<QuicTwoPartyNet<G1Projective>> {
    let deadline = Instant::now() + Duration::from_secs(deadline_secs);
    if party == PARTY0 {
        loop {
            match connect(party, local, peer).await {
                Ok(net) => return Ok(net),
                Err(e) if Instant::now() + Duration::from_secs(2) < deadline => {
                    // Peer likely not listening yet; retry after a pause.
                    let _ = e;
                    sleep(Duration::from_secs(2)).await;
                }
                Err(e) => return Err(e),
            }
        }
    } else {
        timeout(deadline - Instant::now(), connect(party, local, peer))
            .await
            .map_err(|_| anyhow!("timed out waiting for the counterparty to dial"))?
    }
}
