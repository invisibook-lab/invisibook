//! TCP network setup for the 3-node settlement MPC. Plain TCP is used for
//! localhost / trusted-transport deployments; swap in mpc-net's TLS or QUIC
//! backends (both need certificates) for anything crossing machines.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow};
use mpc_net::{
    config::{Address, NetworkConfig, NetworkParty},
    tcp::TcpNetwork,
};

/// Establish the two independent TCP channels REP3 needs. `my_id` is this
/// node's REP3 party id (0/1/2), `bind_addr` the local listen address, and
/// `party_addrs` the three parties' `host:port` addresses indexed by party
/// id (entry `my_id` is ignored by the connector but must be present).
/// Blocks until all connections are up.
pub fn tcp_networks(
    my_id: usize,
    bind_addr: SocketAddr,
    party_addrs: &[String; 3],
) -> Result<[TcpNetwork; 2]> {
    let parties = party_addrs
        .iter()
        .enumerate()
        .map(|(id, addr)| {
            let address: Address = addr
                .parse()
                .map_err(|e| anyhow!("invalid party {id} address {addr}: {e:?}"))?;
            Ok(NetworkParty::new(id, address))
        })
        .collect::<Result<Vec<_>>>()?;
    // The send/recv timeout turns a wedged MPC session (e.g. a peer that
    // died mid-protocol, or the occasional loopback connection-setup race)
    // into a hard error instead of an indefinite hang, so a supervisor can
    // retry the session.
    let config = NetworkConfig::builder(my_id, bind_addr, parties)
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        .build();
    TcpNetwork::networks::<2>(config)
        .map_err(|e| anyhow!("establishing TCP MPC networks: {e:?}"))
        .context("all three parties must be reachable")
}
