//! Census of the bytes the two traders send in one collaborative session.
//!
//! The example runs the REAL `prove_collaborative_share_timed` flow over an
//! in-process duplex channel. A counting network wrapper frames each
//! `NetworkOutbound` message exactly as the QUIC transport does (an 8-byte
//! length prefix plus the `serde_json` body) and tallies the result by
//! payload type. The output explains the RQ1 traffic numbers: it shows how
//! many messages of each type a party sends, their on-wire JSON size, and
//! the raw (binary) size of the same field/point elements.
//!
//! Run with: `cargo run --release --example traffic_census`

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use anyhow::Result;
use ark_bn254::G1Projective;
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId, UnboundedDuplexStream},
    offline_prep::PartyIDBeaverSource,
};
use cozk2p::{
    SidePrivate, compute_public, default_cache_dir, dev_keys, prove_collaborative_share_timed,
    sample_trade,
};
use futures::{Sink, Stream};

/// Compressed size in bytes of one BN254 scalar field element.
const SCALAR_RAW_BYTES: u64 = 32;

/// Per-payload-type counters for one send direction.
#[derive(Default, Clone)]
struct VariantTally {
    /// Number of `NetworkOutbound` messages.
    messages: u64,
    /// Number of scalar/point/byte elements inside those messages.
    elements: u64,
    /// On-wire bytes: 8-byte length prefix + serde_json body, as QUIC sends.
    wire_bytes: u64,
    /// Binary size of the same elements without the JSON encoding.
    raw_bytes: u64,
}

/// All counters for one send direction, keyed by payload variant name.
#[derive(Default)]
struct Tally {
    by_variant: BTreeMap<&'static str, VariantTally>,
}

impl Tally {
    /// Record one outbound message. `msg` must serialize with serde_json,
    /// which holds for every `NetworkPayload` variant.
    fn record(&mut self, msg: &NetworkOutbound<G1Projective>) {
        // Frame the message the same way QuicTwoPartyNet::send does.
        let wire = serde_json::to_vec(msg).expect("payload serializes").len() as u64 + 8;
        let (name, elements, raw) = classify(&msg.payload);
        let v = self.by_variant.entry(name).or_default();
        v.messages += 1;
        v.elements += elements;
        v.wire_bytes += wire;
        v.raw_bytes += raw;
    }
}

/// Return the variant name, element count, and raw binary size of a payload.
fn classify(payload: &NetworkPayload<G1Projective>) -> (&'static str, u64, u64) {
    match payload {
        NetworkPayload::Bytes(b) => ("Bytes", 1, b.len() as u64),
        NetworkPayload::Scalar(_) => ("Scalar", 1, SCALAR_RAW_BYTES),
        NetworkPayload::ScalarBatch(v) => (
            "ScalarBatch",
            v.len() as u64,
            v.len() as u64 * SCALAR_RAW_BYTES,
        ),
        NetworkPayload::ScalarShare(_) => ("ScalarShare", 1, 2 * SCALAR_RAW_BYTES),
        NetworkPayload::Point(p) => ("Point", 1, p.to_bytes().len() as u64),
        NetworkPayload::PointBatch(v) => (
            "PointBatch",
            v.len() as u64,
            v.iter().map(|p| p.to_bytes().len() as u64).sum(),
        ),
        NetworkPayload::PointShare(_) => ("PointShare", 1, 2 * SCALAR_RAW_BYTES),
    }
}

/// In-process network that counts every sent message, then forwards it.
struct CountingNetwork {
    party_id: PartyId,
    conn: UnboundedDuplexStream<G1Projective>,
    tally: Arc<Mutex<Tally>>,
}

impl Stream for CountingNetwork {
    type Item = Result<NetworkOutbound<G1Projective>, MpcNetworkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Same polling pattern as ark-mpc's MockNetwork.
        let this = self.get_mut();
        Box::pin(this.conn.recv())
            .as_mut()
            .poll(cx)
            .map(|value| Some(Ok(value)))
    }
}

impl Sink<NetworkOutbound<G1Projective>> for CountingNetwork {
    type Error = MpcNetworkError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: NetworkOutbound<G1Projective>,
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.tally.lock().expect("tally lock").record(&item);
        this.conn.send(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl MpcNetwork<G1Projective> for CountingNetwork {
    fn party_id(&self) -> PartyId {
        self.party_id
    }

    // Manual expansion of the `async_trait` method: the example crate does
    // not depend on the `async-trait` macro.
    fn close<'a, 'b>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), MpcNetworkError>> + Send + 'b>>
    where
        'a: 'b,
        Self: 'b,
    {
        Box::pin(async { Ok(()) })
    }
}

/// Print one direction's tally as an aligned table.
fn print_tally(direction: &str, tally: &Tally) {
    let mut rows: Vec<(&'static str, VariantTally)> = tally
        .by_variant
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    rows.sort_by_key(|(_, v)| std::cmp::Reverse(v.wire_bytes));

    println!("\n=== {direction} ===");
    println!(
        "{:<12} {:>10} {:>12} {:>14} {:>14} {:>7}",
        "payload", "messages", "elements", "wire bytes", "raw bytes", "blowup"
    );
    let (mut tm, mut te, mut tw, mut tr) = (0u64, 0u64, 0u64, 0u64);
    for (name, v) in &rows {
        let blowup = v.wire_bytes as f64 / v.raw_bytes.max(1) as f64;
        println!(
            "{:<12} {:>10} {:>12} {:>14} {:>14} {:>6.2}x",
            name, v.messages, v.elements, v.wire_bytes, v.raw_bytes, blowup
        );
        tm += v.messages;
        te += v.elements;
        tw += v.wire_bytes;
        tr += v.raw_bytes;
    }
    println!(
        "{:<12} {:>10} {:>12} {:>14} {:>14} {:>6.2}x",
        "TOTAL",
        tm,
        te,
        tw,
        tr,
        tw as f64 / tr.max(1) as f64
    );
    println!(
        "total on-wire: {:.1} MiB (raw binary equivalent: {:.1} MiB)",
        tw as f64 / (1024.0 * 1024.0),
        tr as f64 / (1024.0 * 1024.0)
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let (a, b, price_a, price_b, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller)?;
    let (pk, _vk) = dev_keys(&default_cache_dir())?;

    // One duplex pair connects the two in-process parties; each direction
    // gets its own tally.
    let (stream0, stream1) = UnboundedDuplexStream::new_duplex_pair();
    let tally_a = Arc::new(Mutex::new(Tally::default()));
    let tally_b = Arc::new(Mutex::new(Tally::default()));
    let fabric0 = MpcFabric::new(
        CountingNetwork {
            party_id: PARTY0,
            conn: stream0,
            tally: Arc::clone(&tally_a),
        },
        PartyIDBeaverSource::new(PARTY0),
    );
    let fabric1 = MpcFabric::new(
        CountingNetwork {
            party_id: PARTY1,
            conn: stream1,
            tally: Arc::clone(&tally_b),
        },
        PartyIDBeaverSource::new(PARTY1),
    );

    // Run the same closure both tests and benches use: each party plays its
    // side of the sample trade and exports its native proof share.
    let spawn_party = |fabric: MpcFabric<G1Projective>, side: SidePrivate| {
        let public = public.clone();
        let pk = pk.clone();
        tokio::spawn(async move {
            let party = fabric.party_id();
            prove_collaborative_share_timed(fabric.clone(), party, &side, &public, &pk).await
        })
    };
    let task0 = spawn_party(fabric0.clone(), a.clone());
    let task1 = spawn_party(fabric1.clone(), b.clone());
    let (_share0, timings0) = task0.await??;
    let (_share1, timings1) = task1.await??;
    fabric0.shutdown();
    fabric1.shutdown();

    println!("prove timings, party A: {timings0:?}");
    println!("prove timings, party B: {timings1:?}");
    print_tally("trader A sends", &tally_a.lock().expect("tally lock"));
    print_tally("trader B sends", &tally_b.lock().expect("tally lock"));
    Ok(())
}
