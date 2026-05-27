//! Settlement business logic for the desktop app.
//!
//! Mirrors the CLI settle flow (`cli_settle.rs`) but adapted for async
//! desktop use with progress callbacks and on-chain address exchange.
//!
//! NOTE: Peer address is currently exchanged on-chain. In production,
//! this will use Tor or similar anonymous overlay network for privacy.

#[cfg(not(target_os = "android"))]
mod inner {
    use std::{collections::HashSet, net::SocketAddr, path::Path, sync::Arc};

    use num_bigint::BigUint;
    use rand::RngCore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use invisibook_lib::{
        cash_store::CashRecord,
        chain::{ChainClient, SettleTokenLegParam},
        orderbook,
        types::*,
    };
    use mpc::{SettleConfig, SettleShare, Side, settle};
    use zk::{
        setup::dev_setup_snarkjs,
        test_circuit::TestCircuitHandle,
        wallet::{SettleLargerWitness, fr_to_hex, poseidon_commit, prove_settle_larger},
    };

    const POSEIDON_ZERO_COMMITMENT_HEX: &str =
        "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";

    /// Outcome of a successful settlement.
    pub struct SettleOutcome {
        /// Cash ID of the received cash.
        pub recv_cash_id: String,
        /// Token of the received cash.
        pub recv_token: String,
        /// Plaintext amount received.
        pub recv_amount: u64,
        /// Random used for the received cash commitment.
        pub recv_random_hex: String,
        /// Larger party's change cash ID (None for smaller party or no change).
        pub change_cash_id: Option<String>,
        /// Larger party's change token.
        pub change_token: Option<String>,
        /// Larger party's change plaintext amount.
        pub change_amount: Option<u64>,
        /// Larger party's change random (hex).
        pub change_random_hex: Option<String>,
        /// Larger party's change commitment (hex).
        pub change_commitment_hex: Option<String>,
    }

    /// Run the full settlement flow for a matched order.
    ///
    /// `progress` is called at each major step so the UI can display status.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_settle(
        client: &Arc<ChainClient>,
        my_order: &Order,
        counter_order: &Order,
        cash_records: &[CashRecord],
        mut progress: impl FnMut(&str),
    ) -> Result<SettleOutcome, String> {
        let my_pubkey = client.pubkey_hex().to_string();
        let my_order_id = my_order.id.clone();
        let match_order_id = counter_order.id.clone();

        let price = match (my_order.price, counter_order.price) {
            (Some(p), Some(q)) if p == q => p,
            _ => return Err("orders disagree on price".into()),
        };

        // Determine locked tokens.
        let my_lock_token = match my_order.trade_type {
            TradeType::Buy => my_order.subject.token2.clone(),
            TradeType::Sell => my_order.subject.token1.clone(),
        };
        let counter_lock_token = match counter_order.trade_type {
            TradeType::Buy => counter_order.subject.token2.clone(),
            TradeType::Sell => counter_order.subject.token1.clone(),
        };

        // Load locked CashRecords from the provided records slice.
        let my_locked_recs: Vec<CashRecord> = my_order
            .input_cash_ids
            .iter()
            .filter_map(|id| cash_records.iter().find(|r| &r.cash_id == id).cloned())
            .collect();
        if my_locked_recs.is_empty() {
            return Err("missing local CashRecord for locked inputs".into());
        }
        let my_locked_amount: u64 = my_locked_recs.iter().map(|r| r.amount).sum();

        // ═══════════ Phase 0: Bind QUIC and exchange addresses on-chain ═══════════
        progress("Registering address on chain...");

        // Bind ephemeral port for QUIC.
        let local_sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind ephemeral port: {e}"))?;
        let local_port = local_sock
            .local_addr()
            .map_err(|e| format!("local_addr: {e}"))?
            .port();
        drop(local_sock); // release so QUIC can bind it
        let local_addr_str = format!("127.0.0.1:{local_port}");

        // Register our address on chain.
        client
            .register_settle_addr(my_order_id.clone(), match_order_id.clone(), &local_addr_str)
            .await
            .map_err(|e| format!("register_settle_addr: {e}"))?;

        // Poll for counterparty's address.
        progress("Waiting for counterparty address...");
        let peer_addr_str = loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match client
                .query_settle_addr(my_order_id.clone(), match_order_id.clone())
                .await
            {
                Ok(Some(addr)) => break addr,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("query_settle_addr error: {e}");
                    continue;
                }
            }
        };

        let local: SocketAddr = local_addr_str
            .parse()
            .map_err(|e| format!("parse local addr: {e}"))?;
        let peer: SocketAddr = peer_addr_str
            .parse()
            .map_err(|e| format!("parse peer addr: {e}"))?;

        // ═══════════ Phase 1: MPC comparison ═══════════
        progress("Running MPC comparison...");

        let mpc_side = match my_order.trade_type {
            TradeType::Buy => Side::Buy,
            TradeType::Sell => Side::Sell,
        };

        // MPC compares token1 quantities. For sell orders, the locked amount IS
        // the token1 qty. For buy orders, order_amount/order_random store the
        // token1 qty and its separate blinding factor.
        let (my_mpc_value, my_mpc_random_hex) = match my_order.trade_type {
            TradeType::Buy => {
                let oa = my_locked_recs[0]
                    .order_amount
                    .ok_or("buy order missing order_amount in CashRecord")?;
                let or = my_locked_recs[0]
                    .order_random
                    .as_ref()
                    .ok_or("buy order missing order_random in CashRecord")?
                    .clone();
                (oa, or)
            }
            TradeType::Sell => (my_locked_amount, my_locked_recs[0].random.clone()),
        };

        let my_random_dec = hex_to_fr_decimal(&my_mpc_random_hex);
        let my_commit = fr_to_hex(&poseidon_commit(
            my_mpc_value,
            &hex_to_bytes32(&my_mpc_random_hex),
        ));
        let my_commit_dec = hex_to_fr_decimal(&my_commit);
        let counter_commit_dec = hex_to_fr_decimal(&counter_order.amount);

        let (c1, c2) = match mpc_side {
            Side::Buy => (my_commit_dec.clone(), counter_commit_dec.clone()),
            Side::Sell => (counter_commit_dec.clone(), my_commit_dec.clone()),
        };

        let mpc_config = SettleConfig {
            local_addr: local,
            peer_addr: peer,
        };
        let mpc_result: SettleShare = settle(
            &mpc_config,
            mpc_side,
            my_mpc_value,
            &my_random_dec,
            &c1,
            &c2,
        )
        .await
        .map_err(|e| format!("MPC settle: {e}"))?;

        let mpc_share = MpcShareParam {
            cmp_share: mpc_result.cmp_share,
            cmp_mac: mpc_result.cmp_mac,
            r_smaller_share: mpc_result.r_smaller_share,
            r_smaller_mac: mpc_result.r_smaller_mac,
            mac_key_share: mpc_result.mac_key_share,
        };

        // ═══════════ Phase 2: Submit CompareOrders ═══════════
        progress("Submitting comparison to chain...");
        client
            .compare_orders(my_order_id.clone(), match_order_id.clone(), mpc_share)
            .await
            .map_err(|e| format!("compare_orders: {e}"))?;

        // ═══════════ Phase 3: Poll until Settling ═══════════
        progress("Waiting for chain comparison result...");
        let settled_order = loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            match client
                .query_orders(
                    Some(my_order_id.clone()),
                    None,
                    None,
                    None,
                    None,
                    Some(1),
                    Some(0),
                )
                .await
            {
                Ok(orders) => {
                    if let Some(o) = orders.into_iter().find(|o| o.id == my_order_id) {
                        if o.status == OrderStatus::Settling {
                            break o;
                        }
                    }
                }
                Err(e) => eprintln!("poll error: {e}"),
            }
        };

        let my_is_smaller = settled_order.is_smaller;

        // ═══════════ Phase 3.5: P2P — smaller sends amount to larger ═══════════
        // Smaller party sends its locked amount; larger party receives it.
        // Larger party must NOT send its amount back.
        progress("Exchanging amount via P2P...");
        let counter_locked_amount =
            p2p_exchange_amount(my_is_smaller, my_locked_amount, local, peer).await?;

        // ═══════════ Phase 4: Build ZK leg and submit ═══════════
        // Prepare change info (only for larger party).
        let mut change_info: Option<(u64, [u8; 32], String)> = None;
        // The blinding factor for counter's recv cash (generated by larger, sent to smaller).
        let mut counter_recv_random_for_send: Option<[u8; 32]> = None;
        // The blinding factor for larger's own recv cash (generated fresh, kept locally).
        let mut my_recv_random_for_larger: Option<[u8; 32]> = None;

        let leg = if my_is_smaller {
            progress("Smaller party — confirming settlement...");
            None
        } else {
            progress("Generating ZK proof (larger party)...");

            // Larger knows both amounts → compute fills.
            let (fill_t1, fill_t2) = compute_fills(
                my_order,
                counter_order,
                my_locked_amount,
                counter_locked_amount,
                price,
            );

            // Generate fresh blinding factors for both recv outputs.
            let mut counter_recv_random = [0u8; 32];
            rand::rng().fill_bytes(&mut counter_recv_random);
            counter_recv_random_for_send = Some(counter_recv_random);

            let mut my_recv_random = [0u8; 32];
            rand::rng().fill_bytes(&mut my_recv_random);
            my_recv_random_for_larger = Some(my_recv_random);

            // Counter receives MY token. Amount = my fill in my lock token.
            let counter_recv_amount = if my_lock_token == my_order.subject.token1 {
                fill_t1
            } else {
                fill_t2
            };
            let counter_recv_commit_hex =
                fr_to_hex(&poseidon_commit(counter_recv_amount, &counter_recv_random));

            let larger_setup =
                dev_setup_snarkjs("settle_larger").map_err(|e| format!("setup: {e}"))?;
            let larger_handle = TestCircuitHandle::from_compiled(&larger_setup.circuit_dir)
                .map_err(|e| format!("handle: {e}"))?;

            let my_fill = if my_lock_token == my_order.subject.token1 {
                fill_t1
            } else {
                fill_t2
            };
            let change_amount = my_locked_amount.saturating_sub(my_fill);

            // Generate change_random before build_larger_leg so we can capture it.
            let mut change_random = [0u8; 32];
            if change_amount > 0 {
                rand::rng().fill_bytes(&mut change_random);
            }

            let leg_result = build_larger_leg(
                &my_locked_recs,
                &my_recv_random,
                &counter_recv_random,
                price,
                &my_lock_token,
                my_order,
                change_amount,
                &change_random,
                &counter_recv_commit_hex,
                &counter_order.pubkey,
                &larger_handle,
                &larger_setup.zkey,
            )?;

            // Capture change info for SettleOutcome.
            if change_amount > 0 {
                let change_commit_hex = fr_to_hex(&poseidon_commit(change_amount, &change_random));
                change_info = Some((change_amount, change_random, change_commit_hex));
            }

            Some(leg_result)
        };

        progress("Submitting settlement to chain...");
        client
            .settle_orders(my_order_id.clone(), match_order_id.clone(), leg)
            .await
            .map_err(|e| format!("settle_orders: {e}"))?;

        // ═══════════ Phase 4.5: P2P — larger sends blinding factor to smaller ═══════════
        // The smaller party needs the blinding factor to construct its recv CashRecord.
        // Even though it can infer the amount, it cannot spend the cash without the random.
        progress("Exchanging blinding factor via P2P...");
        let recv_blinding_from_p2p =
            p2p_exchange_blinding(my_is_smaller, counter_recv_random_for_send, local, peer).await?;

        // ═══════════ Phase 5: Compute recv info ═══════════
        let my_recv_token = counter_lock_token.clone();

        // Determine recv blinding factor:
        // - Smaller party: received from larger party via P2P (Phase 4.5).
        // - Larger party: generated fresh in Phase 4, kept locally.
        let my_recv_random = if my_is_smaller {
            recv_blinding_from_p2p
        } else {
            my_recv_random_for_larger.expect("larger party must have generated recv random")
        };

        // Compute recv amount:
        // - Smaller party: its full amount is consumed → recv = own amount converted at price.
        // - Larger party: recv = counter's full amount converted at price (counter_locked_amount).
        let my_recv_amount = if my_is_smaller {
            // Smaller party's fill = all of its locked amount.
            // recv token is in the other denomination.
            match my_order.trade_type {
                // I sell t1: recv t2 = my_locked_amount * price
                TradeType::Sell => my_locked_amount * price,
                // I buy with t2: recv t1 = my_locked_amount / price
                TradeType::Buy => {
                    if price > 0 {
                        my_locked_amount / price
                    } else {
                        0
                    }
                }
            }
        } else {
            // Larger party: recv = counter's locked amount converted at price.
            match my_order.trade_type {
                // I sell t1, counter buys with t2: recv t2 = counter_locked_amount (already in t2)
                // Wait — counter locks the OTHER token. recv = fill in my recv token.
                TradeType::Sell => {
                    // I sell t1. Counter buys with t2. Counter locks t2.
                    // fill_t1 = min(my_lock_t1, counter_lock_t2/price)
                    // Since I'm larger: fill_t1 = counter_lock_t2/price
                    // My recv = fill_t2 = fill_t1 * price = counter_lock_t2
                    counter_locked_amount
                }
                TradeType::Buy => {
                    // I buy with t2. Counter sells t1. Counter locks t1.
                    // fill_t1 = min(counter_lock_t1, my_lock_t2/price)
                    // Since I'm larger: fill_t1 = counter_lock_t1
                    // My recv = fill_t1 = counter_lock_t1
                    counter_locked_amount
                }
            }
        };

        let my_recv_commit_hex = fr_to_hex(&poseidon_commit(my_recv_amount, &my_recv_random));
        let recv_cash_id =
            orderbook::compute_cash_id(&my_pubkey, &my_recv_token, &my_recv_commit_hex);

        // Build change fields for larger party.
        let (
            out_change_cash_id,
            out_change_token,
            out_change_amount,
            out_change_random_hex,
            out_change_commit_hex,
        ) = if let Some((amt, rnd, commit_hex)) = change_info {
            let change_cash_id =
                orderbook::compute_cash_id(&my_pubkey, &my_lock_token, &commit_hex);
            (
                Some(change_cash_id),
                Some(my_lock_token.clone()),
                Some(amt),
                Some(hex::encode(rnd)),
                Some(commit_hex),
            )
        } else {
            (None, None, None, None, None)
        };

        progress("Settlement complete!");

        Ok(SettleOutcome {
            recv_cash_id,
            recv_token: my_recv_token,
            recv_amount: my_recv_amount,
            recv_random_hex: hex::encode(my_recv_random),
            change_cash_id: out_change_cash_id,
            change_token: out_change_token,
            change_amount: out_change_amount,
            change_random_hex: out_change_random_hex,
            change_commitment_hex: out_change_commit_hex,
        })
    }

    /// Return the set of locked input cash IDs that should be marked as spent.
    pub fn spent_cash_ids(order: &Order) -> HashSet<String> {
        order.input_cash_ids.iter().cloned().collect()
    }

    // ────────────────────── Helper Functions ──────────────────────

    /// P2P amount exchange: smaller party sends its locked amount to larger party.
    ///
    /// - Smaller: connect to larger, send `my_locked_amount` (8 bytes LE). Returns 0 (unused).
    /// - Larger: listen, receive counter's locked amount. Returns the received value.
    ///
    /// Port: QUIC port + 1.
    async fn p2p_exchange_amount(
        my_is_smaller: bool,
        my_locked_amount: u64,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<u64, String> {
        use tokio::net::TcpListener;

        let tcp_local = SocketAddr::new(local.ip(), local.port().wrapping_add(1));
        let tcp_peer = SocketAddr::new(peer.ip(), peer.port().wrapping_add(1));

        if my_is_smaller {
            // Smaller → larger: send my amount.
            let mut stream = tcp_connect_retry(&tcp_peer).await?;
            stream
                .write_all(&my_locked_amount.to_le_bytes())
                .await
                .map_err(|e| format!("P2P send amount: {e}"))?;
            Ok(0) // smaller doesn't need counter's amount
        } else {
            // Larger: listen for smaller's amount.
            let listener = TcpListener::bind(tcp_local)
                .await
                .map_err(|e| format!("P2P bind (amount): {e}"))?;
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept())
                    .await
                    .map_err(|_| "P2P: timeout waiting for smaller party amount".to_string())?
                    .map_err(|e| format!("P2P accept (amount): {e}"))?;
            let mut buf = [0u8; 8];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("P2P recv amount: {e}"))?;
            Ok(u64::from_le_bytes(buf))
        }
    }

    /// P2P blinding factor exchange: larger party sends recv blinding factor to smaller.
    ///
    /// - Larger: connect to smaller, send 32-byte blinding factor. Returns own recv random
    ///   (ECDH-derived r_match, already known).
    /// - Smaller: listen, receive 32-byte blinding factor.
    ///
    /// Port: QUIC port + 2 (different from amount exchange).
    async fn p2p_exchange_blinding(
        my_is_smaller: bool,
        blinding_to_send: Option<[u8; 32]>,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<[u8; 32], String> {
        use tokio::net::TcpListener;

        let tcp_local = SocketAddr::new(local.ip(), local.port().wrapping_add(2));
        let tcp_peer = SocketAddr::new(peer.ip(), peer.port().wrapping_add(2));

        if my_is_smaller {
            // Smaller: listen for blinding factor from larger.
            let listener = TcpListener::bind(tcp_local)
                .await
                .map_err(|e| format!("P2P bind (blinding): {e}"))?;
            let (mut stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(60), listener.accept())
                    .await
                    .map_err(|_| "P2P: timeout waiting for blinding factor".to_string())?
                    .map_err(|e| format!("P2P accept (blinding): {e}"))?;
            let mut buf = [0u8; 32];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("P2P recv blinding: {e}"))?;
            Ok(buf)
        } else {
            // Larger → smaller: send blinding factor.
            let blinding = blinding_to_send.ok_or("larger party must have blinding factor")?;
            let mut stream = tcp_connect_retry(&tcp_peer).await?;
            stream
                .write_all(&blinding)
                .await
                .map_err(|e| format!("P2P send blinding: {e}"))?;
            // Larger party's own recv random: not received via P2P; caller computes it.
            // Return a placeholder — caller will override.
            Ok([0u8; 32])
        }
    }

    /// TCP connect with retry (peer may not be listening yet).
    async fn tcp_connect_retry(addr: &SocketAddr) -> Result<tokio::net::TcpStream, String> {
        use tokio::net::TcpStream;
        for _ in 0..15 {
            match TcpStream::connect(addr).await {
                Ok(s) => return Ok(s),
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        Err(format!("P2P: failed to connect to {addr}"))
    }

    /// Convert hex string to BN254 Fr decimal string.
    fn hex_to_fr_decimal(hex_str: &str) -> String {
        let bytes = hex::decode(hex_str).expect("valid hex");
        let n = BigUint::from_bytes_be(&bytes);
        n.to_string()
    }

    /// Convert hex string to [u8; 32].
    fn hex_to_bytes32(hex_str: &str) -> [u8; 32] {
        let raw = hex::decode(hex_str).expect("valid hex");
        let mut arr = [0u8; 32];
        let start = 32usize.saturating_sub(raw.len());
        arr[start..].copy_from_slice(&raw[..raw.len().min(32)]);
        arr
    }

    /// Compute (fill_t1, fill_t2) for a matched pair.
    fn compute_fills(
        order_a: &Order,
        _order_b: &Order,
        locked_a: u64,
        locked_b: u64,
        price: u64,
    ) -> (u64, u64) {
        let (seller_lock_t1, buyer_lock_t2) = match order_a.trade_type {
            TradeType::Sell => (locked_a, locked_b),
            TradeType::Buy => (locked_b, locked_a),
        };
        let buyer_wanted_t1 = if price > 0 { buyer_lock_t2 / price } else { 0 };
        let fill_t1 = seller_lock_t1.min(buyer_wanted_t1);
        let fill_t2 = fill_t1 * price;
        (fill_t1, fill_t2)
    }

    /// Build the larger party's ZK settlement leg with proof.
    ///
    /// `my_recv_random` / `counter_recv_random`: fresh blinding factors for recv outputs.
    /// `change_random` is pre-generated by the caller so it can be captured.
    #[allow(clippy::too_many_arguments)]
    fn build_larger_leg(
        inputs: &[CashRecord],
        my_recv_random: &[u8; 32],
        counter_recv_random: &[u8; 32],
        price: u64,
        token: &TokenID,
        order: &Order,
        change_amount: u64,
        change_random: &[u8; 32],
        counterparty_recv_commit_hex: &str,
        counterparty_pubkey: &str,
        handle: &TestCircuitHandle,
        zkey: &Path,
    ) -> Result<SettleTokenLegParam, String> {
        let inputs_for_witness = decode_inputs(inputs)?;
        let inputs_sum: u64 = inputs.iter().map(|r| r.amount).sum();
        let my_fill = inputs_sum
            .checked_sub(change_amount)
            .ok_or("change > inputs.sum")?;
        let is_token2_sender = token == &order.subject.token2;
        let (other_fill, r_my, r_other) = if is_token2_sender {
            (
                my_fill / price.max(1),
                *my_recv_random,
                *counter_recv_random,
            )
        } else {
            (my_fill * price, *my_recv_random, *counter_recv_random)
        };
        let sp = prove_settle_larger(
            SettleLargerWitness {
                r_my,
                other_fill,
                r_other,
                price,
                is_token2_sender,
                inputs: inputs_for_witness,
                change_amount,
                change_random: *change_random,
                counterparty_recv_commitment_hex: counterparty_recv_commit_hex.to_string(),
            },
            handle,
            zkey,
        )
        .map_err(|e| format!("prove_settle_larger: {e}"))?;
        let change_commitment_hex = if change_amount == 0 {
            POSEIDON_ZERO_COMMITMENT_HEX.to_string()
        } else {
            sp.change_commitment_hex.clone()
        };
        Ok(SettleTokenLegParam {
            side: "larger".to_string(),
            token: token.clone(),
            my_match_commitment: Some(sp.my_match_commitment_hex),
            other_match_commitment: Some(sp.other_match_commitment_hex),
            price: Some(price),
            is_token2_sender: Some(is_token2_sender),
            change_commitment: Some(change_commitment_hex),
            change_pubkey: String::new(),
            match_commitment: None,
            recv_commitment: counterparty_recv_commit_hex.to_string(),
            recv_pubkey: counterparty_pubkey.to_string(),
            zk_proof: serde_json::to_string(&sp.proof_json).map_err(|e| e.to_string())?,
        })
    }

    /// Decode CashRecord randoms from hex to (amount, [u8; 32]) pairs.
    fn decode_inputs(inputs: &[CashRecord]) -> Result<Vec<(u64, [u8; 32])>, String> {
        let mut out = Vec::with_capacity(inputs.len());
        for rec in inputs {
            let raw = hex::decode(&rec.random).map_err(|e| format!("bad random hex: {e}"))?;
            if raw.len() != 32 {
                return Err(format!("cash {} random must be 32 bytes", rec.cash_id));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            out.push((rec.amount, arr));
        }
        Ok(out)
    }
}

#[cfg(not(target_os = "android"))]
pub use inner::*;
