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

    use ed25519_dalek::SigningKey;
    use num_bigint::BigUint;
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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
    }

    /// Run the full settlement flow for a matched order.
    ///
    /// `progress` is called at each major step so the UI can display status.
    /// `seed` is the 32-byte ed25519 seed for ECDH derivation.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_settle(
        client: &Arc<ChainClient>,
        my_order: &Order,
        counter_order: &Order,
        cash_records: &[CashRecord],
        seed: &[u8; 32],
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

        let my_random_hex = &my_locked_recs[0].random;
        let my_random_dec = hex_to_fr_decimal(my_random_hex);
        let my_commit = fr_to_hex(&poseidon_commit(
            my_locked_amount,
            &hex_to_bytes32(my_random_hex),
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
            my_locked_amount,
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

        // ═══════════ Phase 4: Build ZK leg and submit ═══════════
        let leg = if my_is_smaller {
            progress("Smaller party — confirming settlement...");
            None
        } else {
            progress("Generating ZK proof (larger party)...");
            let counter_locked_amount = guess_counter_locked_amount(counter_order, cash_records);
            let (fill_t1, fill_t2) = compute_fills(
                my_order,
                counter_order,
                my_locked_amount,
                counter_locked_amount,
                price,
            );

            let mut counter_recv_random = [0u8; 32];
            rand::rng().fill_bytes(&mut counter_recv_random);
            let counter_recv_amount = if counter_lock_token == my_order.subject.token1 {
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

            let (r_match_t1, r_match_t2) = derive_match_randoms(seed, &counter_order.pubkey);
            let my_fill = if my_lock_token == my_order.subject.token1 {
                fill_t1
            } else {
                fill_t2
            };
            let change_amount = my_locked_amount.saturating_sub(my_fill);

            Some(build_larger_leg(
                &my_locked_recs,
                r_match_t1,
                r_match_t2,
                price,
                &my_lock_token,
                my_order,
                change_amount,
                &counter_recv_commit_hex,
                &counter_order.pubkey,
                &larger_handle,
                &larger_setup.zkey,
            )?)
        };

        progress("Submitting settlement to chain...");
        client
            .settle_orders(my_order_id.clone(), match_order_id.clone(), leg)
            .await
            .map_err(|e| format!("settle_orders: {e}"))?;

        // ═══════════ Phase 5: Update local CashStore info ═══════════
        let my_recv_token = counter_lock_token.clone();
        let (r_match_t1, r_match_t2) = derive_match_randoms(seed, &counter_order.pubkey);
        let r_my_recv = r_match_for_token(&my_recv_token, my_order, r_match_t1, r_match_t2);

        let counter_locked_amount = guess_counter_locked_amount(counter_order, cash_records);
        let (fill_t1, fill_t2) = compute_fills(
            my_order,
            counter_order,
            my_locked_amount,
            counter_locked_amount,
            price,
        );
        let my_recv_amount = if my_recv_token == my_order.subject.token1 {
            fill_t1
        } else {
            fill_t2
        };
        let my_recv_commit_hex = fr_to_hex(&poseidon_commit(my_recv_amount, &r_my_recv));

        let recv_cash_id =
            orderbook::compute_cash_id(&my_pubkey, &my_recv_token, &my_recv_commit_hex);

        progress("Settlement complete!");

        Ok(SettleOutcome {
            recv_cash_id,
            recv_token: my_recv_token,
            recv_amount: my_recv_amount,
            recv_random_hex: hex::encode(r_my_recv),
        })
    }

    /// Return the set of locked input cash IDs that should be marked as spent.
    pub fn spent_cash_ids(order: &Order) -> HashSet<String> {
        order.input_cash_ids.iter().cloned().collect()
    }

    // ────────────────────── Helper Functions ──────────────────────

    /// Derive match randoms via static ECDH (ed25519 -> x25519).
    /// Both parties compute the same shared secret without extra communication.
    fn derive_match_randoms(my_seed: &[u8; 32], counter_pubkey_hex: &str) -> ([u8; 32], [u8; 32]) {
        let signing_key = SigningKey::from_bytes(my_seed);
        let my_x25519_secret = StaticSecret::from(signing_key.to_scalar_bytes());

        let counter_pub_bytes: [u8; 32] = hex::decode(counter_pubkey_hex)
            .expect("valid hex pubkey")
            .try_into()
            .expect("pubkey must be 32 bytes");
        let counter_ed_point = curve25519_dalek::edwards::CompressedEdwardsY(counter_pub_bytes);
        let counter_montgomery = counter_ed_point
            .decompress()
            .expect("valid ed25519 point")
            .to_montgomery();
        let counter_x25519_pub = X25519PublicKey::from(counter_montgomery.to_bytes());

        let shared_secret = my_x25519_secret.diffie_hellman(&counter_x25519_pub);

        let mut h1 = Sha256::new();
        h1.update(b"r_match_t1:");
        h1.update(shared_secret.as_bytes());
        let r1: [u8; 32] = h1.finalize().into();

        let mut h2 = Sha256::new();
        h2.update(b"r_match_t2:");
        h2.update(shared_secret.as_bytes());
        let r2: [u8; 32] = h2.finalize().into();

        (r1, r2)
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

    /// Guess the counterparty's locked amount from local records. Falls back to 0.
    fn guess_counter_locked_amount(counter: &Order, records: &[CashRecord]) -> u64 {
        counter
            .input_cash_ids
            .iter()
            .filter_map(|id| records.iter().find(|r| &r.cash_id == id))
            .map(|r| r.amount)
            .sum()
    }

    /// Choose which r_match corresponds to the given token (Token1 vs Token2).
    fn r_match_for_token(
        token: &TokenID,
        order: &Order,
        r_t1: [u8; 32],
        r_t2: [u8; 32],
    ) -> [u8; 32] {
        if token == &order.subject.token1 {
            r_t1
        } else {
            r_t2
        }
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
    #[allow(clippy::too_many_arguments)]
    fn build_larger_leg(
        inputs: &[CashRecord],
        r_match_t1: [u8; 32],
        r_match_t2: [u8; 32],
        price: u64,
        token: &TokenID,
        order: &Order,
        change_amount: u64,
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
            (my_fill / price.max(1), r_match_t2, r_match_t1)
        } else {
            (my_fill * price, r_match_t1, r_match_t2)
        };
        let mut change_random = [0u8; 32];
        if change_amount > 0 {
            rand::rng().fill_bytes(&mut change_random);
        }
        let sp = prove_settle_larger(
            SettleLargerWitness {
                r_my,
                other_fill,
                r_other,
                price,
                is_token2_sender,
                inputs: inputs_for_witness,
                change_amount,
                change_random,
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
