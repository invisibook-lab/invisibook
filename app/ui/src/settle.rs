//! Desktop settlement per the paper (§VI): compare-only MPC, then each
//! side's own single-prover settle proof.
//!
//! The collaborative part — the MPC comparison, the smaller side's reveal,
//! the payout-note key exchange, and the collaborative PLONK π_cmp — runs
//! in the pre-built `settle2p_session` subprocess (a separate cargo
//! workspace pinned to an older toolchain, so it cannot be linked). This
//! module drives that subprocess over piped stdio, ferries the one ed25519
//! compare signature it asks for, submits the compare writing, then proves
//! THIS side's settle circuit (settle_small when fully filled,
//! settle_large otherwise) with rapidsnark and submits it.
//!
//! NOTE: peer QUIC addresses are exchanged on-chain today; production would
//! use an anonymous overlay. The subprocess uses mock Beaver triples and a
//! dev SRS — testnet only.

#[cfg(not(target_os = "android"))]
mod inner {
    use std::{
        collections::HashSet, fmt, fs, path::PathBuf, process::Stdio, sync::Arc, time::Duration,
    };

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        process::Command,
    };

    use invisibook_lib::{
        cash_store::CashRecord,
        chain::{
            ChainClient, CompareParams, SettleLargeParams, SettleSmallParams,
            verify_compare_cozk2p_sig,
        },
        note::{
            asset_id, fr_from_be_bytes, note_fr_to_hex, npk_from_sk, settle_large_bind,
            settle_small_bind,
        },
        note_prover::{
            SettleLargeWitness, SettleSmallWitness, prove_settle_large, prove_settle_small,
        },
        note_store::{NOTE_PENDING_MINT, NoteRecord},
        orderbook,
        types::*,
    };
    use zk::wallet::hex_to_fr;

    /// `Poseidon(0, 0)` — the zero-commitment used to pad unused locked
    /// slots to the circuit's fixed N=2 shape.
    pub const POSEIDON_ZERO_COMMITMENT_HEX: &str =
        "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";

    /// A newly minted locked CASH the wallet must persist (the relisted
    /// remainder collateral — still the cash model until Phase 5).
    #[derive(Clone, Debug)]
    pub struct NewCash {
        pub cash_id: String,
        pub token: String,
        pub amount: u64,
        pub random_hex: String,
    }

    /// This trader's incoming payout NOTE: the full opening the wallet must
    /// persist to keep it spendable (notes.json IS the money).
    #[derive(Clone, Debug)]
    pub struct NewNote {
        pub cm: String,
        pub token: String,
        pub amount: u64,
        pub r_hex: String,
        /// The note spending secret, derived from the wallet seed + order id
        /// (re-derivable in recovery).
        pub sk_hex: String,
    }

    /// The surviving (larger) side's on-book remainder after settlement: a
    /// fresh Locked collateral cash plus the order-commitment witness the
    /// chain relisted the order under.
    #[derive(Clone, Debug)]
    pub struct Remainder {
        pub locked: NewCash,
        pub order_amount: u64,
        pub order_random_hex: String,
    }

    /// The outcome of a successful settlement, from this trader's view.
    #[derive(Clone, Debug)]
    pub struct SettleOutcome {
        pub cmp: i8,
        pub recv: NewNote,
        /// Present only when this side survived on the book (had a
        /// remainder); the chain relisted the order in place.
        pub remainder: Option<Remainder>,
        /// Session scratch dir; the caller deletes it after persisting.
        pub session_dir: PathBuf,
    }

    /// Why a settlement did not complete. `CrossPrice`, `SelfMatch`, and
    /// `Unrecoverable` are permanent (the caller should stop retrying the
    /// pair); `Transient` and `OnChainRejected` are retryable after a
    /// backoff.
    #[derive(Clone, Debug)]
    pub enum SettleError {
        CrossPrice(String),
        SelfMatch,
        /// Local state is missing something no retry can restore (e.g. the
        /// order-commitment witness whose blinding exists only locally).
        Unrecoverable(String),
        Transient(String),
        OnChainRejected(String),
    }

    impl fmt::Display for SettleError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                SettleError::CrossPrice(m) => write!(f, "cross-price match unsupported: {m}"),
                SettleError::SelfMatch => write!(f, "self-matched pair cannot settle"),
                SettleError::Unrecoverable(m) => write!(f, "unrecoverable local state: {m}"),
                SettleError::Transient(m) => write!(f, "{m}"),
                SettleError::OnChainRejected(m) => write!(f, "settlement rejected on chain: {m}"),
            }
        }
    }

    /// Everything the settle flow needs from config: the prover binary, the
    /// data-dir subpaths, and the wallet seed the per-trade note spending
    /// secrets derive from.
    #[derive(Clone, Debug)]
    pub struct SettleDeps {
        pub bin: PathBuf,
        pub keys_dir: PathBuf,
        pub sessions_dir: PathBuf,
        /// Wallet seed for note-key derivation (the ed25519 seed works: the
        /// note secret is domain-separated by hashing).
        pub note_seed: [u8; 32],
    }

    /// The set of locked input cash IDs an order spends when it settles.
    pub fn spent_cash_ids(order: &Order) -> HashSet<String> {
        order.input_cash_ids.iter().cloned().collect()
    }

    /// Derive the per-trade note spending secret: SHA-256 over a domain
    /// tag, the wallet seed, and the order id — deterministic, so recovery
    /// can re-derive it from `witness.json`'s order id alone.
    fn note_sk_bytes(seed: &[u8; 32], order_id: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"invisibook-note-sk-v1");
        h.update(seed);
        h.update(order_id.as_bytes());
        h.finalize().into()
    }

    // ── Subprocess wire structs (mirror cozk2p's session serde exactly) ──

    #[derive(Serialize)]
    struct LockedCashWire {
        amount: u64,
        random: String,
    }

    #[derive(Serialize)]
    struct MyPrivateWire {
        order_amount: u64,
        r_order: String,
        locked: Vec<LockedCashWire>,
    }

    #[derive(Serialize)]
    struct SessionInputWire {
        role: String,
        order_a_id: String,
        order_b_id: String,
        my_order_id: String,
        my_input_cash_ids: Vec<String>,
        my_lock_token: String,
        my_recv_token: String,
        price: u64,
        a_is_seller: bool,
        order_a: String,
        order_b: String,
        locked_a: [String; 2],
        locked_b: [String; 2],
        my_recv_npk: String,
        my: MyPrivateWire,
    }

    #[derive(Deserialize)]
    struct NeedSigWire {
        cmp: i8,
    }

    /// Subset of the subprocess `SettlePublic` the app cross-checks; serde
    /// ignores the fields not named here.
    #[derive(Deserialize)]
    struct PublicWire {
        order_a: String,
        order_b: String,
    }

    #[derive(Clone, Deserialize)]
    struct MyOutcomeWire {
        i_am_smaller: bool,
        fill: u64,
        recv_amount: u64,
        recv_token: String,
        r_recv: String,
        recv_commitment: String,
        ctr_recv_npk: String,
        ctr_r_recv: String,
        ctr_order_amount: u64,
        ctr_r_order: String,
        new_order_amount: u64,
        r_order_new: String,
        new_order_commitment: String,
        new_locked_amount: u64,
        r_locked_new: String,
        new_locked_commitment: String,
    }

    #[derive(Deserialize)]
    struct SessionResultWire {
        cmp: i8,
        public: PublicWire,
        proof_hex: String,
        sig_a: String,
        sig_b: String,
        my: MyOutcomeWire,
    }

    /// Crash-recovery record the subprocess writes before any secret leaves
    /// it. Mirrors cozk2p's `SessionWitness`.
    #[derive(Deserialize)]
    struct SessionWitnessWire {
        my_order_id: String,
        my_input_cash_ids: Vec<String>,
        my_lock_token: String,
        my_recv_token: String,
        my: MyOutcomeWire,
    }

    /// Token an order locks as collateral: Token1 for a sell, Token2 for a
    /// buy.
    fn lock_token(order: &Order) -> String {
        match order.trade_type {
            TradeType::Buy => order.subject.token2.clone(),
            TradeType::Sell => order.subject.token1.clone(),
        }
    }

    /// Token an order's owner receives at settlement (the opposite leg).
    fn recv_token(order: &Order) -> String {
        match order.trade_type {
            TradeType::Buy => order.subject.token1.clone(),
            TradeType::Sell => order.subject.token2.clone(),
        }
    }

    /// Read one order's locked input commitment hexes from chain state,
    /// padded to two slots with the zero commitment.
    async fn gather_locked_commitments(
        client: &ChainClient,
        order: &Order,
        token: &str,
    ) -> Result<[String; 2], SettleError> {
        let account = client
            .get_account(&order.pubkey, token)
            .await
            .map_err(|e| SettleError::Transient(format!("get_account: {e}")))?;
        let mut out = [
            POSEIDON_ZERO_COMMITMENT_HEX.to_string(),
            POSEIDON_ZERO_COMMITMENT_HEX.to_string(),
        ];
        for (slot, id) in order.input_cash_ids.iter().take(2).enumerate() {
            let cash = account.cash.iter().find(|c| &c.id == id).ok_or_else(|| {
                SettleError::Transient(format!("locked cash {id} not found on chain"))
            })?;
            out[slot] = cash.amount.clone();
        }
        Ok(out)
    }

    /// Build this trader's private witness from its local cash records.
    /// The first locked input's record must carry the explicit
    /// `order_amount` / `order_random` witness that opens the on-chain
    /// `order.amount` commitment.
    fn build_my_private(
        order: &Order,
        records: &[CashRecord],
    ) -> Result<MyPrivateWire, SettleError> {
        let mut locked = Vec::new();
        for id in &order.input_cash_ids {
            let rec = records.iter().find(|r| &r.cash_id == id).ok_or_else(|| {
                SettleError::Transient(format!("missing local CashRecord for locked input {id}"))
            })?;
            locked.push(LockedCashWire {
                amount: rec.amount,
                random: rec.random.clone(),
            });
        }
        if locked.is_empty() {
            return Err(SettleError::Transient("order has no locked inputs".into()));
        }
        let first = records
            .iter()
            .find(|r| r.cash_id == order.input_cash_ids[0])
            .expect("checked above");
        let (order_amount, r_order) = match (first.order_amount, first.order_random.clone()) {
            (Some(amount), Some(random)) => (amount, random),
            _ => {
                return Err(SettleError::Unrecoverable(format!(
                    "locked input {} carries no order-commitment witness \
                     (order_amount/order_random); order.amount cannot be opened",
                    first.cash_id
                )));
            }
        };
        Ok(MyPrivateWire {
            order_amount,
            r_order,
            locked,
        })
    }

    /// Run the full settlement for a matched pair: compare session,
    /// compare submission, this side's settle proof + submission.
    pub async fn run_settle(
        client: &Arc<ChainClient>,
        my_order: &Order,
        counter_order: &Order,
        cash_records: &[CashRecord],
        deps: &SettleDeps,
        mut progress: impl FnMut(&str),
    ) -> Result<SettleOutcome, SettleError> {
        let my_pubkey = client.pubkey_hex().to_string();

        // Self-match would deadlock the serial settle coroutine.
        if counter_order.pubkey == my_pubkey {
            return Err(SettleError::SelfMatch);
        }

        // Deterministic roles: order A is the maker (lower block height,
        // tie → smaller id), mirroring the chain.
        let (maker, taker) = orderbook::maker_taker(my_order, counter_order);
        let i_am_maker = maker.id == my_order.id;
        let role = if i_am_maker { "trader-a" } else { "trader-b" };

        // Equal-price requirement of the settle circuits.
        let (mp, tp) = match (maker.price, taker.price) {
            (Some(mp), Some(tp)) => (mp, tp),
            _ => return Err(SettleError::CrossPrice("orders missing price".into())),
        };
        if mp != tp {
            return Err(SettleError::CrossPrice(
                "co-zk settlement requires equal order prices".into(),
            ));
        }
        let price = mp;
        let a_is_seller = maker.trade_type == TradeType::Sell;

        // Chain-sourced public inputs.
        progress("Reading on-chain settlement state...");
        let order_a = maker.amount.clone();
        let order_b = taker.amount.clone();
        let locked_a = gather_locked_commitments(client, maker, &lock_token(maker)).await?;
        let locked_b = gather_locked_commitments(client, taker, &lock_token(taker)).await?;

        let my_lock_token = lock_token(my_order);
        let my_recv_token = recv_token(my_order);
        let my_priv = build_my_private(my_order, cash_records)?;

        // Fresh per-trade note key: the payout note this wallet receives.
        let my_note_sk = note_sk_bytes(&deps.note_seed, &my_order.id);
        let my_recv_npk = note_fr_to_hex(&npk_from_sk(fr_from_be_bytes(&my_note_sk)));

        let input = SessionInputWire {
            role: role.to_string(),
            order_a_id: maker.id.clone(),
            order_b_id: taker.id.clone(),
            my_order_id: my_order.id.clone(),
            my_input_cash_ids: my_order.input_cash_ids.clone(),
            my_lock_token: my_lock_token.clone(),
            my_recv_token: my_recv_token.clone(),
            price,
            a_is_seller,
            order_a: order_a.clone(),
            order_b: order_b.clone(),
            locked_a,
            locked_b,
            my_recv_npk,
            my: my_priv,
        };

        let session_dir = deps.sessions_dir.join(&my_order.id);
        fs::create_dir_all(&session_dir)
            .map_err(|e| SettleError::Transient(format!("creating session dir: {e}")))?;
        let input_path = session_dir.join("input.json");
        fs::write(
            &input_path,
            serde_json::to_vec(&input).expect("SessionInput serializes"),
        )
        .map_err(|e| SettleError::Transient(format!("writing session input: {e}")))?;

        // ── Rendezvous: exchange QUIC addresses on chain ──
        progress("Registering settlement address...");
        let base = bind_ephemeral_port().await?;
        let local_addr = format!("127.0.0.1:{base}");
        client
            .register_settle_addr(my_order.id.clone(), counter_order.id.clone(), &local_addr)
            .await
            .map_err(|e| SettleError::Transient(format!("register_settle_addr: {e}")))?;

        progress("Waiting for counterparty...");
        let peer_addr = poll_peer_addr(client, &my_order.id, &counter_order.id).await?;

        // ── Compare session (subprocess) ──
        let result = run_prover_session(
            client,
            deps,
            role,
            &local_addr,
            &peer_addr,
            &input_path,
            &session_dir,
            &maker.id,
            &taker.id,
            &maker.pubkey,
            &taker.pubkey,
            &order_a,
            &order_b,
            &mut progress,
        )
        .await?;

        // ── Submit the comparison (either party may land it) ──
        progress("Submitting comparison...");
        let compare = CompareParams {
            order_a_id: maker.id.clone(),
            order_b_id: taker.id.clone(),
            cmp: result.cmp,
            sig_a: result.res.sig_a.clone(),
            sig_b: result.res.sig_b.clone(),
            zk_proof: result.res.proof_hex.clone(),
        };
        if let Err(e) = client.submit_compare_cozk2p(&compare).await {
            let msg = e.to_string();
            if !(msg.contains("not Matched") || msg.contains("duplicated")) {
                progress(&format!("compare submit warning: {msg}"));
            }
        }
        wait_for_settling(client, &my_order.id).await?;

        // ── This side's settle proof + submission ──
        progress("Proving this side's settlement...");
        let outcome = &result.res.my;
        let hex_fr = |s: &str, what: &str| {
            hex_to_fr(s).map_err(|e| SettleError::Transient(format!("{what}: {e}")))
        };
        let my_side_sell = my_order.trade_type == TradeType::Sell;
        let pay_asset = asset_id(&my_lock_token)
            .map_err(|e| SettleError::Unrecoverable(format!("pay asset: {e}")))?;
        let npk_ctr = hex_fr(&outcome.ctr_recv_npk, "ctr_recv_npk")?;
        let r_note = hex_fr(&outcome.ctr_r_recv, "ctr_r_recv")?;
        let locked_pairs: Vec<(u64, _)> = {
            let mut v = Vec::new();
            for l in &input.my.locked {
                v.push((l.amount, hex_fr(&l.random, "locked random")?));
            }
            while v.len() < 2 {
                v.push((0, hex_fr(&"0".repeat(64), "zero pad")?));
            }
            v
        };
        let q = input.my.order_amount;
        let r_q = hex_fr(&input.my.r_order, "r_order")?;

        if outcome.i_am_smaller {
            let setup =
                tokio::task::block_in_place(|| zk::setup::dev_setup_snarkjs("settle_small"))
                    .map_err(|e| SettleError::Transient(format!("settle_small setup: {e}")))?;
            let handle = zk::test_circuit::TestCircuitHandle::from_compiled(&setup.circuit_dir)
                .map_err(|e| SettleError::Transient(format!("circuit handle: {e}")))?;
            let mut w = SettleSmallWitness {
                q,
                r_q,
                locked: [locked_pairs[0], locked_pairs[1]],
                price,
                side_sell: my_side_sell,
                pay_asset,
                npk_ctr,
                r_note,
                bind: fr_from_be_bytes(&[0u8; 32]),
            };
            let cm_note_out = note_fr_to_hex(&w.cm_note_out());
            w.bind = settle_small_bind(
                client.chain_id(),
                &my_order.id,
                &counter_order.id,
                &cm_note_out,
            );
            let proof = tokio::task::block_in_place(|| prove_settle_small(w, &handle, &setup.zkey))
                .map_err(|e| SettleError::Transient(format!("prove settle_small: {e}")))?;

            let mut params = SettleSmallParams {
                order_id: my_order.id.clone(),
                match_order_id: counter_order.id.clone(),
                cm_note_out: proof.cm_note_out_hex.clone(),
                signature: String::new(),
                zk_proof: serde_json::to_string(&proof.proof_json)
                    .map_err(|e| SettleError::Transient(format!("proof json: {e}")))?,
            };
            params.signature = client.sign_settle_small(&params);
            progress("Submitting settlement (small side)...");
            client
                .settle_small(&params)
                .await
                .map_err(|e| SettleError::Transient(format!("settle_small submit: {e}")))?;
        } else {
            let setup =
                tokio::task::block_in_place(|| zk::setup::dev_setup_snarkjs("settle_large"))
                    .map_err(|e| SettleError::Transient(format!("settle_large setup: {e}")))?;
            let handle = zk::test_circuit::TestCircuitHandle::from_compiled(&setup.circuit_dir)
                .map_err(|e| SettleError::Transient(format!("circuit handle: {e}")))?;
            let mut w = SettleLargeWitness {
                q,
                r_q,
                q_ctr: outcome.ctr_order_amount,
                r_q_ctr: hex_fr(&outcome.ctr_r_order, "ctr_r_order")?,
                locked: [locked_pairs[0], locked_pairs[1]],
                price,
                side_sell: my_side_sell,
                r_q_residual: hex_fr(&outcome.r_order_new, "r_order_new")?,
                r_locked_residual: hex_fr(&outcome.r_locked_new, "r_locked_new")?,
                pay_asset,
                npk_ctr,
                r_note,
                bind: fr_from_be_bytes(&[0u8; 32]),
            };
            let (cm_q_res, cm_locked_res, cm_note) = w.output_cms();
            w.bind = settle_large_bind(
                client.chain_id(),
                &my_order.id,
                &counter_order.id,
                &note_fr_to_hex(&cm_q_res),
                &note_fr_to_hex(&cm_locked_res),
                &note_fr_to_hex(&cm_note),
            );
            let proof = tokio::task::block_in_place(|| prove_settle_large(w, &handle, &setup.zkey))
                .map_err(|e| SettleError::Transient(format!("prove settle_large: {e}")))?;

            let mut params = SettleLargeParams {
                order_id: my_order.id.clone(),
                match_order_id: counter_order.id.clone(),
                cm_q_residual: proof.cm_q_residual_hex.clone(),
                cm_locked_residual: proof.cm_locked_residual_hex.clone(),
                cm_note_out: proof.cm_note_out_hex.clone(),
                signature: String::new(),
                zk_proof: serde_json::to_string(&proof.proof_json)
                    .map_err(|e| SettleError::Transient(format!("proof json: {e}")))?,
            };
            params.signature = client.sign_settle_large(&params);
            progress("Submitting settlement (large side)...");
            client
                .settle_large(&params)
                .await
                .map_err(|e| SettleError::Transient(format!("settle_large submit: {e}")))?;
        }

        progress("Confirming settlement on chain...");
        confirm_on_chain(client, &my_order.id, &outcome.new_order_commitment).await?;

        Ok(outcome_from_result(
            &my_pubkey,
            &my_lock_token,
            &deps.note_seed,
            &my_order.id,
            result.cmp,
            outcome,
            session_dir,
        ))
    }

    /// The prover subprocess plus its parsed result.
    struct ProverOutput {
        cmp: i8,
        res: SessionResultWire,
    }

    /// Bind an ephemeral UDP port and release it, returning the number for
    /// the QUIC endpoint to reuse.
    async fn bind_ephemeral_port() -> Result<u16, SettleError> {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| SettleError::Transient(format!("bind ephemeral port: {e}")))?;
        let port = sock
            .local_addr()
            .map_err(|e| SettleError::Transient(format!("local_addr: {e}")))?
            .port();
        drop(sock);
        Ok(port)
    }

    /// Poll the on-chain rendezvous for the counterparty's address, capped
    /// so a stalled pair does not head-of-line-block the serial coroutine.
    async fn poll_peer_addr(
        client: &ChainClient,
        my_order_id: &str,
        counter_id: &str,
    ) -> Result<String, SettleError> {
        for _ in 0..45 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match client
                .query_settle_addr(my_order_id.to_string(), counter_id.to_string())
                .await
            {
                Ok(Some(addr)) => return Ok(addr),
                Ok(None) => continue,
                Err(e) => eprintln!("[settle] query_settle_addr: {e}"),
            }
        }
        Err(SettleError::Transient(
            "timed out waiting for the counterparty to register".into(),
        ))
    }

    /// Poll until this trader's order reaches Settling (the comparison
    /// landed — submitted by either party).
    async fn wait_for_settling(client: &ChainClient, my_order_id: &str) -> Result<(), SettleError> {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match query_one(client, my_order_id).await {
                Some(order) if order.status == OrderStatus::Settling => return Ok(()),
                // Already past Settling (fast counterparty): fine too.
                Some(order) if order.status == OrderStatus::Done => return Ok(()),
                _ => continue,
            }
        }
        Err(SettleError::OnChainRejected(
            "comparison not observed on chain within the confirmation window".into(),
        ))
    }

    async fn query_one(client: &ChainClient, order_id: &str) -> Option<Order> {
        client
            .query_orders(
                Some(order_id.to_string()),
                None,
                None,
                None,
                None,
                Some(1),
                Some(0),
            )
            .await
            .ok()
            .and_then(|orders| orders.into_iter().find(|o| o.id == order_id))
    }

    /// Spawn `settle2p_session`, stream its progress, answer its one
    /// signature request, and parse its result. Bounded by a 10-minute
    /// watchdog; the child is killed if this future is dropped.
    #[allow(clippy::too_many_arguments)]
    async fn run_prover_session(
        client: &ChainClient,
        deps: &SettleDeps,
        role: &str,
        local_addr: &str,
        peer_addr: &str,
        input_path: &std::path::Path,
        session_dir: &std::path::Path,
        order_a_id: &str,
        order_b_id: &str,
        maker_pubkey: &str,
        taker_pubkey: &str,
        expected_order_a: &str,
        expected_order_b: &str,
        progress: &mut impl FnMut(&str),
    ) -> Result<ProverOutput, SettleError> {
        let mut child = Command::new(&deps.bin)
            .arg("--role")
            .arg(role)
            .arg("--listen")
            .arg(local_addr)
            .arg("--peer")
            .arg(peer_addr)
            .arg("--input")
            .arg(input_path)
            .arg("--out-dir")
            .arg(session_dir)
            .arg("--keys-dir")
            .arg(&deps.keys_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                SettleError::Transient(format!("spawning prover {}: {e}", deps.bin.display()))
            })?;

        let stdout = child.stdout.take().expect("piped stdout");
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let mut lines = BufReader::new(stdout).lines();

        let interaction = async {
            loop {
                let line = lines
                    .next_line()
                    .await
                    .map_err(|e| SettleError::Transient(format!("prover stdout: {e}")))?;
                let Some(line) = line else {
                    break;
                };
                let value: serde_json::Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(_) => continue, // ignore non-JSON lines
                };
                match value.get("event").and_then(|e| e.as_str()) {
                    Some("phase") => {
                        if let Some(msg) = value.get("msg").and_then(|m| m.as_str()) {
                            progress(msg);
                        }
                    }
                    Some("need_sig") => {
                        let ns: NeedSigWire = serde_json::from_value(value)
                            .map_err(|e| SettleError::Transient(format!("bad need_sig: {e}")))?;
                        let params = CompareParams {
                            order_a_id: order_a_id.to_string(),
                            order_b_id: order_b_id.to_string(),
                            cmp: ns.cmp,
                            sig_a: String::new(),
                            sig_b: String::new(),
                            zk_proof: String::new(),
                        };
                        let sig = client.sign_compare_cozk2p(&params);
                        let sig_line = format!("{{\"sig\":\"{sig}\"}}\n");
                        stdin
                            .write_all(sig_line.as_bytes())
                            .await
                            .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))?;
                        stdin
                            .flush()
                            .await
                            .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))?;
                    }
                    Some("done") => break,
                    _ => {}
                }
            }
            Ok::<(), SettleError>(())
        };

        // 10-minute watchdog over the whole interaction.
        match tokio::time::timeout(Duration::from_secs(600), interaction).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.start_kill();
                return Err(e);
            }
            Err(_) => {
                let _ = child.start_kill();
                return Err(SettleError::Transient(
                    "prover timed out after 10 minutes".into(),
                ));
            }
        }

        let status = child
            .wait()
            .await
            .map_err(|e| SettleError::Transient(format!("awaiting prover: {e}")))?;
        if !status.success() {
            let mut err = String::new();
            let _ = stderr.read_to_string(&mut err).await;
            let err = err.trim();
            let hint = if err.contains("memory") || err.contains("alloc") {
                " (out of memory — collaborative proving needs several GB)"
            } else {
                ""
            };
            return Err(SettleError::Transient(format!(
                "prover exited with failure{hint}: {err}"
            )));
        }

        let result_bytes = fs::read(session_dir.join("result.json"))
            .map_err(|e| SettleError::Transient(format!("reading prover result: {e}")))?;
        let res: SessionResultWire = serde_json::from_slice(&result_bytes)
            .map_err(|e| SettleError::Transient(format!("parsing prover result: {e}")))?;

        // The proven statement's order commitments must equal the ones read
        // from chain (the prover is a trusted local component, but this
        // catches a stale read or a corrupt result file cheaply).
        if res.public.order_a != expected_order_a || res.public.order_b != expected_order_b {
            return Err(SettleError::Transient(
                "prover statement does not match on-chain order commitments".into(),
            ));
        }

        // Sanity: both compare signatures must verify (the chain re-verifies
        // regardless).
        let params = CompareParams {
            order_a_id: order_a_id.to_string(),
            order_b_id: order_b_id.to_string(),
            cmp: res.cmp,
            sig_a: res.sig_a.clone(),
            sig_b: res.sig_b.clone(),
            zk_proof: res.proof_hex.clone(),
        };
        if !verify_compare_cozk2p_sig(&params, maker_pubkey, &res.sig_a)
            || !verify_compare_cozk2p_sig(&params, taker_pubkey, &res.sig_b)
        {
            return Err(SettleError::Transient(
                "compare signatures failed local verification".into(),
            ));
        }

        Ok(ProverOutput { cmp: res.cmp, res })
    }

    /// Poll until this trader's order is `Done` or has been relisted with
    /// its new remainder commitment. Timing out while the pair is still
    /// mutually matched means the writing was rejected.
    async fn confirm_on_chain(
        client: &ChainClient,
        my_order_id: &str,
        my_new_order_commitment: &str,
    ) -> Result<(), SettleError> {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Some(order) = query_one(client, my_order_id).await {
                if order.status == OrderStatus::Done
                    || (!my_new_order_commitment.is_empty()
                        && order.amount == *my_new_order_commitment)
                {
                    return Ok(());
                }
            }
        }
        Err(SettleError::OnChainRejected(
            "settlement not observed on chain within the confirmation window".into(),
        ))
    }

    /// Assemble the local outcome from the subprocess result.
    fn outcome_from_result(
        my_pubkey: &str,
        my_lock_token: &str,
        note_seed: &[u8; 32],
        my_order_id: &str,
        cmp: i8,
        my: &MyOutcomeWire,
        session_dir: PathBuf,
    ) -> SettleOutcome {
        let recv = NewNote {
            cm: my.recv_commitment.clone(),
            token: my.recv_token.clone(),
            amount: my.recv_amount,
            r_hex: my.r_recv.clone(),
            sk_hex: hex::encode(note_sk_bytes(note_seed, my_order_id)),
        };
        let remainder = if my.new_order_amount > 0 {
            Some(Remainder {
                locked: NewCash {
                    cash_id: orderbook::compute_cash_id(
                        my_pubkey,
                        my_lock_token,
                        &my.new_locked_commitment,
                    ),
                    token: my_lock_token.to_string(),
                    amount: my.new_locked_amount,
                    random_hex: my.r_locked_new.clone(),
                },
                order_amount: my.new_order_amount,
                order_random_hex: my.r_order_new.clone(),
            })
        } else {
            None
        };
        let _ = my.fill; // carried for diagnostics; not persisted separately
        SettleOutcome {
            cmp,
            recv,
            remainder,
            session_dir,
        }
    }

    // ── Crash recovery ──

    /// A landed-but-unpersisted session recovered from its witness file.
    #[derive(Clone, Debug)]
    pub struct Recovered {
        pub spent_ids: Vec<String>,
        /// The incoming payout note to materialize (with leaf index).
        pub note: NoteRecord,
        /// The relisted remainder collateral cash, when this side survived.
        pub remainder_cash: Vec<CashRecord>,
        pub dir: PathBuf,
    }

    /// Inspect every session dir and decide, per the recovery predicate
    /// (payout-note existence in the pool tree), whether it LANDED
    /// (materialize its records) or did not (delete it). Session dirs whose
    /// settlement has not yet finished (no witness.json) are left untouched.
    pub async fn recover_all_sessions(
        client: &ChainClient,
        note_seed: &[u8; 32],
        sessions_dir: &std::path::Path,
    ) -> Vec<Recovered> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(sessions_dir) {
            Ok(e) => e,
            Err(_) => return out,
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            match try_recover_session(client, note_seed, &dir).await {
                Recovery::Landed(rec) => out.push(rec),
                Recovery::Deleted => {
                    let _ = fs::remove_dir_all(&dir);
                }
                Recovery::InProgress => {}
            }
        }
        out
    }

    /// Outcome of examining one session dir for recovery.
    pub enum Recovery {
        /// Landed on chain — records in the payload should be materialized.
        Landed(Recovered),
        /// Did not land — the dir is stale and should be removed.
        Deleted,
        /// No witness yet (mid-flight or never started) — leave it alone.
        InProgress,
    }

    /// Recovery predicate for one session dir: read `witness.json` and ask
    /// the chain whether this side's payout note commitment is in the pool
    /// tree. The note's spending secret is re-derived from the wallet seed
    /// and the order id — nothing beyond the witness file is needed.
    pub async fn try_recover_session(
        client: &ChainClient,
        note_seed: &[u8; 32],
        dir: &std::path::Path,
    ) -> Recovery {
        let witness_bytes = match fs::read(dir.join("witness.json")) {
            Ok(b) => b,
            Err(_) => return Recovery::InProgress,
        };
        let witness: SessionWitnessWire = match serde_json::from_slice(&witness_bytes) {
            Ok(w) => w,
            Err(_) => return Recovery::Deleted,
        };
        let leaf_index = match client.get_note_by_cm(&witness.my.recv_commitment).await {
            Ok(idx) => idx,
            Err(_) => return Recovery::InProgress, // can't decide now; retry later
        };
        if leaf_index < 0 {
            return Recovery::Deleted; // never landed; blindings are stale
        }
        let my_pubkey = client.pubkey_hex().to_string();
        let sk_hex = hex::encode(note_sk_bytes(note_seed, &witness.my_order_id));
        let note = NoteRecord {
            cm: witness.my.recv_commitment.clone(),
            token: witness.my_recv_token.clone(),
            amount: witness.my.recv_amount,
            r: witness.my.r_recv.clone(),
            key_index: 0,
            sk: sk_hex,
            leaf_index: leaf_index as u64,
            status: 0, // NOTE_UNSPENT
            nf: String::new(),
        };
        let mut remainder_cash = Vec::new();
        if witness.my.new_order_amount > 0 {
            remainder_cash.push(CashRecord {
                cash_id: orderbook::compute_cash_id(
                    &my_pubkey,
                    &witness.my_lock_token,
                    &witness.my.new_locked_commitment,
                ),
                token: witness.my_lock_token.clone(),
                amount: witness.my.new_locked_amount,
                random: witness.my.r_locked_new.clone(),
                status: CASH_LOCKED,
                order_amount: Some(witness.my.new_order_amount),
                order_random: Some(witness.my.r_order_new.clone()),
            });
        }
        let _ = NOTE_PENDING_MINT; // status constants re-exported for callers
        Recovery::Landed(Recovered {
            spent_ids: witness.my_input_cash_ids,
            note,
            remainder_cash,
            dir: dir.to_path_buf(),
        })
    }
}

#[cfg(not(target_os = "android"))]
pub use inner::*;
