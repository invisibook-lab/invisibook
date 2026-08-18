//! Desktop settlement per the paper (§VI) on the note model, hardened per
//! the rev.4 plan (F1 + F2):
//!
//! The collaborative part — the MPC comparison, the smaller side's reveal,
//! the payout-note key exchange, and the collaborative PLONK π_cmp — runs
//! in the pre-built `settle2p_session` subprocess (a separate cargo
//! workspace pinned to an older toolchain, so it cannot be linked). This
//! module drives that subprocess over piped stdio in TWO phases:
//!
//! 1. Compare phase: ferry the one ed25519 compare signature, then — on
//!    the subprocess's `compare_ready` — submit `SubmitCompareCoZk2p`,
//!    block until BOTH orders are Settling on chain, and only then answer
//!    `compare_confirmed`. The subprocess reveals nothing before that
//!    anchor lands (the F1 ordering).
//! 2. Settle phase: on `result_ready`, prove THIS side's settle circuit
//!    (settle_small when fully filled, settle_large otherwise) with
//!    rapidsnark and hand the signed leg back; the subprocess exchanges
//!    legs over its still-open QUIC fabric and emits `pair_ready`, after
//!    which either party submits the ATOMIC `SettlePair` (the F2 fix —
//!    both payout notes mint together or nothing changes).
//!
//! NOTE: peer QUIC addresses are exchanged on-chain today; production would
//! use an anonymous overlay. The subprocess uses mock Beaver triples and a
//! dev SRS — testnet only.

#[cfg(not(target_os = "android"))]
mod inner {
    use std::{fmt, fs, path::PathBuf, process::Stdio, sync::Arc, time::Duration};

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        process::Command,
    };

    use invisibook_lib::{
        chain::{
            ChainClient, CompareParams, SettleLargeParams, SettlePairLegParams, SettlePairParams,
            SettleSmallParams, verify_compare_cozk2p_sig,
        },
        note::{
            asset_id, fr_from_be_bytes, note_fr_to_hex, npk_from_sk, settle_large_bind,
            settle_small_bind,
        },
        note_prover::{
            SettleLargeWitness, SettleSmallWitness, prove_settle_large, prove_settle_small,
        },
        note_store::{NOTE_PENDING_MINT, NoteRecord},
        order_store::OrderOpening,
        orderbook,
        types::*,
    };
    use zk::wallet::hex_to_fr;

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

    /// The surviving (larger) side's residual order opening after the chain
    /// relisted it in place: the fresh collateral opening that now opens
    /// the on-chain residual commitment (locked-only model: the residual
    /// quantity is plain wallet bookkeeping, not committed). Replaces the
    /// order's old `OrderOpening` in the wallet's order ledger.
    #[derive(Clone, Debug)]
    pub struct Remainder {
        pub order_amount: u64,
        pub locked_amount: u64,
        pub locked_random_hex: String,
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
        /// order opening whose blindings exist only locally).
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
    struct MyPrivateWire {
        order_amount: u64,
        r_locked: String,
    }

    #[derive(Serialize)]
    struct SessionInputWire {
        role: String,
        order_a_id: String,
        order_b_id: String,
        my_order_id: String,
        my_lock_token: String,
        my_recv_token: String,
        price: u64,
        a_is_seller: bool,
        locked_a: String,
        locked_b: String,
        my_recv_npk: String,
        my: MyPrivateWire,
    }

    #[derive(Deserialize)]
    struct NeedSigWire {
        cmp: i8,
    }

    /// Subset of the subprocess `SettlePublic` the app cross-checks; serde
    /// ignores the fields not named here. Locked-only model: the statement
    /// carries the two collateral commitments, the execution price, and the
    /// maker's side — all 5 signals except the proven `cmp` itself.
    #[derive(Deserialize)]
    struct PublicWire {
        locked_a: String,
        locked_b: String,
        price: u64,
        a_is_seller: bool,
    }

    /// The subprocess's `compare_ready` payload: π_cmp + both signatures,
    /// handed over BEFORE any reveal so the app can land the comparison on
    /// chain first (F1 ordering).
    #[derive(Deserialize)]
    struct CompareReadyWire {
        cmp: i8,
        public: PublicWire,
        proof_hex: String,
        sig_a: String,
        sig_b: String,
    }

    #[derive(Clone, Deserialize)]
    struct MyOutcomeWire {
        is_a: bool,
        i_am_smaller: bool,
        fill: u64,
        recv_amount: u64,
        recv_token: String,
        r_recv: String,
        recv_commitment: String,
        ctr_recv_npk: String,
        ctr_r_recv: String,
        ctr_order_amount: u64,
        ctr_r_locked: String,
        new_order_amount: u64,
        new_locked_amount: u64,
        r_locked_new: String,
        new_locked_commitment: String,
    }

    impl MyOutcomeWire {
        /// True when this side survived on the book as the larger leg, so
        /// the chain relisted its order under a fresh residual collateral
        /// commitment. The residual commitment is the ONE marker (it is what
        /// the relisted row carries on chain); the smaller side leaves it
        /// empty.
        fn is_relisted(&self) -> bool {
            !self.new_locked_commitment.is_empty()
        }
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

    /// One side's settle artifacts, exchanged through the subprocess so
    /// either party can submit the atomic SettlePair. Mirrors cozk2p's
    /// `SettleLeg` serde.
    #[derive(Clone, Serialize, Deserialize)]
    struct SettleLegWire {
        is_a: bool,
        cm_note_out: String,
        signature: String,
        zk_proof: String,
        #[serde(default)]
        cm_locked_residual: String,
    }

    /// Crash-recovery record the subprocess writes before any secret leaves
    /// it. Mirrors cozk2p's `SessionWitness`.
    #[derive(Deserialize)]
    struct SessionWitnessWire {
        my_order_id: String,
        my_lock_token: String,
        my_recv_token: String,
        my: MyOutcomeWire,
    }

    /// Token an order locks as collateral: Token1 for a sell, Token2 for a
    /// buy.
    pub fn lock_token(order: &Order) -> String {
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

    /// An order's single collateral commitment hex (`Order.LockedCommitment`
    /// — the order's ONLY commitment in the locked-only model). The
    /// commitment sits on the order row itself — no extra chain read.
    fn locked_hex(order: &Order) -> Result<String, SettleError> {
        if order.locked_commitment.len() != 64 {
            return Err(SettleError::Transient(format!(
                "order {} carries no collateral commitment (stale read?)",
                orderbook::short_id(&order.id)
            )));
        }
        Ok(order.locked_commitment.clone())
    }

    /// Run the full settlement for a matched pair: compare session, on-chain
    /// compare confirmation, this side's settle proof, leg exchange, and the
    /// atomic SettlePair submission. `opening` is this order's locally
    /// persisted (q, collateral) opening.
    pub async fn run_settle(
        client: &Arc<ChainClient>,
        my_order: &Order,
        counter_order: &Order,
        opening: &OrderOpening,
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

        // Chain-sourced public inputs (all already on the order rows).
        let locked_a = locked_hex(maker)?;
        let locked_b = locked_hex(taker)?;

        let my_lock_token = lock_token(my_order);
        let my_recv_token = recv_token(my_order);

        // Fresh per-trade note key: the payout note this wallet receives.
        let my_note_sk = note_sk_bytes(&deps.note_seed, &my_order.id);
        let my_recv_npk = note_fr_to_hex(&npk_from_sk(fr_from_be_bytes(&my_note_sk)));

        let input = SessionInputWire {
            role: role.to_string(),
            order_a_id: maker.id.clone(),
            order_b_id: taker.id.clone(),
            my_order_id: my_order.id.clone(),
            my_lock_token: my_lock_token.clone(),
            my_recv_token: my_recv_token.clone(),
            price,
            a_is_seller,
            locked_a: locked_a.clone(),
            locked_b: locked_b.clone(),
            my_recv_npk,
            my: MyPrivateWire {
                order_amount: opening.q,
                r_locked: opening.r_locked.clone(),
            },
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

        // ── Full two-phase session (subprocess) ──
        let session = SessionCtx {
            client,
            my_order,
            counter_order,
            maker_id: &maker.id,
            taker_id: &taker.id,
            maker_pubkey: &maker.pubkey,
            taker_pubkey: &taker.pubkey,
            expected_locked_a: &locked_a,
            expected_locked_b: &locked_b,
            price,
            a_is_seller,
            my_lock_token: &my_lock_token,
            opening,
            session_dir: &session_dir,
        };
        let output = run_prover_session(
            deps,
            role,
            &local_addr,
            &peer_addr,
            &input_path,
            &session,
            &mut progress,
        )
        .await?;

        // ── Atomic SettlePair: either party may land it (F2) ──
        progress("Submitting atomic settlement pair...");
        let pair = build_pair_params(&maker.id, &taker.id, &output.legs)?;
        if let Err(e) = client.settle_pair(&pair).await {
            let msg = e.to_string();
            // The counterparty may already have landed the pair; the real
            // verdict comes from the on-chain confirmation below.
            if !(msg.contains("is not Settling") || msg.contains("duplicated")) {
                progress(&format!("settle_pair submit warning: {msg}"));
            }
        }

        progress("Confirming settlement on chain...");
        let outcome = &output.res.my;
        confirm_on_chain(client, &my_order.id, &outcome.new_locked_commitment).await?;

        Ok(outcome_from_result(
            &deps.note_seed,
            &my_order.id,
            output.res.cmp,
            outcome,
            session_dir,
        ))
    }

    /// The prover subprocess's parsed products: the session result and the
    /// exchanged (A, B) settle legs.
    struct ProverOutput {
        res: SessionResultWire,
        legs: (SettleLegWire, SettleLegWire),
    }

    /// Chain-facing context the subprocess interaction needs (grouped to
    /// keep the function argument count sane).
    struct SessionCtx<'a> {
        client: &'a Arc<ChainClient>,
        my_order: &'a Order,
        counter_order: &'a Order,
        maker_id: &'a str,
        taker_id: &'a str,
        maker_pubkey: &'a str,
        taker_pubkey: &'a str,
        expected_locked_a: &'a str,
        expected_locked_b: &'a str,
        price: u64,
        /// Maker side read off the chain rows: order A (the maker) sells.
        a_is_seller: bool,
        my_lock_token: &'a str,
        opening: &'a OrderOpening,
        session_dir: &'a std::path::Path,
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

    /// Poll until `order_id` reaches Settling (the comparison landed —
    /// submitted by either party). `Done` counts too (fast counterparty).
    async fn wait_for_settling(client: &ChainClient, order_id: &str) -> Result<(), SettleError> {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match query_one(client, order_id).await {
                Some(order) if order.status == OrderStatus::Settling => return Ok(()),
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

    /// Cross-check a proven statement against the rows read from the chain:
    /// every non-`cmp` signal of the 5-signal statement (both collateral
    /// commitments, the execution price, the maker's side) must match, or
    /// the subprocess proved something other than THIS pair (a stale chain
    /// read, most likely). Cheap local guard — the chain re-verifies.
    fn check_public_statement(
        ctx: &SessionCtx<'_>,
        public: &PublicWire,
    ) -> Result<(), SettleError> {
        if public.locked_a != ctx.expected_locked_a
            || public.locked_b != ctx.expected_locked_b
            || public.price != ctx.price
            || public.a_is_seller != ctx.a_is_seller
        {
            return Err(SettleError::Transient(
                "prover statement does not match the on-chain order rows".into(),
            ));
        }
        Ok(())
    }

    /// Handle the subprocess's `compare_ready`: cross-check the proven
    /// statement and signatures, submit the comparison, and block until
    /// BOTH orders are Settling. Only a `true` reply lets the subprocess
    /// reveal (the F1 gate).
    async fn confirm_compare(
        ctx: &SessionCtx<'_>,
        ready: &CompareReadyWire,
        progress: &mut impl FnMut(&str),
    ) -> Result<(), SettleError> {
        check_public_statement(ctx, &ready.public)?;
        let params = CompareParams {
            order_a_id: ctx.maker_id.to_string(),
            order_b_id: ctx.taker_id.to_string(),
            cmp: ready.cmp,
            sig_a: ready.sig_a.clone(),
            sig_b: ready.sig_b.clone(),
            zk_proof: ready.proof_hex.clone(),
        };
        if !verify_compare_cozk2p_sig(&params, ctx.maker_pubkey, &ready.sig_a)
            || !verify_compare_cozk2p_sig(&params, ctx.taker_pubkey, &ready.sig_b)
        {
            return Err(SettleError::Transient(
                "compare signatures failed local verification".into(),
            ));
        }

        progress("Submitting comparison...");
        if let Err(e) = ctx.client.submit_compare_cozk2p(&params).await {
            let msg = e.to_string();
            // The counterparty may have submitted first; the Settling wait
            // below is the real verdict.
            if !(msg.contains("not Matched") || msg.contains("duplicated")) {
                progress(&format!("compare submit warning: {msg}"));
            }
        }
        progress("Waiting for the comparison to land on chain...");
        wait_for_settling(ctx.client, &ctx.my_order.id).await?;
        wait_for_settling(ctx.client, &ctx.counter_order.id).await?;
        Ok(())
    }

    /// Prove THIS side's settle circuit from the session outcome and wrap
    /// it as a signed SettlePair leg.
    fn prove_my_leg(
        ctx: &SessionCtx<'_>,
        outcome: &MyOutcomeWire,
    ) -> Result<SettleLegWire, SettleError> {
        let hex_fr = |s: &str, what: &str| {
            hex_to_fr(s).map_err(|e| SettleError::Transient(format!("{what}: {e}")))
        };
        let my_side_sell = ctx.my_order.trade_type == TradeType::Sell;
        let pay_asset = asset_id(ctx.my_lock_token)
            .map_err(|e| SettleError::Unrecoverable(format!("pay asset: {e}")))?;
        let npk_ctr = hex_fr(&outcome.ctr_recv_npk, "ctr_recv_npk")?;
        let r_note = hex_fr(&outcome.ctr_r_recv, "ctr_r_recv")?;
        let q = ctx.opening.q;
        let r_locked = hex_fr(&ctx.opening.r_locked, "r_locked")?;

        if outcome.i_am_smaller {
            let setup =
                tokio::task::block_in_place(|| zk::setup::dev_setup_snarkjs("settle_small"))
                    .map_err(|e| SettleError::Transient(format!("settle_small setup: {e}")))?;
            let handle = zk::test_circuit::TestCircuitHandle::from_compiled(&setup.circuit_dir)
                .map_err(|e| SettleError::Transient(format!("circuit handle: {e}")))?;
            let mut w = SettleSmallWitness {
                q,
                r_locked,
                price: ctx.price,
                side_sell: my_side_sell,
                pay_asset,
                npk_ctr,
                r_note,
                bind: fr_from_be_bytes(&[0u8; 32]),
            };
            let cm_note_out = note_fr_to_hex(&w.cm_note_out());
            w.bind = settle_small_bind(
                ctx.client.chain_id(),
                &ctx.my_order.id,
                &ctx.counter_order.id,
                &cm_note_out,
            );
            let proof = tokio::task::block_in_place(|| prove_settle_small(w, &handle, &setup.zkey))
                .map_err(|e| SettleError::Transient(format!("prove settle_small: {e}")))?;

            let mut params = SettleSmallParams {
                order_id: ctx.my_order.id.clone(),
                match_order_id: ctx.counter_order.id.clone(),
                cm_note_out: proof.cm_note_out_hex.clone(),
                signature: String::new(),
                zk_proof: serde_json::to_string(&proof.proof_json)
                    .map_err(|e| SettleError::Transient(format!("proof json: {e}")))?,
            };
            params.signature = ctx.client.sign_settle_small(&params);
            Ok(SettleLegWire {
                is_a: outcome.is_a,
                cm_note_out: params.cm_note_out,
                signature: params.signature,
                zk_proof: params.zk_proof,
                cm_locked_residual: String::new(),
            })
        } else {
            let setup =
                tokio::task::block_in_place(|| zk::setup::dev_setup_snarkjs("settle_large"))
                    .map_err(|e| SettleError::Transient(format!("settle_large setup: {e}")))?;
            let handle = zk::test_circuit::TestCircuitHandle::from_compiled(&setup.circuit_dir)
                .map_err(|e| SettleError::Transient(format!("circuit handle: {e}")))?;
            let mut w = SettleLargeWitness {
                q,
                r_locked,
                q_ctr: outcome.ctr_order_amount,
                r_locked_ctr: hex_fr(&outcome.ctr_r_locked, "ctr_r_locked")?,
                price: ctx.price,
                side_sell: my_side_sell,
                r_locked_residual: hex_fr(&outcome.r_locked_new, "r_locked_new")?,
                pay_asset,
                npk_ctr,
                r_note,
                bind: fr_from_be_bytes(&[0u8; 32]),
            };
            let (cm_locked_res, cm_note) = w.output_cms();
            w.bind = settle_large_bind(
                ctx.client.chain_id(),
                &ctx.my_order.id,
                &ctx.counter_order.id,
                &note_fr_to_hex(&cm_locked_res),
                &note_fr_to_hex(&cm_note),
            );
            let proof = tokio::task::block_in_place(|| prove_settle_large(w, &handle, &setup.zkey))
                .map_err(|e| SettleError::Transient(format!("prove settle_large: {e}")))?;

            let mut params = SettleLargeParams {
                order_id: ctx.my_order.id.clone(),
                match_order_id: ctx.counter_order.id.clone(),
                cm_locked_residual: proof.cm_locked_residual_hex.clone(),
                cm_note_out: proof.cm_note_out_hex.clone(),
                signature: String::new(),
                zk_proof: serde_json::to_string(&proof.proof_json)
                    .map_err(|e| SettleError::Transient(format!("proof json: {e}")))?,
            };
            params.signature = ctx.client.sign_settle_large(&params);
            Ok(SettleLegWire {
                is_a: outcome.is_a,
                cm_note_out: params.cm_note_out,
                signature: params.signature,
                zk_proof: params.zk_proof,
                cm_locked_residual: params.cm_locked_residual,
            })
        }
    }

    /// Build the atomic SettlePair request from the exchanged (A, B) legs.
    fn build_pair_params(
        maker_id: &str,
        taker_id: &str,
        legs: &(SettleLegWire, SettleLegWire),
    ) -> Result<SettlePairParams, SettleError> {
        let to_leg = |leg: &SettleLegWire| {
            if leg.cm_locked_residual.is_empty() {
                SettlePairLegParams::small(
                    leg.cm_note_out.clone(),
                    leg.signature.clone(),
                    leg.zk_proof.clone(),
                )
            } else {
                SettlePairLegParams::large(
                    leg.cm_note_out.clone(),
                    leg.cm_locked_residual.clone(),
                    leg.signature.clone(),
                    leg.zk_proof.clone(),
                )
            }
        };
        if !legs.0.is_a || legs.1.is_a {
            return Err(SettleError::Transient(
                "exchanged settle legs carry inconsistent roles".into(),
            ));
        }
        Ok(SettlePairParams {
            order_a_id: maker_id.to_string(),
            order_b_id: taker_id.to_string(),
            a: to_leg(&legs.0),
            b: to_leg(&legs.1),
        })
    }

    /// Spawn `settle2p_session` and drive its full stdio protocol:
    /// `need_sig` → sign; `compare_ready` → submit + confirm on chain
    /// (F1 gate); `result_ready` → prove this side's leg; `pair_ready` →
    /// capture both legs. Bounded by a 15-minute watchdog; the child is
    /// killed if this future is dropped.
    async fn run_prover_session(
        deps: &SettleDeps,
        role: &str,
        local_addr: &str,
        peer_addr: &str,
        input_path: &std::path::Path,
        ctx: &SessionCtx<'_>,
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
            .arg(ctx.session_dir)
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

        let mut legs: Option<(SettleLegWire, SettleLegWire)> = None;

        let interaction = async {
            // Reply one JSON line on the child's stdin.
            async fn reply(
                stdin: &mut tokio::process::ChildStdin,
                line: String,
            ) -> Result<(), SettleError> {
                stdin
                    .write_all(line.as_bytes())
                    .await
                    .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))?;
                stdin
                    .write_all(b"\n")
                    .await
                    .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))?;
                stdin
                    .flush()
                    .await
                    .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))
            }

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
                            order_a_id: ctx.maker_id.to_string(),
                            order_b_id: ctx.taker_id.to_string(),
                            cmp: ns.cmp,
                            sig_a: String::new(),
                            sig_b: String::new(),
                            zk_proof: String::new(),
                        };
                        let sig = ctx.client.sign_compare_cozk2p(&params);
                        reply(&mut stdin, format!("{{\"sig\":\"{sig}\"}}")).await?;
                    }
                    Some("compare_ready") => {
                        let ready: CompareReadyWire =
                            serde_json::from_value(value.get("ready").cloned().unwrap_or_default())
                                .map_err(|e| {
                                    SettleError::Transient(format!("bad compare_ready: {e}"))
                                })?;
                        match confirm_compare(ctx, &ready, progress).await {
                            Ok(()) => {
                                reply(&mut stdin, "{\"compare_confirmed\":true}".into()).await?;
                            }
                            Err(e) => {
                                // A false reply makes the subprocess abort
                                // BEFORE any reveal (F1: nothing leaked).
                                let _ =
                                    reply(&mut stdin, "{\"compare_confirmed\":false}".into()).await;
                                return Err(e);
                            }
                        }
                    }
                    Some("result_ready") => {
                        // result.json is on disk while the child still
                        // holds the QUIC connection for the leg exchange.
                        let result_bytes =
                            fs::read(ctx.session_dir.join("result.json")).map_err(|e| {
                                SettleError::Transient(format!("reading prover result: {e}"))
                            })?;
                        let res: SessionResultWire = serde_json::from_slice(&result_bytes)
                            .map_err(|e| {
                                SettleError::Transient(format!("parsing prover result: {e}"))
                            })?;
                        progress("Proving this side's settlement...");
                        let leg = prove_my_leg(ctx, &res.my)?;
                        let leg_line = serde_json::to_string(&serde_json::json!({
                            "settle_leg": leg
                        }))
                        .expect("leg serializes");
                        reply(&mut stdin, leg_line).await?;
                    }
                    Some("pair_ready") => {
                        let leg_a: SettleLegWire =
                            serde_json::from_value(value.get("a").cloned().unwrap_or_default())
                                .map_err(|e| {
                                    SettleError::Transient(format!("bad pair_ready leg a: {e}"))
                                })?;
                        let leg_b: SettleLegWire =
                            serde_json::from_value(value.get("b").cloned().unwrap_or_default())
                                .map_err(|e| {
                                    SettleError::Transient(format!("bad pair_ready leg b: {e}"))
                                })?;
                        legs = Some((leg_a, leg_b));
                    }
                    Some("done") => break,
                    _ => {}
                }
            }
            Ok::<(), SettleError>(())
        };

        // 15-minute watchdog over the whole interaction (the settle-leg
        // round adds two rapidsnark proves on top of the old budget).
        match tokio::time::timeout(Duration::from_secs(900), interaction).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.start_kill();
                return Err(e);
            }
            Err(_) => {
                let _ = child.start_kill();
                return Err(SettleError::Transient(
                    "prover timed out after 15 minutes".into(),
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

        let legs = legs.ok_or_else(|| {
            SettleError::Transient("prover exited without exchanging settle legs".into())
        })?;
        let result_bytes = fs::read(ctx.session_dir.join("result.json"))
            .map_err(|e| SettleError::Transient(format!("reading prover result: {e}")))?;
        let res: SessionResultWire = serde_json::from_slice(&result_bytes)
            .map_err(|e| SettleError::Transient(format!("parsing prover result: {e}")))?;
        // Redundant with confirm_compare, but result.json is re-read here:
        // keep the invariant local.
        check_public_statement(ctx, &res.public)?;
        let _ = (&res.proof_hex, &res.sig_a, &res.sig_b); // consumed in compare phase
        Ok(ProverOutput { res, legs })
    }

    /// Poll until this trader's order is `Done` or has been relisted with
    /// its new residual collateral commitment. Timing out while the pair is
    /// still mutually matched means the writing was rejected.
    async fn confirm_on_chain(
        client: &ChainClient,
        my_order_id: &str,
        my_new_locked_commitment: &str,
    ) -> Result<(), SettleError> {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Some(order) = query_one(client, my_order_id).await {
                if order.status == OrderStatus::Done
                    || (!my_new_locked_commitment.is_empty()
                        && order.locked_commitment == *my_new_locked_commitment)
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
        let remainder = if my.is_relisted() {
            Some(Remainder {
                order_amount: my.new_order_amount,
                locked_amount: my.new_locked_amount,
                locked_random_hex: my.r_locked_new.clone(),
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
        /// The order this session settled (keys the order-opening ledger).
        pub order_id: String,
        /// The incoming payout note to materialize (with leaf index).
        pub note: NoteRecord,
        /// The residual order opening, when this side survived on the book;
        /// `None` means the order fully filled (drop its opening).
        pub remainder: Option<OrderOpening>,
        pub dir: PathBuf,
    }

    /// Inspect every session dir and decide, per the recovery rules below,
    /// whether it LANDED (materialize its records), is provably DEAD
    /// (delete it), is CORRUPT (quarantine for diagnosis), or must be KEPT.
    /// Session dirs whose settlement has not yet finished (no witness.json)
    /// and quarantined `.corrupt` dirs are left untouched.
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
            if dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".corrupt"))
            {
                continue; // already quarantined for diagnosis
            }
            match try_recover_session(client, note_seed, &dir).await {
                Recovery::Landed(rec) => out.push(rec),
                Recovery::Deleted => {
                    let _ = fs::remove_dir_all(&dir);
                }
                Recovery::Corrupt => {
                    quarantine_session_dir(&dir);
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
        /// PROVABLY dead (the on-chain order state rules the settlement
        /// out) — the dir is stale and should be removed.
        Deleted,
        /// The witness cannot be parsed — keep it, but move it aside so it
        /// stays diagnosable and does not block future scans.
        Corrupt,
        /// Anything not decidable yet (no witness, chain unreachable, note
        /// not on chain but the pair can still settle) — leave it alone.
        InProgress,
    }

    /// Move a session dir with an unreadable witness to `<dir>.corrupt`.
    /// The money-critical secrets stay on disk for manual diagnosis; a
    /// stale quarantine from an earlier run is replaced.
    fn quarantine_session_dir(dir: &std::path::Path) {
        let mut target = dir.as_os_str().to_owned();
        target.push(".corrupt");
        let target = std::path::PathBuf::from(target);
        let _ = fs::remove_dir_all(&target);
        if let Err(e) = fs::rename(dir, &target) {
            eprintln!("[settle] quarantining corrupt session {dir:?}: {e}");
        }
    }

    /// The pure recovery decision for a witness whose payout note is NOT
    /// in the pool tree yet.
    ///
    /// The peer may hold both settle legs and submit the SettlePair at any
    /// time while the pair is still Matched/Settling on chain, so the
    /// witness (which holds the ONLY copy of the payout-note blinding) must
    /// be kept in every uncertain state. Deleting is allowed only when the
    /// on-chain order state PROVES this settlement can never land: the
    /// order left Matched/Settling (Done, relisted Pending, Cancelled, or
    /// Frozen) without minting this witness's note — the pair can never be
    /// Settling again, so the note can never mint.
    fn undecided_witness_action(my_status: Option<OrderStatus>) -> Recovery {
        match my_status {
            // Chain unreachable / order unknown: keep — never destroy the
            // only copy of a blinding on uncertainty.
            None => Recovery::InProgress,
            Some(OrderStatus::Matched) | Some(OrderStatus::Settling) => Recovery::InProgress,
            Some(_) => Recovery::Deleted,
        }
    }

    /// Recovery predicate for one session dir: read `witness.json`, ask the
    /// chain whether this side's payout note commitment is in the pool
    /// tree, and — when it is not — decide from the order state whether the
    /// settlement can still land. The note's spending secret is re-derived
    /// from the wallet seed and the order id.
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
            // Unreadable witness: quarantine, never delete (it may still
            // hold the only copy of a payout blinding).
            Err(_) => return Recovery::Corrupt,
        };
        let leaf_index = match client.get_note_by_cm(&witness.my.recv_commitment).await {
            Ok(idx) => idx,
            Err(_) => return Recovery::InProgress, // can't decide now; retry later
        };
        if leaf_index < 0 {
            // Note not on chain (yet): the peer may still submit the
            // SettlePair. Only a provably dead order state allows cleanup.
            let my_status = query_one(client, &witness.my_order_id)
                .await
                .map(|o| o.status);
            return undecided_witness_action(my_status);
        }
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
            pending_order: String::new(),
        };
        // Rebuild the residual order opening from the witness, using the
        // same relist predicate the live path uses.
        let remainder = if witness.my.is_relisted() {
            Some(OrderOpening {
                order_id: witness.my_order_id.clone(),
                q: witness.my.new_order_amount,
                locked_amount: witness.my.new_locked_amount,
                r_locked: witness.my.r_locked_new.clone(),
                lock_token: witness.my_lock_token.clone(),
            })
        } else {
            None
        };
        let _ = NOTE_PENDING_MINT; // status constants re-exported for callers
        Recovery::Landed(Recovered {
            order_id: witness.my_order_id.clone(),
            note,
            remainder,
            dir: dir.to_path_buf(),
        })
    }

    #[cfg(test)]
    mod recovery_tests {
        use super::*;

        /// P1-6 regression: while the payout note is absent, every
        /// uncertain state KEEPS the witness — the peer may still submit
        /// the exchanged SettlePair later. Only a provably dead order
        /// state deletes.
        #[test]
        fn witness_kept_while_settlement_can_still_land() {
            // Chain unreachable / order unknown → keep.
            assert!(matches!(
                undecided_witness_action(None),
                Recovery::InProgress
            ));
            // The pair can still settle → keep.
            assert!(matches!(
                undecided_witness_action(Some(OrderStatus::Settling)),
                Recovery::InProgress
            ));
            assert!(matches!(
                undecided_witness_action(Some(OrderStatus::Matched)),
                Recovery::InProgress
            ));
        }

        /// Deletion needs PROOF: the order left the settling states without
        /// this witness's note — that settlement can never land anymore.
        #[test]
        fn witness_deleted_only_when_provably_dead() {
            for status in [
                OrderStatus::Pending, // relisted via a different settlement
                OrderStatus::Done,    // settled via a different leg set
                OrderStatus::Cancelled,
                OrderStatus::Frozen,
            ] {
                assert!(
                    matches!(undecided_witness_action(Some(status)), Recovery::Deleted),
                    "{status} must allow cleanup"
                );
            }
        }

        /// A corrupt witness is quarantined (renamed), never deleted: the
        /// bytes stay on disk for diagnosis.
        #[test]
        fn corrupt_witness_is_quarantined_not_deleted() {
            let base =
                std::env::temp_dir().join(format!("settle_corrupt_test_{}", std::process::id()));
            let dir = base.join("session-1");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("witness.json"), b"{not json").unwrap();

            quarantine_session_dir(&dir);

            let quarantined = base.join("session-1.corrupt");
            assert!(!dir.exists(), "original dir must be moved");
            assert!(
                quarantined.join("witness.json").exists(),
                "witness bytes must survive quarantine"
            );
            let _ = fs::remove_dir_all(&base);
        }
    }
}

#[cfg(not(target_os = "android"))]
pub use inner::*;
