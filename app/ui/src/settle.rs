//! Desktop settlement per the paper (§VI) on the note model, hardened per
//! the rev.4 plan (F1 + F2):
//!
//! The collaborative part — the MPC comparison, collaborative PLONK π_cmp,
//! pre-reveal payout-note key exchange/WAL, and smaller-side reveal — runs
//! in the pre-built `settle2p_session` subprocess (a separate cargo
//! workspace pinned to an older toolchain, so it cannot be linked). This
//! module drives that subprocess over piped stdio in TWO phases:
//!
//! 1. Compare phase: ferry the ed25519 comparison signature, then — on
//!    `compare_ready` — submit this owner's proof share. The chain only
//!    reconstructs and verifies π_cmp after both identity-bound shares land;
//!    only then does the host answer `compare_confirmed`, so the smaller
//!    opening is not revealed before on-chain verification.
//! 2. Settle phase: on `result_ready`, prove THIS side's settle circuit
//!    (settle_small when fully filled, settle_large otherwise) with
//!    rapidsnark and immediately submit this owner's signed leg. The
//!    settlement-leg window was already created when π_cmp verified;
//!    settlement remains atomic and runs only when both owners' legs verify.
//!    At expiry, only a non-equal round with a lone large-side leg freezes the
//!    missing small owner; zero-leg, only-small, and incomplete equal rounds
//!    release both without blame. A small-side leg alone is not delivery
//!    evidence. Payout-key WAL entries are not yet owner-signed/on-chain or
//!    publicly bound by the settle circuits, so the overall client model is
//!    compliant-until-fail-stop rather than Byzantine-safe.
//!
//! NOTE: peer QUIC addresses are exchanged on-chain today; production would
//! use an anonymous overlay. The subprocess uses mock Beaver triples and a
//! dev SRS — testnet only.

#[cfg(not(target_os = "android"))]
mod inner {
    /// The comparison-share deadline is derived from this round's
    /// `MatchHeight`, so
    /// both owners can sign the same absolute height without a checkpoint or
    /// a first-uploader-selected window.
    const COMPARE_SHARE_TIMEOUT_BLOCKS: u64 = 10;

    /// Keep a stalled RPC/chain from occupying the serial settlement worker
    /// forever. Durable chain rows and the session WAL make a later retry safe.
    const CHAIN_TERMINAL_WAIT_TIMEOUT_SECS: u64 = 300;
    const CHAIN_RPC_TIMEOUT_SECS: u64 = 20;
    const RENDEZVOUS_TIMEOUT_SECS: u64 = 90;

    use std::{
        collections::HashSet,
        fmt, fs,
        path::PathBuf,
        process::Stdio,
        sync::Arc,
        time::{Duration, Instant},
    };

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        process::Command,
    };

    use invisibook_lib::{
        chain::{
            ChainClient, CompareParams, CompareShareParams, SettleLargeParams, SettleLegProgress,
            SettlePairLegParams, SettleSmallParams, SubmitSettleLegParams,
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
        pub refund: Option<NewNote>,
        /// Present only when this side survived on the book (had a
        /// remainder); the chain relisted the order in place.
        pub remainder: Option<Remainder>,
        /// Session scratch dir; the caller deletes it after persisting.
        pub session_dir: PathBuf,
        /// Non-overlapping wall-clock intervals for this trader's settlement
        /// driver. These boundaries follow the protocol, rather than the
        /// subprocess lifetime, so experiments can report comparison and
        /// final settlement without mixing them.
        pub timings: SettlePhaseTimings,
    }

    /// One trader's semantic settlement phases. Their sum is `total_ms`:
    /// rendezvous ends immediately before the comparison subprocess starts;
    /// comparison ends only after both proof shares reconstruct and verify
    /// on chain; final settlement then runs through proof generation, the
    /// owner's leg submission, and atomic confirmation.
    #[derive(Clone, Debug, Default)]
    pub struct SettlePhaseTimings {
        pub rendezvous_ms: f64,
        pub comparison_ms: f64,
        pub final_settlement_ms: f64,
        pub settlement_proof_ms: f64,
        pub total_ms: f64,
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
                SettleError::CrossPrice(m) => write!(f, "invalid matched prices: {m}"),
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

    fn refund_note_sk_bytes(seed: &[u8; 32], order_id: &str) -> [u8; 32] {
        note_sk_bytes(seed, &format!("{order_id}:refund"))
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
        price_a: u64,
        price_b: u64,
        execution_price: u64,
        a_is_seller: bool,
        locked_a: String,
        locked_b: String,
        my_recv_npk: String,
        my_refund_npk: String,
        transport_secret: String,
        peer_transport_pubkey: String,
        my: MyPrivateWire,
    }

    #[derive(Deserialize)]
    struct NeedSigWire {
        cmp: i8,
    }

    /// Subset of the subprocess `SettlePublic` the app cross-checks; serde
    /// ignores the fields not named here. Locked-only model: the statement
    /// carries both collateral commitments, both public collateral prices,
    /// and the maker's side.
    #[derive(Deserialize)]
    struct PublicWire {
        locked_a: String,
        locked_b: String,
        price_a: u64,
        price_b: u64,
        a_is_seller: bool,
    }

    /// The subprocess's `compare_ready` payload: this party's native
    /// collaborative-proof share plus both comparison signatures. It is
    /// handed over BEFORE any reveal so the app can land its own share on
    /// chain first (F1 ordering).
    #[derive(Deserialize)]
    struct CompareReadyWire {
        cmp: i8,
        public: PublicWire,
        proof_share_hex: String,
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
        refund_amount: u64,
        refund_token: String,
        refund_npk: String,
        r_refund: String,
        refund_commitment: String,
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
        proof_share_hex: String,
        sig_a: String,
        sig_b: String,
        my: MyOutcomeWire,
    }

    /// One side's settlement proof and signed public outputs.
    #[derive(Clone, Serialize, Deserialize)]
    struct SettleLegWire {
        is_a: bool,
        cm_note_out: String,
        cm_refund_out: String,
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

    fn collateral_price(order: &Order) -> Result<u64, SettleError> {
        match order.kind {
            OrderKind::Limit => order.price,
            OrderKind::Market => order.protection_price,
        }
        .filter(|price| *price > 0)
        .ok_or_else(|| {
            SettleError::CrossPrice(format!(
                "order {} is missing its public collateral price",
                orderbook::short_id(&order.id)
            ))
        })
    }

    /// Run the full settlement for a matched pair: compare session, on-chain
    /// compare confirmation, this side's proof submission, and atomic
    /// settlement. `opening` is this order's locally
    /// persisted (q, collateral) opening.
    pub async fn run_settle(
        client: &Arc<ChainClient>,
        my_order: &Order,
        counter_order: &Order,
        opening: &OrderOpening,
        deps: &SettleDeps,
        mut progress: impl FnMut(&str),
    ) -> Result<SettleOutcome, SettleError> {
        let run_started_at = Instant::now();
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
        let comparison_deadline =
            maker.match_height.max(taker.match_height) + COMPARE_SHARE_TIMEOUT_BLOCKS;

        let price_a = collateral_price(maker)?;
        let price_b = collateral_price(taker)?;
        let execution_price = maker
            .execution_price
            .filter(|price| *price > 0 && Some(*price) == taker.execution_price)
            .ok_or_else(|| {
                SettleError::CrossPrice("orders disagree on the execution price".into())
            })?;
        let a_is_seller = maker.trade_type == TradeType::Sell;

        // Chain-sourced public inputs (all already on the order rows).
        let locked_a = locked_hex(maker)?;
        let locked_b = locked_hex(taker)?;

        let my_lock_token = lock_token(my_order);
        let my_recv_token = recv_token(my_order);

        // Fresh per-trade note key: the payout note this wallet receives.
        let my_note_sk = note_sk_bytes(&deps.note_seed, &my_order.id);
        let my_recv_npk = note_fr_to_hex(&npk_from_sk(fr_from_be_bytes(&my_note_sk)));
        let my_refund_sk = refund_note_sk_bytes(&deps.note_seed, &my_order.id);
        let my_refund_npk = note_fr_to_hex(&npk_from_sk(fr_from_be_bytes(&my_refund_sk)));

        use x25519_dalek::{PublicKey, StaticSecret};
        let mut transport_kdf = Sha256::new();
        transport_kdf.update(b"invisibook-settle-transport-v1");
        transport_kdf.update(deps.note_seed);
        transport_kdf.update(my_order.id.as_bytes());
        transport_kdf.update(my_order.match_round.to_be_bytes());
        let transport_secret_bytes: [u8; 32] = transport_kdf.finalize().into();
        let transport_secret = StaticSecret::from(transport_secret_bytes);
        let transport_pubkey = PublicKey::from(&transport_secret);

        // ── Rendezvous: exchange QUIC addresses on chain ──
        progress("Registering settlement address...");
        let base = bind_ephemeral_port().await?;
        let local_addr = format!("127.0.0.1:{base}");
        let register_error = match tokio::time::timeout(
            Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
            client.register_settle_addr(
                my_order.id.clone(),
                counter_order.id.clone(),
                my_order.match_round,
                &local_addr,
                &hex::encode(transport_pubkey.as_bytes()),
            ),
        )
        .await
        {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(SettleError::Transient(format!("register_settle_addr: {e}"))),
            Err(_) => Some(SettleError::Transient(
                "register_settle_addr timed out".into(),
            )),
        };
        if let Some(cause) = register_error {
            return Err(close_failed_pre_reveal_round(
                client,
                &maker.id,
                &taker.id,
                &my_order.id,
                my_order.match_round,
                comparison_deadline,
                cause,
                &mut progress,
            )
            .await);
        }

        progress("Waiting for counterparty...");
        let peer = match poll_peer_addr(
            client,
            &my_order.id,
            &counter_order.id,
            my_order.match_round,
        )
        .await
        {
            Ok(peer) => peer,
            Err(cause) => {
                return Err(close_failed_pre_reveal_round(
                    client,
                    &maker.id,
                    &taker.id,
                    &my_order.id,
                    my_order.match_round,
                    comparison_deadline,
                    cause,
                    &mut progress,
                )
                .await);
            }
        };

        let input = SessionInputWire {
            role: role.to_string(),
            order_a_id: maker.id.clone(),
            order_b_id: taker.id.clone(),
            my_order_id: my_order.id.clone(),
            my_lock_token: my_lock_token.clone(),
            my_recv_token: my_recv_token.clone(),
            price_a,
            price_b,
            execution_price,
            a_is_seller,
            locked_a: locked_a.clone(),
            locked_b: locked_b.clone(),
            my_recv_npk,
            my_refund_npk,
            transport_secret: hex::encode(transport_secret.to_bytes()),
            peer_transport_pubkey: peer.encryption_pubkey.clone(),
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
            price_a,
            price_b,
            execution_price,
            a_is_seller,
            my_lock_token: &my_lock_token,
            opening,
            session_dir: &session_dir,
        };
        let comparison_started_at = Instant::now();
        let rendezvous_ms = comparison_started_at
            .duration_since(run_started_at)
            .as_secs_f64()
            * 1e3;
        let output = match run_prover_session(
            deps,
            role,
            &local_addr,
            &peer.addr,
            &input_path,
            &session,
            &mut progress,
        )
        .await
        {
            Ok(output) => output,
            Err(session_err) => {
                // Comparison may already be verified even though the peer
                // aborted before reveal/result_ready. The chain opens a
                // zero-leg deadline together with Settling; after it elapses
                // either owner can release both orders without blame. A lone
                // large-side leg is punitive only when cmp != 0 because that
                // proof requires the small opening; a lone small-side leg is
                // non-punitive because it does not prove reveal delivery.
                if matches!(
                    query_one(client, &my_order.id).await,
                    Some(order) if order.status == OrderStatus::Settling
                ) {
                    progress("Settlement peer stopped; waiting for the chain deadline...");
                    let terminal = wait_for_settlement_terminal(
                        client,
                        &maker.id,
                        &taker.id,
                        &my_order.id,
                        my_order.match_round,
                        true,
                        &mut progress,
                    )
                    .await?;
                    if terminal.complete {
                        return Err(SettleError::Transient(format!(
                            "{session_err}; settlement completed on chain and will be recovered from the session WAL"
                        )));
                    }
                    let submitted = terminal.my_submitted || terminal.peer_submitted;
                    return Err(if !terminal.missing_order_id.is_empty() {
                        SettleError::OnChainRejected(format!(
                            "settlement proof deadline elapsed; missing owner {} was recorded on chain",
                            terminal.missing_order_id
                        ))
                    } else if submitted {
                        SettleError::OnChainRejected(
                            "settlement deadline elapsed with one proof but no objective reveal-delivery evidence; both orders were released without blame"
                                .into(),
                        )
                    } else {
                        SettleError::OnChainRejected(
                            "peer stopped before reveal completion; both orders were released without penalty"
                                .into(),
                            )
                    });
                }
                return Err(close_failed_pre_reveal_round(
                    client,
                    &maker.id,
                    &taker.id,
                    &my_order.id,
                    my_order.match_round,
                    comparison_deadline,
                    session_err,
                    &mut progress,
                )
                .await);
            }
        };

        progress("Confirming settlement on chain...");
        let outcome = &output.res.my;
        let terminal = wait_for_settlement_terminal(
            client,
            &maker.id,
            &taker.id,
            &my_order.id,
            my_order.match_round,
            false,
            &mut progress,
        )
        .await?;
        if !terminal.complete {
            let submitted = terminal.my_submitted || terminal.peer_submitted;
            return Err(if !terminal.missing_order_id.is_empty() {
                SettleError::OnChainRejected(format!(
                    "settlement proof deadline elapsed; missing owner {} was recorded on chain",
                    terminal.missing_order_id
                ))
            } else if submitted {
                SettleError::OnChainRejected(
                    "settlement deadline elapsed with one proof but no objective reveal-delivery evidence; both orders were released without blame"
                        .into(),
                )
            } else {
                SettleError::OnChainRejected(
                    "settlement deadline elapsed before either owner submitted a proof; both orders were released"
                        .into(),
                )
            });
        }

        let timings = SettlePhaseTimings {
            rendezvous_ms,
            comparison_ms: output
                .comparison_confirmed_at
                .duration_since(comparison_started_at)
                .as_secs_f64()
                * 1e3,
            final_settlement_ms: output.comparison_confirmed_at.elapsed().as_secs_f64() * 1e3,
            settlement_proof_ms: output.settlement_proof_ms,
            total_ms: run_started_at.elapsed().as_secs_f64() * 1e3,
        };

        Ok(outcome_from_result(
            &deps.note_seed,
            &my_order.id,
            output.res.cmp,
            outcome,
            session_dir,
            timings,
        ))
    }

    /// The prover subprocess's parsed products.
    struct ProverOutput {
        res: SessionResultWire,
        comparison_confirmed_at: Instant,
        settlement_proof_ms: f64,
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
        price_a: u64,
        price_b: u64,
        execution_price: u64,
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
        match_round: u64,
    ) -> Result<invisibook_lib::chain::SettlePeer, SettleError> {
        let poll = async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                match tokio::time::timeout(
                    Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
                    client.query_settle_addr(
                        my_order_id.to_string(),
                        counter_id.to_string(),
                        match_round,
                    ),
                )
                .await
                {
                    Ok(Ok(Some(addr))) => return addr,
                    Ok(Ok(None)) => continue,
                    Ok(Err(e)) => eprintln!("[settle] query_settle_addr: {e}"),
                    Err(_) => eprintln!("[settle] query_settle_addr timed out"),
                }
            }
        };
        match tokio::time::timeout(Duration::from_secs(RENDEZVOUS_TIMEOUT_SECS), poll).await {
            Ok(addr) => Ok(addr),
            Err(_) => Err(SettleError::Transient(
                "timed out waiting for the counterparty to register".into(),
            )),
        }
    }

    async fn query_one(client: &ChainClient, order_id: &str) -> Option<Order> {
        match tokio::time::timeout(
            Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
            client.query_orders(
                Some(order_id.to_string()),
                None,
                None,
                None,
                None,
                Some(1),
                Some(0),
            ),
        )
        .await
        {
            Ok(Ok(orders)) => orders.into_iter().find(|o| o.id == order_id),
            Ok(Err(e)) => {
                eprintln!("[settle] query order {order_id}: {e}");
                None
            }
            Err(_) => {
                eprintln!("[settle] query order {order_id} timed out");
                None
            }
        }
    }

    enum ComparisonRoundTerminal {
        Verified,
        Expired,
    }

    /// Resolve one exact comparison-share round from durable chain state.
    /// `eager_expiry` is used after rendezvous/MPC failure, when this client
    /// knows it will never upload a share in the current session. The expiry
    /// writing is still only a request: the function returns solely after a
    /// read observes `verified` or `expired`.
    async fn wait_for_comparison_terminal(
        client: &ChainClient,
        order_a_id: &str,
        order_b_id: &str,
        owner_order_id: &str,
        match_round: u64,
        expected_deadline: u64,
        eager_expiry: bool,
        progress: &mut impl FnMut(&str),
    ) -> Result<ComparisonRoundTerminal, SettleError> {
        let wait_started = Instant::now();
        let mut last_expiry_attempt: Option<Instant> = None;
        loop {
            if wait_started.elapsed() >= Duration::from_secs(CHAIN_TERMINAL_WAIT_TIMEOUT_SECS) {
                return Err(SettleError::Transient(
                    "timed out waiting for a durable comparison-round terminal".into(),
                ));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            match tokio::time::timeout(
                Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
                client.query_compare_cozk2p_shares(
                    order_a_id.to_string(),
                    order_b_id.to_string(),
                    owner_order_id.to_string(),
                    match_round,
                ),
            )
            .await
            {
                Ok(Ok(round)) => {
                    if round.deadline_height != expected_deadline {
                        return Err(SettleError::Transient(format!(
                            "comparison round reported deadline {} (expected {expected_deadline})",
                            round.deadline_height
                        )));
                    }
                    if round.ready {
                        if !round.my_submitted
                            || !round.peer_submitted
                            || round.verified_height == 0
                            || round.state_commitment.is_empty()
                        {
                            return Err(SettleError::Transient(
                                "chain reported an internally inconsistent verified comparison round"
                                    .into(),
                            ));
                        }
                        return Ok(ComparisonRoundTerminal::Verified);
                    }
                    if round.expired_at_height != 0 {
                        return Ok(ComparisonRoundTerminal::Expired);
                    }
                }
                Ok(Err(e)) => eprintln!("[settle] query comparison-share round: {e}"),
                Err(_) => eprintln!("[settle] query comparison-share round timed out"),
            }

            let now = Instant::now();
            let expiry_due = (eager_expiry || wait_started.elapsed() >= Duration::from_secs(35))
                && last_expiry_attempt
                    .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(5));
            if expiry_due {
                progress("Waiting for the comparison deadline or the peer share...");
                match tokio::time::timeout(
                    Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
                    client.expire_compare_cozk2p_shares(
                        order_a_id.to_string(),
                        order_b_id.to_string(),
                        owner_order_id.to_string(),
                        match_round,
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("[settle] request comparison-share expiry: {e}"),
                    Err(_) => eprintln!("[settle] comparison-share expiry request timed out"),
                }
                last_expiry_attempt = Some(now);
            }
        }
    }

    /// Resolve a comparison-created settlement-leg round from durable chain
    /// state. In particular, a successful HTTP write is only an admission
    /// acknowledgement, not proof that expiry executed. We therefore keep
    /// polling until the row itself says `complete` or `expired` and retry the
    /// signed expiry request after the expected ten-block window.
    async fn wait_for_settlement_terminal(
        client: &ChainClient,
        order_a_id: &str,
        order_b_id: &str,
        owner_order_id: &str,
        match_round: u64,
        eager_expiry: bool,
        progress: &mut impl FnMut(&str),
    ) -> Result<SettleLegProgress, SettleError> {
        let wait_started = Instant::now();
        let mut last_expiry_attempt: Option<Instant> = None;
        let mut last_finalize_attempt: Option<Instant> = None;
        loop {
            if wait_started.elapsed() >= Duration::from_secs(CHAIN_TERMINAL_WAIT_TIMEOUT_SECS) {
                return Err(SettleError::Transient(
                    "timed out waiting for a durable settlement-round terminal".into(),
                ));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            match tokio::time::timeout(
                Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
                client.query_settle_legs(
                    order_a_id.to_string(),
                    order_b_id.to_string(),
                    owner_order_id.to_string(),
                    match_round,
                ),
            )
            .await
            {
                Ok(Ok(round)) => {
                    if round.complete {
                        if !round.my_submitted
                            || !round.peer_submitted
                            || round.completed_height == 0
                        {
                            return Err(SettleError::Transient(
                                "chain reported an internally inconsistent completed settlement round"
                                    .into(),
                            ));
                        }
                        return Ok(round);
                    }
                    if round.expired_at_height != 0 {
                        return Ok(round);
                    }
                    if round.my_submitted && round.peer_submitted {
                        let now = Instant::now();
                        if last_finalize_attempt
                            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(5))
                        {
                            progress(
                                "Both settlement proofs are present; finalizing atomically...",
                            );
                            match tokio::time::timeout(
                                Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
                                client.finalize_settle_legs(
                                    order_a_id.to_string(),
                                    order_b_id.to_string(),
                                    match_round,
                                ),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    eprintln!("[settle] finalize stored settlement legs: {e}")
                                }
                                Err(_) => {
                                    eprintln!("[settle] finalize settlement legs timed out")
                                }
                            }
                            last_finalize_attempt = Some(now);
                        }

                        // Expiry must reject a round whose two immutable legs
                        // are already present. Keep polling and idempotently
                        // retry finalization until a read observes completion.
                        continue;
                    }
                    if round.deadline_height == 0 {
                        eprintln!(
                            "[settle] comparison is Settling but its settlement deadline is not visible yet"
                        );
                    }
                }
                Ok(Err(e)) => eprintln!("[settle] query settlement-leg round: {e}"),
                Err(_) => eprintln!("[settle] query settlement-leg round timed out"),
            }

            let now = Instant::now();
            let expiry_due = (eager_expiry || wait_started.elapsed() >= Duration::from_secs(35))
                && last_expiry_attempt
                    .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(5));
            if expiry_due {
                progress("Waiting for the settlement deadline or the peer proof...");
                match tokio::time::timeout(
                    Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
                    client.expire_settle_legs(
                        order_a_id.to_string(),
                        order_b_id.to_string(),
                        owner_order_id.to_string(),
                        match_round,
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => eprintln!("[settle] request settlement-leg expiry: {e}"),
                    Err(_) => eprintln!("[settle] settlement-leg expiry request timed out"),
                }
                last_expiry_attempt = Some(now);
            }
        }
    }

    /// A rendezvous/MPC failure before `compare_ready` still has an active
    /// match-bound comparison deadline. Drive that round to a durable chain
    /// terminal so a zero-share abort cannot leave both orders Matched
    /// forever. If an earlier/uncertain write already verified comparison,
    /// continue through the zero-leg settlement deadline instead.
    async fn close_failed_pre_reveal_round(
        client: &ChainClient,
        order_a_id: &str,
        order_b_id: &str,
        owner_order_id: &str,
        match_round: u64,
        comparison_deadline: u64,
        cause: SettleError,
        progress: &mut impl FnMut(&str),
    ) -> SettleError {
        match wait_for_comparison_terminal(
            client,
            order_a_id,
            order_b_id,
            owner_order_id,
            match_round,
            comparison_deadline,
            true,
            progress,
        )
        .await
        {
            Ok(ComparisonRoundTerminal::Expired) => SettleError::OnChainRejected(format!(
                "{cause}; comparison round expired before reveal and both orders were released"
            )),
            Ok(ComparisonRoundTerminal::Verified) => {
                progress(
                    "Comparison verified during recovery; waiting for the no-reveal settlement deadline...",
                );
                match wait_for_settlement_terminal(
                    client,
                    order_a_id,
                    order_b_id,
                    owner_order_id,
                    match_round,
                    true,
                    progress,
                )
                .await
                {
                    Ok(round) if round.complete => SettleError::Transient(format!(
                        "{cause}; settlement nevertheless completed on chain and will be recovered from WAL"
                    )),
                    Ok(round) if !round.missing_order_id.is_empty() => {
                        SettleError::OnChainRejected(format!(
                            "{cause}; settlement closed with missing owner {}",
                            round.missing_order_id
                        ))
                    }
                    Ok(_) => SettleError::OnChainRejected(format!(
                        "{cause}; reveal delivery was not proven and both orders were released without blame"
                    )),
                    Err(e) => e,
                }
            }
            Err(e) => e,
        }
    }

    /// Cross-check a proven statement against the rows read from the chain:
    /// every non-`cmp` signal (both collateral commitments and prices plus
    /// the maker's side) must match, or
    /// the subprocess proved something other than THIS pair (a stale chain
    /// read, most likely). Cheap local guard — the chain re-verifies.
    fn check_public_statement(
        ctx: &SessionCtx<'_>,
        public: &PublicWire,
    ) -> Result<(), SettleError> {
        if public.locked_a != ctx.expected_locked_a
            || public.locked_b != ctx.expected_locked_b
            || public.price_a != ctx.price_a
            || public.price_b != ctx.price_b
            || public.a_is_seller != ctx.a_is_seller
        {
            return Err(SettleError::Transient(
                "prover statement does not match the on-chain order rows".into(),
            ));
        }
        Ok(())
    }

    /// Handle the subprocess's `compare_ready`: cross-check the proven
    /// statement and signatures, submit THIS owner's proof share, and block
    /// until the peer's independently signed share lets the chain reconstruct
    /// and verify the proof. Only a `true` reply lets the subprocess reveal.
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
            // The canonical comparison signature does not include proof
            // material. The native share is identity-bound separately by
            // SubmitCompareCoZk2pShare's outer signature.
            zk_proof: String::new(),
        };
        if !verify_compare_cozk2p_sig(&params, ctx.maker_pubkey, &ready.sig_a)
            || !verify_compare_cozk2p_sig(&params, ctx.taker_pubkey, &ready.sig_b)
        {
            return Err(SettleError::Transient(
                "compare signatures failed local verification".into(),
            ));
        }

        progress("Submitting this order's comparison proof share...");
        let deadline_height = ctx
            .my_order
            .match_height
            .max(ctx.counter_order.match_height)
            + COMPARE_SHARE_TIMEOUT_BLOCKS;
        if let Err(submit_err) = ctx
            .client
            .submit_compare_cozk2p_share(CompareShareParams {
                chain_id: ctx.client.chain_id(),
                order_a_id: ctx.maker_id.to_string(),
                order_b_id: ctx.taker_id.to_string(),
                owner_order_id: ctx.my_order.id.clone(),
                match_round: ctx.my_order.match_round,
                cmp: ready.cmp,
                deadline_height,
                proof_share: ready.proof_share_hex.clone(),
                signature: String::new(),
            })
            .await
        {
            // A transport failure is not proof that the write did not land.
            // Keep the prover behind the reveal gate and resolve the round
            // from chain state instead of killing it with a possibly-live
            // identity-bound share still pending.
            eprintln!("[settle] comparison-share submission uncertain: {submit_err}");
        }
        progress("Waiting for both proof shares and on-chain verification...");
        match wait_for_comparison_terminal(
            ctx.client,
            ctx.maker_id,
            ctx.taker_id,
            &ctx.my_order.id,
            ctx.my_order.match_round,
            deadline_height,
            false,
            progress,
        )
        .await?
        {
            ComparisonRoundTerminal::Verified => Ok(()),
            ComparisonRoundTerminal::Expired => Err(SettleError::OnChainRejected(
                "comparison proof-share deadline elapsed; both orders were released before reveal"
                    .into(),
            )),
        }
    }

    /// Prove THIS side's settle circuit from the session outcome and wrap
    /// it as this owner's independently submitted leg.
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
        let npk_refund = hex_fr(&outcome.refund_npk, "refund_npk")?;
        let r_refund = hex_fr(&outcome.r_refund, "r_refund")?;
        let q = ctx.opening.q;
        let r_locked = hex_fr(&ctx.opening.r_locked, "r_locked")?;
        let my_collateral_price = if outcome.is_a {
            ctx.price_a
        } else {
            ctx.price_b
        };
        let ctr_collateral_price = if outcome.is_a {
            ctx.price_b
        } else {
            ctx.price_a
        };

        if outcome.i_am_smaller {
            let setup =
                tokio::task::block_in_place(|| zk::setup::dev_setup_snarkjs("settle_small"))
                    .map_err(|e| SettleError::Transient(format!("settle_small setup: {e}")))?;
            let handle = zk::test_circuit::TestCircuitHandle::from_compiled(&setup.circuit_dir)
                .map_err(|e| SettleError::Transient(format!("circuit handle: {e}")))?;
            let mut w = SettleSmallWitness {
                q,
                r_locked,
                collateral_price: my_collateral_price,
                execution_price: ctx.execution_price,
                side_sell: my_side_sell,
                pay_asset,
                npk_ctr,
                r_note,
                npk_refund,
                r_refund,
                bind: fr_from_be_bytes(&[0u8; 32]),
            };
            let (cm_note_out, cm_refund_out) = w.output_cms();
            let cm_note_out = note_fr_to_hex(&cm_note_out);
            let cm_refund_out = note_fr_to_hex(&cm_refund_out);
            w.bind = settle_small_bind(
                ctx.client.chain_id(),
                &ctx.my_order.id,
                &ctx.counter_order.id,
                &cm_note_out,
                &cm_refund_out,
            );
            let proof = tokio::task::block_in_place(|| prove_settle_small(w, &handle, &setup.zkey))
                .map_err(|e| SettleError::Transient(format!("prove settle_small: {e}")))?;

            let mut params = SettleSmallParams {
                order_id: ctx.my_order.id.clone(),
                match_order_id: ctx.counter_order.id.clone(),
                cm_note_out: proof.cm_note_out_hex.clone(),
                cm_refund_out: proof.cm_refund_out_hex.clone(),
                signature: String::new(),
                zk_proof: serde_json::to_string(&proof.proof_json)
                    .map_err(|e| SettleError::Transient(format!("proof json: {e}")))?,
            };
            params.signature = ctx.client.sign_settle_small(&params);
            Ok(SettleLegWire {
                is_a: outcome.is_a,
                cm_note_out: params.cm_note_out,
                cm_refund_out: params.cm_refund_out,
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
                collateral_price: my_collateral_price,
                ctr_collateral_price,
                execution_price: ctx.execution_price,
                side_sell: my_side_sell,
                r_locked_residual: hex_fr(&outcome.r_locked_new, "r_locked_new")?,
                pay_asset,
                npk_ctr,
                r_note,
                npk_refund,
                r_refund,
                bind: fr_from_be_bytes(&[0u8; 32]),
            };
            let (cm_locked_res, cm_note, cm_refund) = w.output_cms();
            w.bind = settle_large_bind(
                ctx.client.chain_id(),
                &ctx.my_order.id,
                &ctx.counter_order.id,
                &note_fr_to_hex(&cm_locked_res),
                &note_fr_to_hex(&cm_note),
                &note_fr_to_hex(&cm_refund),
            );
            let proof = tokio::task::block_in_place(|| prove_settle_large(w, &handle, &setup.zkey))
                .map_err(|e| SettleError::Transient(format!("prove settle_large: {e}")))?;

            let mut params = SettleLargeParams {
                order_id: ctx.my_order.id.clone(),
                match_order_id: ctx.counter_order.id.clone(),
                cm_locked_residual: proof.cm_locked_residual_hex.clone(),
                cm_note_out: proof.cm_note_out_hex.clone(),
                cm_refund_out: proof.cm_refund_out_hex.clone(),
                signature: String::new(),
                zk_proof: serde_json::to_string(&proof.proof_json)
                    .map_err(|e| SettleError::Transient(format!("proof json: {e}")))?,
            };
            params.signature = ctx.client.sign_settle_large(&params);
            Ok(SettleLegWire {
                is_a: outcome.is_a,
                cm_note_out: params.cm_note_out,
                cm_refund_out: params.cm_refund_out,
                signature: params.signature,
                zk_proof: params.zk_proof,
                cm_locked_residual: params.cm_locked_residual,
            })
        }
    }

    fn chain_leg_params(leg: &SettleLegWire) -> SettlePairLegParams {
        if leg.cm_locked_residual.is_empty() {
            SettlePairLegParams::small(
                leg.cm_note_out.clone(),
                leg.cm_refund_out.clone(),
                leg.signature.clone(),
                leg.zk_proof.clone(),
            )
        } else {
            SettlePairLegParams::large(
                leg.cm_note_out.clone(),
                leg.cm_refund_out.clone(),
                leg.cm_locked_residual.clone(),
                leg.signature.clone(),
                leg.zk_proof.clone(),
            )
        }
    }

    /// Spawn `settle2p_session` and drive its full stdio protocol:
    /// `need_sig` → sign; `compare_ready` → submit + confirm on chain
    /// (pre-reveal gate); `result_ready` → prove and submit this owner's
    /// leg. Bounded by a 15-minute watchdog; the child is killed if this
    /// future is dropped.
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

        let mut comparison_confirmed_at: Option<Instant> = None;
        let mut settlement_proof_ms: Option<f64> = None;

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
                                // Semantic phase boundary: comparison is not
                                // complete until both proof shares reconstruct
                                // and verify on chain. Everything after this
                                // instant belongs to final settlement.
                                comparison_confirmed_at = Some(Instant::now());
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
                        // result.json is on disk; this host now proves and
                        // submits only its own settlement leg.
                        let result_bytes =
                            fs::read(ctx.session_dir.join("result.json")).map_err(|e| {
                                SettleError::Transient(format!("reading prover result: {e}"))
                            })?;
                        let res: SessionResultWire = serde_json::from_slice(&result_bytes)
                            .map_err(|e| {
                                SettleError::Transient(format!("parsing prover result: {e}"))
                            })?;
                        progress("Proving this side's settlement...");
                        let proof_started_at = Instant::now();
                        let leg = prove_my_leg(ctx, &res.my)?;
                        settlement_proof_ms = Some(proof_started_at.elapsed().as_secs_f64() * 1e3);
                        if leg.is_a != (ctx.my_order.id == ctx.maker_id) {
                            return Err(SettleError::Transient(
                                "settlement proof carries the wrong canonical owner role".into(),
                            ));
                        }
                        progress("Submitting this order's settlement proof...");
                        ctx.client
                            .submit_settle_leg(SubmitSettleLegParams {
                                chain_id: ctx.client.chain_id(),
                                order_a_id: ctx.maker_id.to_string(),
                                order_b_id: ctx.taker_id.to_string(),
                                owner_order_id: ctx.my_order.id.clone(),
                                match_round: ctx.my_order.match_round,
                                leg: chain_leg_params(&leg),
                                submission_signature: String::new(),
                            })
                            .await
                            .map_err(|e| {
                                SettleError::Transient(format!(
                                    "submit this owner's settlement proof: {e}"
                                ))
                            })?;
                        reply(&mut stdin, "{\"settle_leg_submitted\":true}".into()).await?;
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

        let result_bytes = fs::read(ctx.session_dir.join("result.json"))
            .map_err(|e| SettleError::Transient(format!("reading prover result: {e}")))?;
        let res: SessionResultWire = serde_json::from_slice(&result_bytes)
            .map_err(|e| SettleError::Transient(format!("parsing prover result: {e}")))?;
        // Redundant with confirm_compare, but result.json is re-read here:
        // keep the invariant local.
        check_public_statement(ctx, &res.public)?;
        let _ = (&res.proof_share_hex, &res.sig_a, &res.sig_b); // consumed in compare phase
        Ok(ProverOutput {
            res,
            comparison_confirmed_at: comparison_confirmed_at.ok_or_else(|| {
                SettleError::Transient("prover exited before comparison confirmation".into())
            })?,
            settlement_proof_ms: settlement_proof_ms.ok_or_else(|| {
                SettleError::Transient("prover exited before settlement proving".into())
            })?,
        })
    }

    /// Assemble the local outcome from the subprocess result.
    fn outcome_from_result(
        note_seed: &[u8; 32],
        my_order_id: &str,
        cmp: i8,
        my: &MyOutcomeWire,
        session_dir: PathBuf,
        timings: SettlePhaseTimings,
    ) -> SettleOutcome {
        let recv = NewNote {
            cm: my.recv_commitment.clone(),
            token: my.recv_token.clone(),
            amount: my.recv_amount,
            r_hex: my.r_recv.clone(),
            sk_hex: hex::encode(note_sk_bytes(note_seed, my_order_id)),
        };
        let refund = (my.refund_amount > 0).then(|| NewNote {
            cm: my.refund_commitment.clone(),
            token: my.refund_token.clone(),
            amount: my.refund_amount,
            r_hex: my.r_refund.clone(),
            sk_hex: hex::encode(refund_note_sk_bytes(note_seed, my_order_id)),
        });
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
            refund,
            remainder,
            session_dir,
            timings,
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
        pub refund_note: Option<NoteRecord>,
        /// The residual order opening, when this side survived on the book;
        /// `None` means the order fully filled (drop its opening).
        pub remainder: Option<OrderOpening>,
        pub dir: PathBuf,
    }

    /// Exact immutable identity of one comparison-created settlement window.
    /// Recovery derives this only from mutually linked `Settling` rows read
    /// from the chain; no local WAL field is trusted to select a round.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecoverableSettleRound {
        order_a_id: String,
        order_b_id: String,
        owner_order_id: String,
        match_round: u64,
    }

    /// Select this wallet's exact live settlement rounds from one chain
    /// snapshot. Both rows must still be `Settling`, point at each other, and
    /// carry the same non-zero round. Canonical A/B ordering is recomputed in
    /// lockstep with the chain, and self-owned pairs are de-duplicated.
    fn owned_recoverable_settle_rounds(
        orders: &[Order],
        owner_pubkey: &str,
    ) -> Vec<RecoverableSettleRound> {
        let mut seen = HashSet::new();
        let mut rounds = Vec::new();
        for mine in orders {
            if mine.pubkey != owner_pubkey || mine.status != OrderStatus::Settling {
                continue;
            }
            let Some(peer_id) = mine.match_order.as_deref() else {
                continue;
            };
            let Some(peer) = orders.iter().find(|order| order.id == peer_id) else {
                continue;
            };
            if peer.status != OrderStatus::Settling
                || peer.match_order.as_deref() != Some(mine.id.as_str())
                || mine.match_round == 0
                || peer.match_round != mine.match_round
            {
                continue;
            }
            let (a, b) = orderbook::maker_taker(mine, peer);
            let key = (a.id.clone(), b.id.clone(), mine.match_round);
            if !seen.insert(key.clone()) {
                continue;
            }
            rounds.push(RecoverableSettleRound {
                order_a_id: key.0,
                order_b_id: key.1,
                owner_order_id: mine.id.clone(),
                match_round: key.2,
            });
        }
        rounds
    }

    /// On restart, resume every exact owner-controlled `Settling` round from
    /// durable chain state. This deliberately never reconstructs or submits a
    /// settlement leg from `payout_keys.json` or a partial/corrupt witness:
    /// two already-stored legs may be finalized permissionlessly; otherwise
    /// the existing signed expiry path resolves the fixed deadline.
    async fn resume_owned_settling_rounds(client: &ChainClient) {
        let orders = match tokio::time::timeout(
            Duration::from_secs(CHAIN_RPC_TIMEOUT_SECS),
            client.query_orders(
                None,
                None,
                None,
                None,
                Some(OrderStatus::Settling),
                None,
                None,
            ),
        )
        .await
        {
            Ok(Ok(orders)) => orders,
            Ok(Err(e)) => {
                eprintln!("[settle] restart recovery could not query Settling orders: {e}");
                return;
            }
            Err(_) => {
                eprintln!("[settle] restart recovery query for Settling orders timed out");
                return;
            }
        };

        for round in owned_recoverable_settle_rounds(&orders, client.pubkey_hex()) {
            let mut progress = |status: &str| {
                eprintln!(
                    "[settle] restart recovery {} (round {}): {status}",
                    orderbook::short_id(&round.owner_order_id),
                    round.match_round
                );
            };
            match wait_for_settlement_terminal(
                client,
                &round.order_a_id,
                &round.order_b_id,
                &round.owner_order_id,
                round.match_round,
                true,
                &mut progress,
            )
            .await
            {
                Ok(terminal) if terminal.complete => eprintln!(
                    "[settle] restart recovery completed round {} for {}",
                    round.match_round, round.owner_order_id
                ),
                Ok(terminal) => eprintln!(
                    "[settle] restart recovery expired round {} for {} (missing={})",
                    round.match_round, round.owner_order_id, terminal.missing_order_id
                ),
                Err(e) => eprintln!(
                    "[settle] restart recovery left round {} for a later retry: {e}",
                    round.match_round
                ),
            }
        }
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

        // A process crash can leave the chain in `Settling` before a complete
        // witness exists (including payout_keys-only sessions). Resolve those
        // exact chain rounds first, so neither a missing WAL nor two restarted
        // clients can strand the pair forever. If finalization mints the note,
        // the directory scan below materializes it in this same startup pass.
        resume_owned_settling_rounds(client).await;

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
    /// The peer may still submit its own leg and complete the atomic
    /// settlement while the pair is Matched/Settling on chain, so the
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
            // Note not on chain (yet): the peer may still submit its leg.
            // Only a provably dead order state allows cleanup.
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
        let refund_note = if witness.my.refund_amount > 0 {
            let refund_leaf = match client.get_note_by_cm(&witness.my.refund_commitment).await {
                Ok(index) if index >= 0 => index as u64,
                _ => return Recovery::InProgress,
            };
            Some(NoteRecord {
                cm: witness.my.refund_commitment.clone(),
                token: witness.my.refund_token.clone(),
                amount: witness.my.refund_amount,
                r: witness.my.r_refund.clone(),
                key_index: 0,
                sk: hex::encode(refund_note_sk_bytes(note_seed, &witness.my_order_id)),
                leaf_index: refund_leaf,
                status: 0,
                nf: String::new(),
                pending_order: String::new(),
            })
        } else {
            None
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
            refund_note,
            remainder,
            dir: dir.to_path_buf(),
        })
    }

    #[cfg(test)]
    mod recovery_tests {
        use super::*;

        fn recovery_order(
            id: &str,
            pubkey: &str,
            status: OrderStatus,
            match_round: u64,
            block_height: u32,
            intra_block_index: u32,
        ) -> Order {
            Order {
                id: id.into(),
                kind: OrderKind::Limit,
                trade_type: TradeType::Sell,
                subject: TradePair {
                    token1: "ETH".into(),
                    token2: "USDT".into(),
                },
                price: Some(1),
                protection_price: None,
                execution_price: Some(1),
                match_round,
                match_height: 100,
                pubkey: pubkey.into(),
                locked_commitment: "11".repeat(32),
                fee: 0,
                block_height,
                intra_block_index,
                status,
                match_order: None,
            }
        }

        /// Restart recovery must derive canonical A/B and the round solely
        /// from two mutually linked Settling rows. The owner may be the taker;
        /// the resulting request must still use maker-first chain ordering.
        #[test]
        fn restart_recovery_selects_exact_owner_pair_and_round() {
            let mut maker = recovery_order("maker", "peer-key", OrderStatus::Settling, 7, 10, 0);
            let mut mine = recovery_order("mine", "my-key", OrderStatus::Settling, 7, 11, 0);
            maker.match_order = Some(mine.id.clone());
            mine.match_order = Some(maker.id.clone());

            let rounds = owned_recoverable_settle_rounds(&[mine, maker], "my-key");
            assert_eq!(
                rounds,
                vec![RecoverableSettleRound {
                    order_a_id: "maker".into(),
                    order_b_id: "mine".into(),
                    owner_order_id: "mine".into(),
                    match_round: 7,
                }]
            );
        }

        /// A stale/local WAL must never select a chain round. Any status,
        /// reciprocal-link, or round disagreement suppresses recovery writes.
        #[test]
        fn restart_recovery_rejects_non_exact_chain_pair() {
            let mut mine = recovery_order("mine", "my-key", OrderStatus::Settling, 7, 10, 0);
            let mut peer = recovery_order("peer", "peer-key", OrderStatus::Settling, 8, 11, 0);
            mine.match_order = Some(peer.id.clone());
            peer.match_order = Some(mine.id.clone());
            assert!(
                owned_recoverable_settle_rounds(&[mine.clone(), peer.clone()], "my-key").is_empty()
            );

            peer.match_round = 7;
            peer.match_order = Some("someone-else".into());
            assert!(
                owned_recoverable_settle_rounds(&[mine.clone(), peer.clone()], "my-key").is_empty()
            );

            peer.match_order = Some(mine.id.clone());
            peer.status = OrderStatus::Pending;
            assert!(owned_recoverable_settle_rounds(&[mine.clone(), peer], "my-key").is_empty());

            mine.status = OrderStatus::Matched;
            assert!(owned_recoverable_settle_rounds(&[mine], "my-key").is_empty());
        }

        /// P1-6 regression: while the payout note is absent, every
        /// uncertain state KEEPS the witness — the peer may still submit
        /// its settlement leg later. Only a provably dead order
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
