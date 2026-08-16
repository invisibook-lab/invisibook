//! Desktop settlement via the 2-party collaborative-ZK path
//! (`SettleOrdersCoZk2p`).
//!
//! The app owns no cryptography: all of it — the MPC comparison, the fill
//! reveal, the output-commitment exchange, and the collaborative PLONK
//! proof — runs in the pre-built `settle2p_session` subprocess (a separate
//! cargo workspace pinned to an older toolchain, so it cannot be linked).
//! This module drives that subprocess over piped stdio, ferries the one
//! ed25519 signature it asks for, submits the single on-chain writing, and
//! persists the resulting UTXOs.
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
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        process::Command,
    };

    use invisibook_lib::{
        cash_store::CashRecord,
        chain::{ChainClient, SettleCoZkParams},
        orderbook,
        types::*,
    };

    /// `Poseidon(0, 0)` — the zero-commitment used to pad unused locked
    /// slots to the circuit's fixed N=2 shape.
    pub const POSEIDON_ZERO_COMMITMENT_HEX: &str =
        "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864";

    /// A newly minted UTXO the wallet must persist to keep it spendable.
    #[derive(Clone, Debug)]
    pub struct NewCash {
        pub cash_id: String,
        pub token: String,
        pub amount: u64,
        pub random_hex: String,
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
        pub recv: NewCash,
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

    /// Everything the settle flow needs from config: the prover binary and
    /// the two data-dir subpaths.
    #[derive(Clone, Debug)]
    pub struct SettleDeps {
        pub bin: PathBuf,
        pub keys_dir: PathBuf,
        pub sessions_dir: PathBuf,
    }

    /// The set of locked input cash IDs an order spends when it settles.
    pub fn spent_cash_ids(order: &Order) -> HashSet<String> {
        order.input_cash_ids.iter().cloned().collect()
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
        my: MyPrivateWire,
    }

    #[derive(Deserialize)]
    struct NeedSigWire {
        cmp: i8,
        new_order_a: String,
        new_order_b: String,
        new_locked_a: String,
        new_locked_b: String,
        recv_a: String,
        recv_b: String,
    }

    /// Subset of the subprocess `SettlePublic` the app cross-checks; serde
    /// ignores the fields not named here.
    #[derive(Deserialize)]
    struct PublicWire {
        order_a: String,
        order_b: String,
    }

    #[derive(Deserialize)]
    struct MyOutcomeWire {
        recv_amount: u64,
        r_recv: String,
        recv_commitment: String,
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

    /// Crash-recovery record the subprocess writes before releasing its
    /// signature. Mirrors cozk2p's `SessionWitness`.
    #[derive(Deserialize)]
    struct SessionWitnessWire {
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
    /// padded to two slots with the zero commitment. `order.input_cash_ids`
    /// must reference cashes owned by `order.pubkey` in `token`.
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
    /// `order.amount` commitment — every writer persists it (trade_form on
    /// lock, settlement on relist, recovery on materialize), and its
    /// blinding exists nowhere else, so a record without it can never
    /// settle.
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
        // The first input carries the order-commitment witness.
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

    /// Run the full 2-party collaborative settlement for a matched pair.
    /// `my_order` and `counter_order` must be mutually `Matched`.
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

        // Equal-price requirement of the co-zk circuit.
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

        // ── Prover subprocess ──
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

        // ── Submit and confirm ──
        progress("Submitting settlement...");
        let params = SettleCoZkParams {
            order_a_id: maker.id.clone(),
            order_b_id: taker.id.clone(),
            cmp: result.cmp,
            new_order_a_commitment: result.need.new_order_a.clone(),
            new_order_b_commitment: result.need.new_order_b.clone(),
            new_locked_a_commitment: result.need.new_locked_a.clone(),
            new_locked_b_commitment: result.need.new_locked_b.clone(),
            recv_a_commitment: result.need.recv_a.clone(),
            recv_b_commitment: result.need.recv_b.clone(),
            sig_a: result.res.sig_a.clone(),
            sig_b: result.res.sig_b.clone(),
            zk_proof: result.res.proof_hex.clone(),
        };
        // Best-effort submit — either party may land it; a duplicate or a
        // pair already advanced past Matched is a benign race, judged by
        // the confirm-poll below.
        if let Err(e) = client.settle_orders_cozk2p(&params).await {
            let msg = e.to_string();
            if !(msg.contains("not Matched") || msg.contains("duplicated")) {
                progress(&format!("submit warning: {msg}"));
            }
        }

        progress("Confirming settlement on chain...");
        let my_new_order = result.res.my.new_order_commitment.clone();
        confirm_on_chain(client, &my_order.id, &my_new_order).await?;

        Ok(outcome_from_result(
            &my_pubkey,
            &my_lock_token,
            &my_recv_token,
            result.cmp,
            &result.res.my,
            session_dir,
        ))
    }

    /// The prover subprocess plus the signature it made this trader produce.
    struct ProverOutput {
        cmp: i8,
        need: NeedSigWire,
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

        let mut need: Option<NeedSigWire> = None;

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
                        let params = SettleCoZkParams {
                            order_a_id: order_a_id.to_string(),
                            order_b_id: order_b_id.to_string(),
                            cmp: ns.cmp,
                            new_order_a_commitment: ns.new_order_a.clone(),
                            new_order_b_commitment: ns.new_order_b.clone(),
                            new_locked_a_commitment: ns.new_locked_a.clone(),
                            new_locked_b_commitment: ns.new_locked_b.clone(),
                            recv_a_commitment: ns.recv_a.clone(),
                            recv_b_commitment: ns.recv_b.clone(),
                            sig_a: String::new(),
                            sig_b: String::new(),
                            zk_proof: String::new(),
                        };
                        let sig = client.sign_settle_cozk2p(&params);
                        let sig_line = format!("{{\"sig\":\"{sig}\"}}\n");
                        stdin
                            .write_all(sig_line.as_bytes())
                            .await
                            .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))?;
                        stdin
                            .flush()
                            .await
                            .map_err(|e| SettleError::Transient(format!("prover stdin: {e}")))?;
                        need = Some(ns);
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

        let need = need
            .ok_or_else(|| SettleError::Transient("prover never requested a signature".into()))?;
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

        // Sanity: the proven statement must match the chain-sourced inputs,
        // and both signatures must verify (the chain re-verifies regardless).
        let params = SettleCoZkParams {
            order_a_id: order_a_id.to_string(),
            order_b_id: order_b_id.to_string(),
            cmp: res.cmp,
            new_order_a_commitment: need.new_order_a.clone(),
            new_order_b_commitment: need.new_order_b.clone(),
            new_locked_a_commitment: need.new_locked_a.clone(),
            new_locked_b_commitment: need.new_locked_b.clone(),
            recv_a_commitment: need.recv_a.clone(),
            recv_b_commitment: need.recv_b.clone(),
            sig_a: res.sig_a.clone(),
            sig_b: res.sig_b.clone(),
            zk_proof: res.proof_hex.clone(),
        };
        if !invisibook_lib::chain::verify_settle_cozk2p_sig(&params, maker_pubkey, &res.sig_a)
            || !invisibook_lib::chain::verify_settle_cozk2p_sig(&params, taker_pubkey, &res.sig_b)
        {
            return Err(SettleError::Transient(
                "settlement signatures failed local verification".into(),
            ));
        }

        Ok(ProverOutput {
            cmp: res.cmp,
            need,
            res,
        })
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
            let orders = match client
                .query_orders(
                    Some(my_order_id.to_string()),
                    None,
                    None,
                    None,
                    None,
                    Some(1),
                    Some(0),
                )
                .await
            {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("[settle] confirm poll: {e}");
                    continue;
                }
            };
            if let Some(order) = orders.into_iter().find(|o| o.id == my_order_id) {
                if order.status == OrderStatus::Done || order.amount == *my_new_order_commitment {
                    return Ok(());
                }
            }
        }
        Err(SettleError::OnChainRejected(
            "settlement not observed on chain within the confirmation window".into(),
        ))
    }

    /// Assemble the local outcome from the subprocess result. Cash ids are
    /// content-addressed over the commitment hex, matching the chain.
    fn outcome_from_result(
        my_pubkey: &str,
        my_lock_token: &str,
        my_recv_token: &str,
        cmp: i8,
        my: &MyOutcomeWire,
        session_dir: PathBuf,
    ) -> SettleOutcome {
        let recv = NewCash {
            cash_id: orderbook::compute_cash_id(my_pubkey, my_recv_token, &my.recv_commitment),
            token: my_recv_token.to_string(),
            amount: my.recv_amount,
            random_hex: my.r_recv.clone(),
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
        pub add: Vec<CashRecord>,
        pub dir: PathBuf,
    }

    /// Inspect every session dir and decide, per the recovery predicate
    /// (recv-cash existence on chain), whether it LANDED (materialize its
    /// records) or did not (delete it). Session dirs whose settlement has
    /// not yet finished (no witness.json) are left untouched.
    pub async fn recover_all_sessions(
        client: &ChainClient,
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
            match try_recover_session(client, &dir).await {
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

    /// Recovery predicate for one session dir: read `witness.json`, compute
    /// the recv cash id, and check on-chain existence. `dir` must be a
    /// session scratch directory.
    pub async fn try_recover_session(client: &ChainClient, dir: &std::path::Path) -> Recovery {
        let witness_bytes = match fs::read(dir.join("witness.json")) {
            Ok(b) => b,
            Err(_) => return Recovery::InProgress,
        };
        let witness: SessionWitnessWire = match serde_json::from_slice(&witness_bytes) {
            Ok(w) => w,
            Err(_) => return Recovery::Deleted,
        };
        let my_pubkey = client.pubkey_hex().to_string();
        let recv_id = orderbook::compute_cash_id(
            &my_pubkey,
            &witness.my_recv_token,
            &witness.my.recv_commitment,
        );
        let account = match client.get_account(&my_pubkey, &witness.my_recv_token).await {
            Ok(a) => a,
            Err(_) => return Recovery::InProgress, // can't decide now; retry later
        };
        if !account.cash.iter().any(|c| c.id == recv_id) {
            return Recovery::Deleted; // never landed; blindings are stale
        }
        // Landed: materialize spent inputs + recv + optional remainder.
        let mut add = vec![CashRecord {
            cash_id: recv_id,
            token: witness.my_recv_token.clone(),
            amount: witness.my.recv_amount,
            random: witness.my.r_recv.clone(),
            status: CASH_ACTIVE,
            order_amount: None,
            order_random: None,
        }];
        if witness.my.new_order_amount > 0 {
            add.push(CashRecord {
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
        Recovery::Landed(Recovered {
            spent_ids: witness.my_input_cash_ids,
            add,
            dir: dir.to_path_buf(),
        })
    }
}

#[cfg(not(target_os = "android"))]
pub use inner::*;
