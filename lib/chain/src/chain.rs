use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use yu_sdk::{KeyPair, YuClient};

use crate::types::*;

// Re-export KeyPair so consumers don't need to depend on yu-sdk directly.
pub use yu_sdk::KeyPair as YuKeyPair;

// ────────────────────── Request/Response Types ──────────────────────

/// Mirror of chain Go `SendOrderRequest` (v2): spend two pool notes, commit
/// the order quantity as `amount` (cm_q), lock its collateral, destroy the
/// plaintext `fee`, and mint the change note.
#[derive(Debug, Clone, Serialize)]
pub struct SendOrderParams {
    pub id: OrderID,
    #[serde(rename = "type")]
    pub trade_type: u8,
    pub subject: TradePairJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<u64>,
    pub amount: CipherText, // cm_q
    pub pubkey: String,
    pub signature: String,
    pub anchor: String,
    pub input_nullifiers: Vec<String>,
    pub locked_commitment: String,
    pub fee: u64,
    pub change_commitment: String,
    pub zk_proof: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TradePairJson {
    pub token1: TokenID,
    pub token2: TokenID,
}

// ────────────────────── SendOrder Signing Message ──────────────────────

/// Domain tag separating the SendOrder signing message from every other
/// ed25519 message in the system (e.g. the co-zk settle messages).
const SEND_ORDER_SIGNING_DOMAIN: &str = "invisibook-send-order-v2";

/// Appends `s` to `buf` prefixed with its u32 big-endian byte length, so
/// consecutive fields of arbitrary content concatenate without ambiguity.
fn put_signing_field(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Canonical byte string the order owner ed25519-signs to authorize a
/// SendOrder request. Covers every request field except the signature itself
/// and the zk proof (already bound to its commitments through public-input
/// verification). The `signature` field of `params` is not part of the
/// message and may be empty. Must stay in lockstep with Go
/// `core.SendOrderSigningMessage`.
pub fn send_order_signing_message(params: &SendOrderParams) -> Vec<u8> {
    let price = params.price.map(|p| p.to_string()).unwrap_or_default();
    let mut buf = Vec::with_capacity(256);
    put_signing_field(&mut buf, SEND_ORDER_SIGNING_DOMAIN);
    put_signing_field(&mut buf, &params.id);
    put_signing_field(&mut buf, &params.trade_type.to_string());
    put_signing_field(&mut buf, &params.subject.token1);
    put_signing_field(&mut buf, &params.subject.token2);
    put_signing_field(&mut buf, &price);
    put_signing_field(&mut buf, &params.amount);
    put_signing_field(&mut buf, &params.pubkey);
    put_signing_field(&mut buf, &params.anchor);
    put_signing_field(&mut buf, &params.input_nullifiers[0]);
    put_signing_field(&mut buf, &params.input_nullifiers[1]);
    put_signing_field(&mut buf, &params.locked_commitment);
    // Fee as a raw u64-BE 8-byte field (matches Go's binary.BigEndian).
    let fee_bytes = params.fee.to_be_bytes();
    buf.extend_from_slice(&(fee_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&fee_bytes);
    put_signing_field(&mut buf, &params.change_commitment);
    buf
}

/// Mirror of chain Go `CompareRequest` — the dual-signed comparison result
/// (paper π_cmp phase). `zk_proof` is snarkjs Groth16 JSON for
/// `SubmitCompareCoZk`, hex-encoded ark-compressed PLONK bytes for
/// `SubmitCompareCoZk2p`.
#[derive(Debug, Clone, Serialize)]
pub struct CompareParams {
    /// The maker's order ID (lower block height; ties broken by the
    /// lexicographically smaller ID) — always the circuit's a-side.
    pub order_a_id: OrderID,
    /// The taker's order ID — the circuit's b-side.
    pub order_b_id: OrderID,
    /// Public three-way comparison of the hidden order amounts,
    /// `sign(a - b)`.
    pub cmp: i8,
    pub sig_a: String,
    pub sig_b: String,
    pub zk_proof: String,
}

/// Builds the canonical compare byte string with the given domain `prefix`,
/// in lockstep with Go `core.compareMessage`. The signature fields of
/// `params` are not part of the message and may be empty.
fn compare_message_with_prefix(prefix: &str, params: &CompareParams) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        prefix, params.order_a_id, params.order_b_id, params.cmp
    )
    .into_bytes()
}

/// Canonical byte string both traders ed25519-sign for the Groth16 compare
/// variant. Lockstep with Go `core.CoZkCompareMessage`.
pub fn compare_cozk_message(params: &CompareParams) -> Vec<u8> {
    compare_message_with_prefix("invisibook-cozk-compare-v2", params)
}

/// Canonical byte string both traders ed25519-sign for the 2-party PLONK
/// compare variant. Lockstep with Go `core.CoZk2pCompareMessage`.
pub fn compare_cozk2p_message(params: &CompareParams) -> Vec<u8> {
    compare_message_with_prefix("invisibook-cozk2p-compare-v2", params)
}

/// Verifies an ed25519 signature over `compare_cozk2p_message(params)`.
/// Returns `false` (never panics) on any malformed input.
pub fn verify_compare_cozk2p_sig(params: &CompareParams, pubkey_hex: &str, sig_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&compare_cozk2p_message(params), &signature)
        .is_ok()
}

/// Mirror of chain Go `SettleSmallRequest` — the fully filled side's own
/// settlement update (paper π_A).
#[derive(Debug, Clone, Serialize)]
pub struct SettleSmallParams {
    pub order_id: OrderID,
    pub match_order_id: OrderID,
    pub cm_note_out: String,
    pub signature: String,
    pub zk_proof: String,
}

/// Mirror of chain Go `SettleLargeRequest` — the partially filled side's
/// own update (paper π_B).
#[derive(Debug, Clone, Serialize)]
pub struct SettleLargeParams {
    pub order_id: OrderID,
    pub match_order_id: OrderID,
    pub cm_q_residual: String,
    pub cm_locked_residual: String,
    pub cm_note_out: String,
    pub signature: String,
    pub zk_proof: String,
}

/// One leg of a `SettlePair` — mirror of Go `SettlePairLeg`. The residual
/// fields are set ONLY for the larger side (π_B); a fully filled leg (π_A,
/// and both legs when cmp == 0) leaves them empty, and they are omitted from
/// the wire JSON to match the Go `omitempty` tags. Each leg carries its own
/// owner signature (over the SettleSmall/SettleLarge message), so a pair
/// needs no new signed message.
#[derive(Debug, Clone, Serialize)]
pub struct SettlePairLegParams {
    pub cm_note_out: String,
    pub signature: String,
    pub zk_proof: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cm_q_residual: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cm_locked_residual: String,
}

impl SettlePairLegParams {
    /// A fully filled leg (π_A): the whole collateral transfers as one note;
    /// no residual. `signature` is over the SettleSmall message.
    pub fn small(cm_note_out: String, signature: String, zk_proof: String) -> Self {
        Self {
            cm_note_out,
            signature,
            zk_proof,
            cm_q_residual: String::new(),
            cm_locked_residual: String::new(),
        }
    }

    /// A larger leg (π_B): pays the fill as a note and relists the residual.
    /// `signature` is over the SettleLarge message.
    pub fn large(
        cm_note_out: String,
        cm_q_residual: String,
        cm_locked_residual: String,
        signature: String,
        zk_proof: String,
    ) -> Self {
        Self {
            cm_note_out,
            signature,
            zk_proof,
            cm_q_residual,
            cm_locked_residual,
        }
    }
}

/// Mirror of chain Go `SettlePairRequest` — settles BOTH sides of a matched
/// pair in one atomic writing (both proofs verified, both payout notes minted
/// together, so neither side is paid without the other). A/B are the
/// canonical maker/taker order ids; the recorded cmp decides which leg is
/// the larger one.
#[derive(Debug, Clone, Serialize)]
pub struct SettlePairParams {
    pub order_a_id: OrderID,
    pub order_b_id: OrderID,
    pub a: SettlePairLegParams,
    pub b: SettlePairLegParams,
}

/// Length-prefixed settle signing message, lockstep with Go
/// `core.settleSigMessage`.
fn settle_sig_message(domain: &str, fields: &[&str]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(256);
    let mut put = |f: &[u8]| {
        msg.extend_from_slice(&(f.len() as u32).to_be_bytes());
        msg.extend_from_slice(f);
    };
    put(domain.as_bytes());
    for f in fields {
        put(f.as_bytes());
    }
    msg
}

/// The owner-signed message for SettleSmall (Go `core.SettleSmallSigMessage`).
pub fn settle_small_message(params: &SettleSmallParams) -> Vec<u8> {
    settle_sig_message(
        "invisibook-settle-small-v1",
        &[
            &params.order_id,
            &params.match_order_id,
            &params.cm_note_out,
        ],
    )
}

/// The owner-signed message for SettleLarge (Go `core.SettleLargeSigMessage`).
pub fn settle_large_message(params: &SettleLargeParams) -> Vec<u8> {
    settle_sig_message(
        "invisibook-settle-large-v1",
        &[
            &params.order_id,
            &params.match_order_id,
            &params.cm_q_residual,
            &params.cm_locked_residual,
            &params.cm_note_out,
        ],
    )
}

/// Register settle address request params.
#[derive(Debug, Serialize)]
struct RegisterSettleAddrParams {
    order_id: OrderID,
    match_order_id: OrderID,
    addr: String,
}

/// Query settle address request params.
#[derive(Debug, Serialize)]
struct QuerySettleAddrParams {
    order_id: OrderID,
    match_order_id: OrderID,
}

/// Query settle address response.
#[derive(Debug, Deserialize)]
struct QuerySettleAddrResponse {
    #[serde(default)]
    addr: String,
}

#[derive(Debug, Serialize)]
struct QueryOrdersParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<OrderID>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    trade_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token1: Option<TokenID>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token2: Option<TokenID>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct QueryOrdersResponse {
    pub orders: Vec<QueryOrderItem>,
}

#[derive(Debug, Deserialize)]
pub struct QueryOrderItem {
    pub id: OrderID,
    #[serde(rename = "type")]
    pub trade_type: u8,
    pub subject: QueryTradePair,
    #[serde(default, deserialize_with = "deserialize_price")]
    pub price: Option<u64>,
    pub amount: CipherText,
    pub pubkey: String,
    #[serde(default)]
    pub locked_commitment: String,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub block_height: u32,
    #[serde(default)]
    pub intra_block_index: u32,
    pub status: u8,
    #[serde(default)]
    pub match_order: Option<String>,
}

/// Go's `*big.Int` serializes as a JSON string (e.g. `"100"`) via `MarshalText`,
/// but we need `Option<u64>`. This handles both string and number representations.
fn deserialize_price<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: Option<Value> = Option::deserialize(deserializer)?;
    match v {
        None => Ok(None),
        Some(Value::Number(n)) => Ok(n.as_u64()),
        Some(Value::String(s)) => Ok(s.parse::<u64>().ok()),
        _ => Ok(None),
    }
}

#[derive(Debug, Deserialize)]
pub struct QueryTradePair {
    pub token1: TokenID,
    pub token2: TokenID,
}

// ────────────────────── Account Request/Response Types ──────────────────────

#[derive(Debug, Serialize)]
struct GetAccountParams {
    pubkey: String,
    token: TokenID,
}

#[derive(Debug, Serialize)]
struct DepositParams {
    pubkey: String,
    token: TokenID,
    /// Hex commitment to the (hidden) plaintext amount the source-chain bridge
    /// attested. Until the bridge proof is verified on-chain, this field is
    /// trusted blindly (testnet/demo only).
    bridge_commitment: String,
    /// Hex commitment that becomes the new `Cash.Amount`.
    output_commitment: String,
    /// snarkjs `proof.json` produced by rapidsnark.
    zk_proof: String,
}

#[derive(Debug, Serialize)]
struct WithdrawParams {
    pubkey: String,
    token: TokenID,
    inputs: Vec<String>,
    /// Hex commitment to the (hidden) withdrawn amount. Trusted by chain
    /// until the destination-chain bridge release proof lands.
    bridge_out_commitment: String,
    /// Always length 2: `[change_commitment, zero_pad_commitment]`. When the
    /// withdrawal has no change, slot 0 is the well-known `Poseidon(0,0)` hex.
    output_commitments: Vec<String>,
    /// Empty string means "mint change back to the withdrawer" (chain
    /// substitutes `pubkey`).
    #[serde(skip_serializing_if = "String::is_empty")]
    change_pubkey: String,
    /// snarkjs `proof.json` produced by rapidsnark.
    zk_proof: String,
}

/// Mirror of chain Go `NoteDepositRequest` (shielded pool).
#[derive(Debug, Serialize)]
struct NoteDepositParams {
    token: String,
    bridge_commitment: String,
    output_commitment: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    bridge_sig: String,
    zk_proof: String,
}

/// Mirror of chain Go `NoteWithdrawRequest` (shielded pool).
#[derive(Debug, Serialize)]
struct NoteWithdrawParams {
    token: String,
    anchor: String,
    nullifiers: Vec<String>,
    bridge_out_commitment: String,
    change_commitment: String,
    zk_proof: String,
}

/// One leaf in a GetNotes response.
#[derive(Debug, Clone, Deserialize)]
pub struct NoteLeaf {
    pub leaf_index: u64,
    pub cm: String,
    pub height: u64,
}

/// GetNotes response: leaves plus the pool head for cross-checking the
/// client-side tree root after syncing.
#[derive(Debug, Deserialize)]
pub struct NotesResponse {
    pub leaf_count: u64,
    pub latest_root: String,
    pub notes: Vec<NoteLeaf>,
}

/// GetPoolInfo response.
#[derive(Debug, Deserialize)]
pub struct PoolInfoResponse {
    pub leaf_count: u64,
    pub latest_root: String,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    pubkey: String,
    token: TokenID,
    #[serde(default)]
    cash: Vec<CashItemResponse>,
}

#[derive(Debug, Deserialize)]
struct CashItemResponse {
    id: String,
    pubkey: String,
    token: TokenID,
    amount: CipherText,
    #[serde(default)]
    zk_proof: String,
    #[serde(default)]
    status: u8,
    #[serde(default)]
    by: String,
}

// ────────────────────── Chain Client ──────────────────────

// ────────────────────── WebSocket Event Types ──────────────────────

/// Raw event from the yu Receipt WebSocket stream.
/// Go's `json.Marshal([]byte)` encodes as a base64 string, so `value` is a String here.
#[derive(Deserialize)]
struct YuEvent {
    value: String, // base64-encoded JSON bytes
}

/// Partial Receipt structure — only the fields we care about.
#[derive(Deserialize)]
struct YuReceipt {
    tripod_name: Option<String>,
    writing_name: Option<String>,
    #[serde(default)]
    events: Vec<YuEvent>,
    #[serde(default)]
    error: String,
}

/// JSON event emitted by Go `SendOrder` via `ctx.EmitJsonEvent`.
#[derive(Deserialize)]
struct ChainOrderEvent {
    #[allow(dead_code)]
    event_type: String,
    order: QueryOrderItem,
    matched: Option<QueryOrderItem>,
}

/// Events yielded by `subscribe_order_events`.
pub enum OrderEvent {
    /// An order was confirmed on-chain.
    Confirmed(Order),
    /// An error occurred (chain tx error or parse failure).
    Error(String),
}

// ────────────────────── Chain Client ──────────────────────

pub struct ChainClient {
    client: YuClient,
    ws_url: String,
    chain_id: u64,
    seed: [u8; 32],     // ed25519 private key seed (for application-level signing)
    pubkey_hex: String, // raw ed25519 pubkey as 64-char hex
}

impl ChainClient {
    /// Creates a new ChainClient connected to the given yu node.
    /// `http_url` example: "http://localhost:7999"
    /// `ws_url`   example: "ws://localhost:8999"
    /// `seed` is the 32-byte ed25519 private key seed.
    pub fn new(http_url: &str, ws_url: &str, seed: [u8; 32], chain_id: u64) -> Self {
        let keypair = KeyPair::from_ed25519_bytes(&seed);
        let pubkey_hex = hex::encode(keypair.pubkey_bytes());
        let client = YuClient::new(http_url, ws_url).with_keypair(keypair);
        Self {
            client,
            ws_url: ws_url.trim_end_matches('/').to_string(),
            chain_id,
            seed,
            pubkey_hex,
        }
    }

    /// Returns the owner's raw ed25519 pubkey as a 64-char hex string.
    /// The chain id this client signs and binds against.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// Signs `message` with the client's ed25519 private key.
    /// Returns the 64-byte signature as a 128-char hex string.
    fn sign(&self, message: &[u8]) -> String {
        let kp = KeyPair::from_ed25519_bytes(&self.seed);
        hex::encode(kp.sign(message))
    }

    /// Submits a new order to the chain. When `change` is provided (split
    /// Submits a SendOrder v2 request. The caller assembles `params`
    /// (nullifiers, cm_q, locked commitment, fee, change commitment) and the
    /// send_order proof; this method signs the canonical message and submits.
    pub async fn send_order(
        &self,
        mut params: SendOrderParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        params.pubkey = self.pubkey_hex.clone();
        params.signature = self.sign(&send_order_signing_message(&params));
        self.client
            .write_chain("orderbook", "SendOrder", &params, self.chain_id, 100, 0)
            .await
    }

    /// ed25519-signs the canonical 2-party compare message with this
    /// client's key, returning the 128-char hex signature. The signature
    /// fields of `params` are ignored (they are not part of the message).
    pub fn sign_compare_cozk2p(&self, params: &CompareParams) -> String {
        self.sign(&compare_cozk2p_message(params))
    }

    /// Submits the dual-signed comparison result with its collaboratively
    /// generated PLONK π_cmp; either party may submit.
    pub async fn submit_compare_cozk2p(
        &self,
        params: &CompareParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .write_chain(
                "orderbook",
                "SubmitCompareCoZk2p",
                params,
                self.chain_id,
                100,
                0,
            )
            .await
    }

    /// ed25519-signs the SettleSmall message with this client's key.
    pub fn sign_settle_small(&self, params: &SettleSmallParams) -> String {
        self.sign(&settle_small_message(params))
    }

    /// Submits this side's fully-filled settlement update (paper π_A).
    /// Persist-before-publish: the payout note the counterparty will
    /// receive was already committed to by their wallet; MY submission must
    /// come after MY WAL holds everything needed to re-submit.
    pub async fn settle_small(
        &self,
        params: &SettleSmallParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .write_chain("orderbook", "SettleSmall", params, self.chain_id, 100, 0)
            .await
    }

    /// ed25519-signs the SettleLarge message with this client's key.
    pub fn sign_settle_large(&self, params: &SettleLargeParams) -> String {
        self.sign(&settle_large_message(params))
    }

    /// Submits this side's partially-filled settlement update (paper π_B).
    pub async fn settle_large(
        &self,
        params: &SettleLargeParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .write_chain("orderbook", "SettleLarge", params, self.chain_id, 100, 0)
            .await
    }

    /// Submits BOTH sides' settlements as one atomic `SettlePair` writing —
    /// either the whole pair settles or nothing does. The two legs' proofs
    /// and per-leg signatures are exchanged over the settlement channel, then
    /// either party submits the pair. Use in place of the separate
    /// settle_small / settle_large writings to close the fair-exchange gap.
    pub async fn settle_pair(
        &self,
        params: &SettlePairParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .write_chain("orderbook", "SettlePair", params, self.chain_id, 100, 0)
            .await
    }

    /// Registers this party's QUIC address on-chain for MPC peer discovery.
    /// NOTE: This on-chain address exchange is temporary. In production, peer
    /// addresses will be exchanged via Tor or similar anonymous overlay network.
    pub async fn register_settle_addr(
        &self,
        order_id: OrderID,
        match_order_id: OrderID,
        addr: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = RegisterSettleAddrParams {
            order_id,
            match_order_id,
            addr: addr.to_string(),
        };
        self.client
            .write_chain(
                "orderbook",
                "RegisterSettleAddr",
                &params,
                self.chain_id,
                10,
                0,
            )
            .await
    }

    /// Queries the counterparty's registered QUIC address for MPC settle.
    /// Returns `None` if the counterparty hasn't registered yet.
    pub async fn query_settle_addr(
        &self,
        order_id: OrderID,
        match_order_id: OrderID,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let params = QuerySettleAddrParams {
            order_id,
            match_order_id,
        };
        let value: Value = self
            .client
            .read_chain("orderbook", "QuerySettleAddr", &params)
            .await?;
        let resp: QuerySettleAddrResponse = serde_json::from_value(value)?;
        if resp.addr.is_empty() {
            Ok(None)
        } else {
            Ok(Some(resp.addr))
        }
    }

    /// Queries orders from the chain with optional filters and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn query_orders(
        &self,
        id: Option<OrderID>,
        trade_type: Option<TradeType>,
        token1: Option<TokenID>,
        token2: Option<TokenID>,
        status: Option<OrderStatus>,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<Order>, Box<dyn std::error::Error>> {
        let params = QueryOrdersParams {
            id,
            trade_type: trade_type.map(|t| match t {
                TradeType::Buy => 0,
                TradeType::Sell => 1,
            }),
            token1,
            token2,
            status: status.map(|s| match s {
                OrderStatus::Pending => 0,
                OrderStatus::Matched => 1,
                OrderStatus::Done => 2,
                OrderStatus::Cancelled => 3,
                OrderStatus::Frozen => 4,
                OrderStatus::Settling => 5,
            }),
            limit,
            offset,
        };
        let value: Value = self
            .client
            .read_chain("orderbook", "QueryOrders", &params)
            .await?;
        let resp: QueryOrdersResponse = serde_json::from_value(value)?;
        Ok(resp.orders.into_iter().map(query_item_to_order).collect())
    }

    /// Gets account details for the given pubkey and token.
    pub async fn get_account(
        &self,
        pubkey: &str,
        token: &str,
    ) -> Result<AccountRecord, Box<dyn std::error::Error>> {
        let params = GetAccountParams {
            pubkey: pubkey.to_string(),
            token: token.to_string(),
        };
        let value: Value = self
            .client
            .read_chain("account", "GetAccount", &params)
            .await?;
        let resp: AccountResponse = serde_json::from_value(value)?;
        Ok(AccountRecord {
            pubkey: resp.pubkey,
            token: resp.token,
            cash: resp
                .cash
                .into_iter()
                .map(|c| CashItem {
                    id: c.id,
                    pubkey: c.pubkey,
                    token: c.token,
                    amount: c.amount,
                    zk_proof: c.zk_proof,
                    status: c.status,
                    by: c.by,
                })
                .collect(),
        })
    }

    /// Deposits `plaintext_amount` of `token` into the depositor's account.
    ///
    /// Generates a fresh blinding factor for the new Cash and a separate one
    /// for the (placeholder) bridge commitment, runs rapidsnark to produce the
    /// deposit proof, sends the writing request to chain, and on success
    /// appends the new Cash to the local store so the wallet can spend it.
    ///
    /// `circuit_handle` carries the compiled `deposit.circom` artifacts;
    /// `zkey` is the path to the rapidsnark proving key. Both come from a
    /// `lib_zk::setup::DevSetup` (or a production ceremony output).
    ///
    /// Returns `(cash_id, output_random_hex)` so the caller can persist the
    /// random alongside the cash for future spend operations.
    pub async fn deposit(
        &self,
        token: &str,
        plaintext_amount: u64,
        circuit_handle: &zk::test_circuit::TestCircuitHandle,
        zkey: &std::path::Path,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        use rand::RngCore;

        let mut output_random = [0u8; 32];
        let mut r_bridge = [0u8; 32];
        rand::rng().fill_bytes(&mut output_random);
        rand::rng().fill_bytes(&mut r_bridge);

        let dp = zk::wallet::prove_deposit(
            zk::wallet::DepositWitness {
                deposit_amount: plaintext_amount,
                r_bridge,
                output_amount: plaintext_amount,
                output_random,
            },
            circuit_handle,
            zkey,
        )?;

        let cash_id =
            crate::orderbook::compute_cash_id(&self.pubkey_hex, token, &dp.output_commitment_hex);

        let params = DepositParams {
            pubkey: self.pubkey_hex.clone(),
            token: token.to_string(),
            bridge_commitment: dp.bridge_commitment_hex,
            output_commitment: dp.output_commitment_hex,
            zk_proof: serde_json::to_string(&dp.proof_json)?,
        };
        self.client
            .write_chain("account", "Deposit", &params, self.chain_id, 100, 0)
            .await?;

        Ok((cash_id, hex::encode(output_random)))
    }

    /// Withdraws `plaintext_amount` of `token` to the destination chain.
    /// Spends `input_records` (must total ≥ `plaintext_amount`), generates a
    /// rapidsnark withdraw proof binding the hidden amount to a fresh
    /// bridge_out commitment, and submits the writing request.
    ///
    /// On success returns `Some((change_cash_id, change_random_hex))` if a
    /// change Cash was minted, or `None` if the inputs covered the withdraw
    /// exactly. The caller is responsible for updating the local CashStore.
    ///
    /// Errors out (without touching chain) if `input_records` is empty, has
    /// more than 2 entries (matches the N=2 circuit), or doesn't cover the
    /// requested amount.
    pub async fn withdraw(
        &self,
        token: &str,
        plaintext_amount: u64,
        input_records: &[crate::cash_store::CashRecord],
        circuit_handle: &zk::test_circuit::TestCircuitHandle,
        zkey: &std::path::Path,
    ) -> Result<Option<(String, String)>, Box<dyn std::error::Error>> {
        use rand::RngCore;

        if input_records.is_empty() || input_records.len() > 2 {
            return Err(format!(
                "withdraw circuit takes 1..=2 inputs, got {}",
                input_records.len()
            )
            .into());
        }
        let input_total: u64 = input_records.iter().map(|r| r.amount).sum();
        if input_total < plaintext_amount {
            return Err(format!(
                "input cash totals {input_total}, need at least {plaintext_amount}"
            )
            .into());
        }
        let change_amount = input_total - plaintext_amount;

        // Decode each record's stored random hex back into 32-byte BE form.
        let mut inputs_for_witness: Vec<(u64, [u8; 32])> = Vec::with_capacity(input_records.len());
        for rec in input_records {
            let raw = hex::decode(&rec.random)?;
            if raw.len() != 32 {
                return Err(format!(
                    "cash {} random must decode to 32 bytes, got {}",
                    rec.cash_id,
                    raw.len()
                )
                .into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            inputs_for_witness.push((rec.amount, arr));
        }

        let mut r_bridge_out = [0u8; 32];
        let mut change_random = [0u8; 32];
        rand::rng().fill_bytes(&mut r_bridge_out);
        rand::rng().fill_bytes(&mut change_random);

        let wp = zk::wallet::prove_withdraw(
            zk::wallet::WithdrawWitness {
                withdraw_amount: plaintext_amount,
                r_bridge_out,
                inputs: inputs_for_witness,
                change_amount,
                change_random,
            },
            circuit_handle,
            zkey,
        )?;

        // Always M=2 outputs: slot[0] = change (or zero pad if no change),
        // slot[1] = zero pad. The chain detects "no change" by comparing
        // slot[0] against the well-known PoseidonZeroCommitmentHex constant.
        let zero_commitment_hex =
            zk::wallet::fr_to_hex(&zk::wallet::poseidon_commit(0, &[0u8; 32]));
        let output_commitments = vec![
            wp.change_commitment_hex.clone(),
            zero_commitment_hex.clone(),
        ];

        let params = WithdrawParams {
            pubkey: self.pubkey_hex.clone(),
            token: token.to_string(),
            inputs: input_records.iter().map(|r| r.cash_id.clone()).collect(),
            bridge_out_commitment: wp.bridge_out_commitment_hex,
            output_commitments,
            change_pubkey: String::new(), // chain defaults to req.Pubkey
            zk_proof: serde_json::to_string(&wp.proof_json)?,
        };
        self.client
            .write_chain("account", "Withdraw", &params, self.chain_id, 100, 0)
            .await?;

        if change_amount == 0 {
            Ok(None)
        } else {
            let change_cash_id = crate::orderbook::compute_cash_id(
                &self.pubkey_hex,
                token,
                &wp.change_commitment_hex,
            );
            Ok(Some((change_cash_id, hex::encode(change_random))))
        }
    }

    // ────────────────────── Shielded pool ──────────────────────

    /// Submits a NoteDeposit writing: mint one shielded note from a bridged
    /// value. The caller pre-computes the commitments and proof (see
    /// `note_prover::prove_note_deposit`) and MUST have durably persisted
    /// the note's opening before calling (persist-before-publish).
    pub async fn note_deposit(
        &self,
        token: &str,
        bridge_commitment_hex: &str,
        output_commitment_hex: &str,
        bridge_sig_hex: &str,
        zk_proof_json: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = NoteDepositParams {
            token: token.to_string(),
            bridge_commitment: bridge_commitment_hex.to_string(),
            output_commitment: output_commitment_hex.to_string(),
            bridge_sig: bridge_sig_hex.to_string(),
            zk_proof: zk_proof_json.to_string(),
        };
        self.client
            .write_chain("account", "NoteDeposit", &params, self.chain_id, 100, 0)
            .await
    }

    /// Submits a NoteWithdraw writing: spend two note slots, withdraw
    /// through the bridge, mint the change note. Same persist-before-publish
    /// obligation for the change note's opening.
    pub async fn note_withdraw(
        &self,
        token: &str,
        anchor_hex: &str,
        nullifiers_hex: [String; 2],
        bridge_out_commitment_hex: &str,
        change_commitment_hex: &str,
        zk_proof_json: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = NoteWithdrawParams {
            token: token.to_string(),
            anchor: anchor_hex.to_string(),
            nullifiers: nullifiers_hex.to_vec(),
            bridge_out_commitment: bridge_out_commitment_hex.to_string(),
            change_commitment: change_commitment_hex.to_string(),
            zk_proof: zk_proof_json.to_string(),
        };
        self.client
            .write_chain("account", "NoteWithdraw", &params, self.chain_id, 100, 0)
            .await
    }

    /// Reads a range of pool leaves (limit 0 = all from `start_index`).
    pub async fn get_notes(
        &self,
        start_index: u64,
        limit: i64,
    ) -> Result<NotesResponse, Box<dyn std::error::Error>> {
        let value: Value = self
            .client
            .read_chain(
                "account",
                "GetNotes",
                &serde_json::json!({"start_index": start_index, "limit": limit}),
            )
            .await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Reads the pool's current leaf count and root.
    pub async fn get_pool_info(&self) -> Result<PoolInfoResponse, Box<dyn std::error::Error>> {
        let value: Value = self
            .client
            .read_chain("account", "GetPoolInfo", &serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Reads spent-ness for each queried nullifier.
    pub async fn get_nullifiers(
        &self,
        nullifiers: &[String],
    ) -> Result<Vec<bool>, Box<dyn std::error::Error>> {
        let value: Value = self
            .client
            .read_chain(
                "account",
                "GetNullifiers",
                &serde_json::json!({"nullifiers": nullifiers}),
            )
            .await?;
        #[derive(Deserialize)]
        struct Resp {
            spent: Vec<bool>,
        }
        let resp: Resp = serde_json::from_value(value)?;
        Ok(resp.spent)
    }

    /// Looks up a commitment's leaf index (recovery flows; -1 = absent).
    pub async fn get_note_by_cm(&self, cm_hex: &str) -> Result<i64, Box<dyn std::error::Error>> {
        let value: Value = self
            .client
            .read_chain("account", "GetNoteByCm", &serde_json::json!({"cm": cm_hex}))
            .await?;
        #[derive(Deserialize)]
        struct Resp {
            leaf_index: i64,
        }
        let resp: Resp = serde_json::from_value(value)?;
        Ok(resp.leaf_index)
    }

    /// Subscribe to on-chain order events via WebSocket.
    ///
    /// Returns an `mpsc::Receiver<OrderEvent>` that yields confirmed orders or
    /// chain-reported errors, plus a `JoinHandle` for the background task.
    pub async fn subscribe_order_events(
        &self,
    ) -> Result<
        (
            tokio::sync::mpsc::Receiver<OrderEvent>,
            tokio::task::JoinHandle<()>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use futures_util::StreamExt;
        use tokio_tungstenite::connect_async;

        let url = format!("{}/subscribe/results", self.ws_url);
        let (ws_stream, _) = connect_async(url.as_str()).await?;
        let (_, mut read) = ws_stream.split();

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        let handle = tokio::spawn(async move {
            use base64::Engine;

            eprintln!("[ws] subscription connected");
            while let Some(Ok(msg)) = read.next().await {
                let Ok(text) = msg.into_text() else { continue };
                let Ok(receipt) = serde_json::from_str::<YuReceipt>(&text) else {
                    eprintln!(
                        "[ws] failed to parse receipt: {}",
                        &text[..text.len().min(200)]
                    );
                    continue;
                };
                eprintln!(
                    "[ws] receipt: tripod={:?} writing={:?} error={:?} events={}",
                    receipt.tripod_name,
                    receipt.writing_name,
                    receipt.error,
                    receipt.events.len()
                );
                if receipt.tripod_name.as_deref() != Some("orderbook") {
                    continue;
                }
                if receipt.writing_name.as_deref() != Some("SendOrder") {
                    continue;
                }
                if !receipt.error.is_empty() {
                    let _ = tx.send(OrderEvent::Error(receipt.error)).await;
                    continue;
                }
                for event in receipt.events {
                    // Go encodes []byte as base64 — decode first
                    let decoded =
                        match base64::engine::general_purpose::STANDARD.decode(&event.value) {
                            Ok(d) => d,
                            Err(e) => {
                                eprintln!("[ws] base64 decode failed: {e}");
                                continue;
                            }
                        };
                    match serde_json::from_slice::<ChainOrderEvent>(&decoded) {
                        Ok(chain_event) => {
                            let _ = tx
                                .send(OrderEvent::Confirmed(query_item_to_order(
                                    chain_event.order,
                                )))
                                .await;
                            if let Some(matched) = chain_event.matched {
                                let _ = tx
                                    .send(OrderEvent::Confirmed(query_item_to_order(matched)))
                                    .await;
                            }
                        }
                        Err(e) => {
                            let _ = tx
                                .send(OrderEvent::Error(format!(
                                    "Failed to parse chain event: {e}"
                                )))
                                .await;
                        }
                    }
                }
            }
        });

        Ok((rx, handle))
    }
}

// ────────────────────── Helpers ──────────────────────

fn query_item_to_order(item: QueryOrderItem) -> Order {
    let trade_type = match item.trade_type {
        0 => TradeType::Buy,
        _ => TradeType::Sell,
    };
    let status = match item.status {
        0 => OrderStatus::Pending,
        1 => OrderStatus::Matched,
        2 => OrderStatus::Done,
        3 => OrderStatus::Cancelled,
        5 => OrderStatus::Settling,
        _ => OrderStatus::Frozen,
    };
    Order {
        id: item.id,
        trade_type,
        subject: TradePair {
            token1: item.subject.token1,
            token2: item.subject.token2,
        },
        price: item.price,
        amount: item.amount,
        pubkey: item.pubkey,
        locked_commitment: item.locked_commitment,
        fee: item.fee,
        block_height: item.block_height,
        intra_block_index: item.intra_block_index,
        status,
        match_order: item.match_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a SettleCoZkParams with the given `cmp` and six distinct dummy
    /// 64-char commitments; signature and proof fields are left empty.
    fn test_params(cmp: i8) -> CompareParams {
        CompareParams {
            order_a_id: "order-a-id".to_string(),
            order_b_id: "order-b-id".to_string(),
            cmp,
            sig_a: String::new(),
            sig_b: String::new(),
            zk_proof: String::new(),
        }
    }

    /// Byte-lockstep check against a hand-concatenated 2p compare message
    /// for every `cmp` sign; `cmp_str` mirrors Go's `strconv.Itoa`.
    #[test]
    fn compare_cozk2p_message_lockstep() {
        for (cmp, cmp_str) in [(-1i8, "-1"), (0i8, "0"), (1i8, "1")] {
            let p = test_params(cmp);
            let expected = String::from("invisibook-cozk2p-compare-v2:")
                + &p.order_a_id
                + ":"
                + &p.order_b_id
                + ":"
                + cmp_str;
            assert_eq!(compare_cozk2p_message(&p), expected.into_bytes());
        }
    }

    #[test]
    fn compare_messages_are_domain_separated() {
        let p = test_params(1);
        assert_ne!(compare_cozk_message(&p), compare_cozk2p_message(&p));
    }

    /// The settle signing messages are length-prefixed and domain-separated
    /// (lockstep with Go core.settleSigMessage: u32-BE length per field).
    #[test]
    fn settle_messages_lockstep() {
        let small = SettleSmallParams {
            order_id: "order-b-id".into(),
            match_order_id: "order-a-id".into(),
            cm_note_out: "77".repeat(32),
            signature: String::new(),
            zk_proof: String::new(),
        };
        let msg = settle_small_message(&small);
        let mut expected = Vec::new();
        for f in [
            "invisibook-settle-small-v1",
            "order-b-id",
            "order-a-id",
            &"77".repeat(32),
        ] {
            expected.extend_from_slice(&(f.len() as u32).to_be_bytes());
            expected.extend_from_slice(f.as_bytes());
        }
        assert_eq!(msg, expected);

        let large = SettleLargeParams {
            order_id: "order-a-id".into(),
            match_order_id: "order-b-id".into(),
            cm_q_residual: "88".repeat(32),
            cm_locked_residual: "99".repeat(32),
            cm_note_out: "aa".repeat(32),
            signature: String::new(),
            zk_proof: String::new(),
        };
        assert_ne!(settle_large_message(&large), settle_small_message(&small));
    }

    /// SettlePair wire JSON must match the Go request: a fully filled leg
    /// omits the residual fields (Go `omitempty`), a larger leg includes
    /// them, and the field names line up with the Go json tags.
    #[test]
    fn settle_pair_leg_json_lockstep() {
        let small = SettlePairLegParams::small("11".repeat(32), "sig-b".into(), "pf".into());
        let sj = serde_json::to_value(&small).unwrap();
        assert!(sj.get("cm_q_residual").is_none(), "small leg must omit residual q");
        assert!(
            sj.get("cm_locked_residual").is_none(),
            "small leg must omit residual collateral"
        );
        assert_eq!(sj["cm_note_out"], "11".repeat(32));

        let large = SettlePairLegParams::large(
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "sig-a".into(),
            "pf".into(),
        );
        let lj = serde_json::to_value(&large).unwrap();
        assert_eq!(lj["cm_q_residual"], "33".repeat(32));
        assert_eq!(lj["cm_locked_residual"], "44".repeat(32));

        let pair = SettlePairParams {
            order_a_id: "order-a".into(),
            order_b_id: "order-b".into(),
            a: large,
            b: small,
        };
        let pj = serde_json::to_value(&pair).unwrap();
        assert_eq!(pj["order_a_id"], "order-a");
        assert_eq!(pj["order_b_id"], "order-b");
        assert!(pj.get("a").is_some() && pj.get("b").is_some());
    }

    /// sign_compare_cozk2p output must verify under verify_compare_cozk2p_sig,
    /// and any tampering must fail verification without panicking.
    #[test]
    fn sign_verify_compare_cozk2p_roundtrip() {
        let seed = [7u8; 32];
        let client = ChainClient::new("http://localhost:7999", "ws://localhost:8999", seed, 1926);
        let params = test_params(1);

        let sig = client.sign_compare_cozk2p(&params);
        assert!(verify_compare_cozk2p_sig(
            &params,
            client.pubkey_hex(),
            &sig
        ));

        let mut bad_sig = hex::decode(&sig).unwrap();
        bad_sig[0] ^= 0x01;
        assert!(!verify_compare_cozk2p_sig(
            &params,
            client.pubkey_hex(),
            &hex::encode(bad_sig)
        ));

        let other = test_params(-1);
        assert!(!verify_compare_cozk2p_sig(
            &other,
            client.pubkey_hex(),
            &sig
        ));

        // A Groth16-domain signature must not verify in the 2p domain.
        let sig_3p = client.sign(&compare_cozk_message(&params));
        assert!(!verify_compare_cozk2p_sig(
            &params,
            client.pubkey_hex(),
            &sig_3p
        ));

        assert!(!verify_compare_cozk2p_sig(&params, "zz", &sig));
        assert!(!verify_compare_cozk2p_sig(
            &params,
            client.pubkey_hex(),
            "zz"
        ));
    }

    fn full_send_order_params() -> SendOrderParams {
        SendOrderParams {
            id: "order-1".to_string(),
            trade_type: 0,
            subject: TradePairJson {
                token1: "ETH".to_string(),
                token2: "USDT".to_string(),
            },
            price: Some(3500),
            amount: "a".repeat(64),
            pubkey: "alice-pk".to_string(),
            signature: String::new(),
            anchor: "b".repeat(64),
            input_nullifiers: vec!["c".repeat(64), "d".repeat(64)],
            locked_commitment: "e".repeat(64),
            fee: 7,
            change_commitment: "f".repeat(64),
            zk_proof: String::new(),
        }
    }

    /// Byte-lockstep with Go core.SendOrderSigningMessage (v2): the frozen
    /// vector below was recomputed from the shared layout and the Go test
    /// asserts the identical bytes.
    #[test]
    fn send_order_signing_message_lockstep_vectors() {
        let want = "00000018696e76697369626f6f6b2d73656e642d6f726465722d7632000000076f726465722d3100000001300000000345544800000004555344540000000433353030000000406161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000008616c6963652d706b00000040626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620000004063636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363000000406464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646400000040656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565650000000800000000000000070000004066666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666";
        assert_eq!(
            hex::encode(send_order_signing_message(&full_send_order_params())),
            want
        );
    }

    /// The signature and zk proof are excluded from the message; every
    /// order-defining field changes it.
    #[test]
    fn send_order_signing_message_field_coverage() {
        let base = send_order_signing_message(&full_send_order_params());

        let mut signed = full_send_order_params();
        signed.signature = "ff".repeat(64);
        signed.zk_proof = "proof".to_string();
        assert_eq!(send_order_signing_message(&signed), base);

        let mut priced = full_send_order_params();
        priced.price = Some(1);
        assert_ne!(send_order_signing_message(&priced), base);

        let mut refeed = full_send_order_params();
        refeed.fee = 999_999;
        assert_ne!(send_order_signing_message(&refeed), base);
    }
}
