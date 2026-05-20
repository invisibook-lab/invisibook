use serde::{Deserialize, Serialize};
use serde_json::Value;
use yu_sdk::{KeyPair, YuClient};

use crate::types::*;

// Re-export KeyPair so consumers don't need to depend on yu-sdk directly.
pub use yu_sdk::KeyPair as YuKeyPair;

// ────────────────────── Request/Response Types ──────────────────────

#[derive(Debug, Serialize)]
struct CashChangeParam {
    cash_id: String,
    amount: CipherText,
}

#[derive(Debug, Serialize)]
struct SendOrderParams {
    id: OrderID,
    #[serde(rename = "type")]
    trade_type: u8,
    subject: TradePairJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<u64>,
    amount: CipherText,
    pubkey: String,    // sender's ed25519 pubkey (64-char hex)
    signature: String, // ed25519 sig over order ID bytes (128-char hex)
    input_cash_ids: Vec<String>,
    handling_fee: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    change: Option<CashChangeParam>,
    /// snarkjs `proof.json` for the split conservation proof. Only required
    /// when `change.is_some()`; chain rejects empty proof in split mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    zk_proof: Option<String>,
}

#[derive(Debug, Serialize)]
struct TradePairJson {
    token1: TokenID,
    token2: TokenID,
}

/// Per-party MPC share submission for the comparison phase.
#[derive(Debug, Serialize)]
struct CompareOrderParams {
    order_id: OrderID,
    match_order_id: OrderID,
    mpc_share: MpcShareParamJson,
}

/// Per-party settle submission sent to chain after comparison.
/// `leg` is required for the larger party, omitted for the smaller party.
#[derive(Debug, Serialize)]
struct SettleOrderParams {
    order_id: OrderID,
    match_order_id: OrderID,
    #[serde(skip_serializing_if = "Option::is_none")]
    leg: Option<SettleTokenLegParam>,
}

/// Serializable form of MpcShareParam for the chain JSON API.
#[derive(Debug, Serialize)]
struct MpcShareParamJson {
    cmp_share: String,
    cmp_mac: String,
    r_smaller_share: String,
    r_smaller_mac: String,
    mac_key_share: String,
}

/// Mirror of chain Go `SettleTokenLeg`. `side` is `"larger"` or `"smaller"`;
/// only the fields applicable to that side need to be populated (the rest are
/// `None` and skipped from the JSON via `serde`).
#[derive(Debug, Serialize)]
pub struct SettleTokenLegParam {
    pub side: String,
    pub token: TokenID,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub my_match_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_match_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_token2_sender: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_commitment: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub change_pubkey: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_commitment: Option<String>,

    pub recv_commitment: String,
    pub recv_pubkey: String,
    pub zk_proof: String,
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
    pub input_cash_ids: Vec<String>,
    #[serde(default)]
    pub handling_fee: Vec<String>,
    #[serde(default)]
    pub block_height: u32,
    pub status: u8,
    #[serde(default)]
    pub match_order: Option<String>,
    #[serde(default)]
    pub is_smaller: bool,
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
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// Signs `message` with the client's ed25519 private key.
    /// Returns the 64-byte signature as a 128-char hex string.
    fn sign(&self, message: &[u8]) -> String {
        let kp = KeyPair::from_ed25519_bytes(&self.seed);
        hex::encode(kp.sign(message))
    }

    /// Sends a new order to the chain (writing request to OrderBook.SendOrder).
    /// If `change` is provided, the chain will split the input cash and mint change;
    /// in that case `split_proof_json` is required (snarkjs `proof.json` from
    /// rapidsnark) — chain rejects split-mode requests without a proof.
    /// Submits a new order to the chain. When `change` is provided (split
    /// mode), `split_proof_json` must contain the ZK proof proving
    /// sum(inputs) == sum(outputs).
    pub async fn send_order(
        &self,
        order: &Order,
        change: Option<&CashChange>,
        split_proof_json: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if change.is_some() && split_proof_json.is_none() {
            return Err("split mode requires a zk_proof".into());
        }
        let type_int = match order.trade_type {
            TradeType::Buy => 0u8,
            TradeType::Sell => 1u8,
        };
        let signature = self.sign(order.id.as_bytes());
        let params = SendOrderParams {
            id: order.id.clone(),
            trade_type: type_int,
            subject: TradePairJson {
                token1: order.subject.token1.clone(),
                token2: order.subject.token2.clone(),
            },
            price: order.price,
            amount: order.amount.clone(),
            pubkey: self.pubkey_hex.clone(),
            signature,
            input_cash_ids: order.input_cash_ids.clone(),
            handling_fee: order.handling_fee.clone(),
            change: change.map(|c| CashChangeParam {
                cash_id: c.cash_id.clone(),
                amount: c.amount.clone(),
            }),
            zk_proof: split_proof_json,
        };
        self.client
            .write_chain("orderbook", "SendOrder", &params, self.chain_id, 100, 0)
            .await
    }

    /// Submits this party's MPC shares for order comparison.
    /// The chain collects both parties' shares and verifies the MAC,
    /// then sets both orders to Compared status.
    pub async fn compare_orders(
        &self,
        order_id: OrderID,
        match_order_id: OrderID,
        mpc_share: MpcShareParam,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = CompareOrderParams {
            order_id,
            match_order_id,
            mpc_share: MpcShareParamJson {
                cmp_share: mpc_share.cmp_share,
                cmp_mac: mpc_share.cmp_mac,
                r_smaller_share: mpc_share.r_smaller_share,
                r_smaller_mac: mpc_share.r_smaller_mac,
                mac_key_share: mpc_share.mac_key_share,
            },
        };
        self.client
            .write_chain("orderbook", "CompareOrders", &params, self.chain_id, 100, 0)
            .await
    }

    /// Submits this party's settlement confirmation (after comparison).
    /// The larger party (IsSmaller=false) must provide a ZK `leg`; the smaller
    /// party (IsSmaller=true) confirms without proof (`leg` is `None`).
    pub async fn settle_orders(
        &self,
        order_id: OrderID,
        match_order_id: OrderID,
        leg: Option<SettleTokenLegParam>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = SettleOrderParams {
            order_id,
            match_order_id,
            leg,
        };
        self.client
            .write_chain("orderbook", "SettleOrders", &params, self.chain_id, 100, 0)
            .await
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
        input_cash_ids: item.input_cash_ids,
        handling_fee: item.handling_fee,
        block_height: item.block_height,
        status,
        match_order: item.match_order,
        is_smaller: item.is_smaller,
    }
}
