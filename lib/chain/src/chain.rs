use serde::{Deserialize, Serialize};
use serde_json::Value;
use yu_sdk::{KeyPair, YuClient};

use crate::types::*;

// Re-export KeyPair so consumers don't need to depend on yu-sdk directly.
pub use yu_sdk::KeyPair as YuKeyPair;

// ────────────────────── Request/Response Types ──────────────────────

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
}

#[derive(Debug, Serialize)]
struct TradePairJson {
    token1: TokenID,
    token2: TokenID,
}

#[derive(Debug, Serialize)]
struct SettleOrderParams {
    order_ids: Vec<OrderID>,
    outputs: Vec<CashOutputParams>,
    zk_proof: String,
}

#[derive(Debug, Serialize)]
struct CashOutputParams {
    pubkey: String, // recipient's ed25519 pubkey (64-char hex)
    token: TokenID,
    amount: CipherText,
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
    pub price: Option<u64>,
    pub amount: CipherText,
    pub pubkey: String,
    pub input_cash_ids: Vec<String>,
    pub status: u8,
    #[serde(default)]
    pub match_order: Option<String>,
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
    amount: CipherText,
    zk_proof: String,
}

#[derive(Debug, Serialize)]
struct WithdrawParams {
    token: TokenID,
    inputs: Vec<String>,
    change: ChangeOutputParams,
    zk_proof: String,
}

#[derive(Debug, Serialize)]
struct ChangeOutputParams {
    pubkey: String,
    amount: CipherText,
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
/// `value` is a base64-encoded JSON payload (Go encodes []byte as base64).
#[derive(Deserialize)]
struct YuEvent {
    value: Vec<u8>, // serde_json auto-decodes base64 → raw bytes
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
    pub async fn send_order(
        &self,
        order: &Order,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        };
        self.client
            .write_chain("orderbook", "SendOrder", &params, self.chain_id, 100, 0)
            .await
    }

    /// Requests settlement of a matched order pair (writing request to OrderBook.SettleOrder).
    pub async fn settle_order(
        &self,
        order_ids: Vec<OrderID>,
        outputs: Vec<CashOutput>,
        zk_proof: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = SettleOrderParams {
            order_ids,
            outputs: outputs
                .into_iter()
                .map(|o| CashOutputParams {
                    pubkey: o.pubkey,
                    token: o.token,
                    amount: o.amount,
                })
                .collect(),
            zk_proof: zk_proof.to_string(),
        };
        self.client
            .write_chain("orderbook", "SettleOrder", &params, self.chain_id, 100, 0)
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
            }),
            limit,
            offset,
        };
        let value: Value = self
            .client
            .read_chain("orderbook", "QueryOrders", &params)
            .await?;
        let resp: QueryOrdersResponse = serde_json::from_value(value)?;
        Ok(resp
            .orders
            .into_iter()
            .map(query_item_to_order)
            .collect())
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

    /// Deposits funds into an account (requires zk proof of bridge deposit).
    pub async fn deposit(
        &self,
        pubkey: &str,
        token: &str,
        amount: &str,
        zk_proof: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = DepositParams {
            pubkey: pubkey.to_string(),
            token: token.to_string(),
            amount: amount.to_string(),
            zk_proof: zk_proof.to_string(),
        };
        self.client
            .write_chain("account", "Deposit", &params, self.chain_id, 100, 0)
            .await
    }

    /// Withdraws funds from the account (requires zk proof that amount <= balance).
    pub async fn withdraw(
        &self,
        token: &str,
        inputs: Vec<String>,
        change: ChangeOutput,
        zk_proof: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = WithdrawParams {
            token: token.to_string(),
            inputs,
            change: ChangeOutputParams {
                pubkey: change.pubkey,
                amount: change.amount,
            },
            zk_proof: zk_proof.to_string(),
        };
        self.client
            .write_chain("account", "Withdraw", &params, self.chain_id, 100, 0)
            .await
    }

    /// Subscribe to on-chain order events via WebSocket.
    ///
    /// Returns an `mpsc::Receiver<Order>` that yields confirmed orders as they
    /// are included in blocks, plus a `JoinHandle` for the background task.
    /// Each `SendOrder` tx emits one "created" event (and optionally one
    /// "matched" event) — both are forwarded as separate `Order` values.
    pub async fn subscribe_order_events(
        &self,
    ) -> Result<
        (tokio::sync::mpsc::Receiver<Order>, tokio::task::JoinHandle<()>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use futures_util::StreamExt;
        use tokio_tungstenite::connect_async;

        let url = format!("{}/subscribe/results", self.ws_url);
        let (ws_stream, _) = connect_async(url.as_str()).await?;
        let (_, mut read) = ws_stream.split();

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        let handle = tokio::spawn(async move {
            while let Some(Ok(msg)) = read.next().await {
                let Ok(text) = msg.into_text() else { continue };
                let Ok(receipt) = serde_json::from_str::<YuReceipt>(&text) else {
                    continue;
                };
                if receipt.tripod_name.as_deref() != Some("orderbook") {
                    continue;
                }
                if receipt.writing_name.as_deref() != Some("SendOrder") {
                    continue;
                }
                if !receipt.error.is_empty() {
                    continue; // tx failed on-chain, ignore
                }
                for event in receipt.events {
                    let Ok(chain_event) =
                        serde_json::from_slice::<ChainOrderEvent>(&event.value)
                    else {
                        continue;
                    };
                    let _ = tx.send(query_item_to_order(chain_event.order)).await;
                    if let Some(matched) = chain_event.matched {
                        let _ = tx.send(query_item_to_order(matched)).await;
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
        handling_fee: Vec::new(),
        status,
        match_order: item.match_order,
    }
}
