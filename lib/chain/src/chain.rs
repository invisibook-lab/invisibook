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
    price: Option<String>,
    amount: CipherText,
    owner: String,
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
    owner: String,
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
    pub price: Option<String>,
    pub amount: CipherText,
    pub owner: String,
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
    address: String,
    token: TokenID,
}

#[derive(Debug, Serialize)]
struct DepositParams {
    address: String,
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
    owner: String,
    amount: CipherText,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    address: String,
    token: TokenID,
    #[serde(default)]
    cash: Vec<CashItemResponse>,
}

#[derive(Debug, Deserialize)]
struct CashItemResponse {
    id: String,
    owner: String,
    token: TokenID,
    amount: CipherText,
    #[serde(default)]
    zk_proof: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    by: String,
}

// ────────────────────── Chain Client ──────────────────────

pub struct ChainClient {
    client: YuClient,
}

impl ChainClient {
    /// Creates a new ChainClient connected to the given yu node.
    /// `http_url` example: "http://localhost:7999"
    /// `ws_url`   example: "ws://localhost:8999"
    pub fn new(http_url: &str, ws_url: &str, keypair: KeyPair) -> Self {
        let client = YuClient::new(http_url, ws_url).with_keypair(keypair);
        Self { client }
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
        let params = SendOrderParams {
            id: order.id.clone(),
            trade_type: type_int,
            subject: TradePairJson {
                token1: order.subject.token1.clone(),
                token2: order.subject.token2.clone(),
            },
            price: order.price.map(|p| p.to_string()),
            amount: order.amount.clone(),
            owner: order.owner.clone(),
            input_cash_ids: order.input_cash_ids.clone(),
            handling_fee: order.handling_fee.clone(),
        };
        self.client
            .write_chain("orderbook", "SendOrder", &params, 100, 0)
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
                    owner: o.owner,
                    token: o.token,
                    amount: o.amount,
                })
                .collect(),
            zk_proof: zk_proof.to_string(),
        };
        self.client
            .write_chain("orderbook", "SettleOrder", &params, 100, 0)
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

    /// Gets account details for the given address and token.
    pub async fn get_account(
        &self,
        address: &str,
        token: &str,
    ) -> Result<AccountRecord, Box<dyn std::error::Error>> {
        let params = GetAccountParams {
            address: address.to_string(),
            token: token.to_string(),
        };
        let value: Value = self
            .client
            .read_chain("account", "GetAccount", &params)
            .await?;
        let resp: AccountResponse = serde_json::from_value(value)?;
        Ok(AccountRecord {
            address: resp.address,
            token: resp.token,
            cash: resp
                .cash
                .into_iter()
                .map(|c| CashItem {
                    id: c.id,
                    owner: c.owner,
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
        address: &str,
        token: &str,
        amount: &str,
        zk_proof: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = DepositParams {
            address: address.to_string(),
            token: token.to_string(),
            amount: amount.to_string(),
            zk_proof: zk_proof.to_string(),
        };
        self.client
            .write_chain("account", "Deposit", &params, 100, 0)
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
                owner: change.owner,
                amount: change.amount,
            },
            zk_proof: zk_proof.to_string(),
        };
        self.client
            .write_chain("account", "Withdraw", &params, 100, 0)
            .await
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
        price: item.price.and_then(|p| p.parse().ok()),
        amount: item.amount,
        owner: item.owner,
        input_cash_ids: item.input_cash_ids,
        handling_fee: Vec::new(),
        status,
        match_order: item.match_order,
    }
}
