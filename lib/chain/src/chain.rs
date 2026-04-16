use serde::{Deserialize, Serialize};
use serde_json::Value;
use yu_sdk::{KeyPair, YuClient};

use crate::types::*;

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
}

#[derive(Debug, Serialize)]
struct TradePairJson {
    token1: TokenID,
    token2: TokenID,
}

#[derive(Debug, Serialize)]
struct SettleOrderParams {
    order_ids: Vec<OrderID>,
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
    pub status: u8,
}

#[derive(Debug, Deserialize)]
pub struct QueryTradePair {
    pub token1: TokenID,
    pub token2: TokenID,
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
        };
        self.client
            .write_chain("orderbook", "SendOrder", &params, 100, 0)
            .await
    }

    /// Requests settlement of a list of matched orders (writing request to OrderBook.SettleOrder).
    pub async fn settle_order(
        &self,
        order_ids: Vec<OrderID>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = SettleOrderParams { order_ids };
        self.client
            .write_chain("orderbook", "SettleOrder", &params, 100, 0)
            .await
    }

    /// Queries orders from the chain with optional filters and pagination.
    pub async fn query_orders(
        &self,
        id: Option<OrderID>,
        trade_type: Option<TradeType>,
        token1: Option<TokenID>,
        token2: Option<TokenID>,
        status: Option<OrderStatus>,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
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
        self.client
            .read_chain("orderbook", "QueryOrders", &params)
            .await
    }
}
