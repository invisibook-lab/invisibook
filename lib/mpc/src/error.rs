use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
