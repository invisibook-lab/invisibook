use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("invalid elliptic curve point")]
    InvalidPoint,
    #[error("not enough beaver triples: need {need}, have {have}")]
    InsufficientTriples { need: usize, have: usize },
    #[error("protocol error: {0}")]
    Protocol(String),
}
