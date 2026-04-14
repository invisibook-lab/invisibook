use thiserror::Error;

#[derive(Error, Debug)]
pub enum MpcError {
    #[error("not yet implemented")]
    NotImplemented,
    #[error("protocol error: {0}")]
    Protocol(String),
}
