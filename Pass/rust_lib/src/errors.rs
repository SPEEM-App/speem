use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("Crypto error")]
    CryptoError,

    #[error("Configuration error: {0}")]
    ConfigError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Unexpected error")]
    UnexpectedError,
}

impl From<ring::error::Unspecified> for AppError {
    fn from(_: ring::error::Unspecified) -> Self { AppError::CryptoError }
}

pub type Result<T> = std::result::Result<T, AppError>;
