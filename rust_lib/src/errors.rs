use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Crypto error")]
    CryptoError,

    #[error("Configuration error")]
    ConfigError(String),

    #[error("Unknown error")]
    Unknown,
}


impl From<ring::error::Unspecified> for AppError {
    fn from(_: ring::error::Unspecified) -> Self { AppError::CryptoError }
}



pub type Result<T> = std::result::Result<T, AppError>;
