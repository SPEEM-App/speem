use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Crypto error")]
    CryptoError(#[from] ring::error::Unspecified),

    #[error("Configuration error")]
    ConfigError(String),

    #[error("Unknown error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, AppError>;
