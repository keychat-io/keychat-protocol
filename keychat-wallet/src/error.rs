use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    /// General CDK / protocol error.
    #[error("CDK error: {0}")]
    Cdk(#[from] cdk::Error),

    /// SQLite / storage layer error.
    #[error("CDK database error: {0}")]
    CdkDatabase(#[from] cdk_common::database::Error),

    #[error("BIP39 error: {0}")]
    Bip39(#[from] bip39::Error),

    #[error("Invalid mint URL: {0}")]
    InvalidMintUrl(#[from] cdk::mint_url::Error),

    #[error("Wallet not initialized")]
    NotInitialized,

    #[error("Mint not found: {0}")]
    MintNotFound(String),

    #[error("No default mint configured")]
    NoDefaultMint,

    #[error("Insufficient funds: need {needed} sats, have {available} sats")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Quote not found: {0}")]
    QuoteNotFound(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, WalletError>;
