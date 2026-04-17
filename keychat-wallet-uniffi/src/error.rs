use keychat_wallet::WalletError;

/// UniFFI error surface for the wallet layer.
///
/// Kept local to this crate so the protocol's `KeychatUniError` does not have
/// to know wallet exists.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum WalletUniError {
    #[error("Wallet error: {msg}")]
    Wallet { msg: String },

    #[error("Invalid argument: {msg}")]
    InvalidArgument { msg: String },

    #[error("Insufficient funds: need {needed} sats, have {available} sats")]
    InsufficientFunds { needed: u64, available: u64 },

    #[error("Mint not found: {id}")]
    MintNotFound { id: String },
}

impl From<WalletError> for WalletUniError {
    fn from(err: WalletError) -> Self {
        match err {
            WalletError::InsufficientFunds { needed, available } => {
                WalletUniError::InsufficientFunds { needed, available }
            }
            WalletError::MintNotFound(id) => WalletUniError::MintNotFound { id },
            other => WalletUniError::Wallet {
                msg: other.to_string(),
            },
        }
    }
}
