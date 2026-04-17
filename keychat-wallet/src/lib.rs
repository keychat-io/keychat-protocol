//! Keychat wallet — unified multi-protocol wallet library.
//!
//! Mirrors the Flutter `unified_wallet` architecture:
//!
//!   * [`WalletProvider`] — one implementation per protocol (Cashu, NWC, LND, …)
//!     managing N accounts.
//!   * [`WalletAccount`] — a single account inside a protocol (one mint, one
//!     NWC connection, one LND node).
//!   * [`WalletTransaction`] — unified signed-amount transaction record.
//!   * [`WalletManager`] — registry + router across providers.
//!
//! Only [`cashu::CashuProvider`] is implemented today. NWC and Ark providers
//! are planned; the trait is designed to fit them without changes.

pub mod cashu;
pub mod error;
pub mod manager;
pub mod provider;
pub mod types;

use std::str::FromStr;

pub use error::{Result, WalletError};
pub use manager::WalletManager;
pub use provider::WalletProvider;
pub use types::{
    MeltResult, MintQuote, MintQuoteStatus, TransactionStatus, WalletAccount, WalletProtocol,
    WalletTransaction,
};

/// Derive a BIP-39 seed from a mnemonic phrase.
///
/// Exposed so upstream crates (e.g. the UniFFI layer) can convert the
/// mnemonic to a seed without depending on `bip39` directly, keeping the
/// plaintext phrase scoped to a short-lived local variable.
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<[u8; 64]> {
    let parsed = bip39::Mnemonic::from_str(mnemonic)?;
    Ok(parsed.to_seed(""))
}
