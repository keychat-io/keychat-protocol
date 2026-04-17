//! UniFFI layer for `keychat-wallet`.
//!
//! Standalone crate so the protocol's main UniFFI bindings (`keychat-uniffi`)
//! do not depend on wallet code. Apps that do not need a wallet can skip this
//! crate entirely.

mod error;
mod wallet;

pub use error::WalletUniError;
pub use wallet::*;

uniffi::setup_scaffolding!();
