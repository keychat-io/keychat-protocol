//! Unified `WalletProvider` trait.
//!
//! This trait mirrors the Flutter `WalletProvider` interface in
//! `unified_wallet/providers/wallet_provider.dart`. One provider implementation
//! per protocol (Cashu, NWC, LND, Ark) — each provider internally manages
//! many accounts.

use async_trait::async_trait;

use crate::error::Result;
use crate::types::{WalletAccount, WalletProtocol, WalletTransaction};

/// Common interface implemented by every wallet backend.
///
/// Methods on this trait are truly protocol-agnostic: list/add/remove accounts,
/// pay & create Lightning invoices, list transactions. Protocol-specific
/// operations (Cashu send_token/receive_token, NWC request-response, etc.)
/// live as inherent methods on the concrete provider type — not on the trait.
#[async_trait]
pub trait WalletProvider: Send + Sync {
    /// Protocol this provider handles.
    fn protocol_type(&self) -> WalletProtocol;

    /// All accounts currently managed by this provider.
    async fn list_accounts(&self) -> Result<Vec<WalletAccount>>;

    /// Refresh all account data (balances, connection state, ...).
    async fn refresh(&self) -> Result<()>;

    /// Refresh one specific account. Returns the updated account, or `None`
    /// if no account with that id exists.
    async fn refresh_account(&self, account_id: &str) -> Result<Option<WalletAccount>>;

    /// Parse `connection_string` and add the resulting account.
    ///
    /// The connection string may contain secrets (NWC URI with secret key,
    /// LND macaroon). Providers encrypt/store these internally. The account
    /// id returned via `list_accounts` is always non-secret.
    async fn add_account(&self, connection_string: &str) -> Result<bool>;

    /// Remove the account with `account_id`.
    async fn remove_account(&self, account_id: &str) -> Result<()>;

    /// Paginated transaction history for `account_id`.
    async fn transactions(
        &self,
        account_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<WalletTransaction>>;

    /// `true` if this provider can parse `connection_string`.
    fn can_handle(&self, connection_string: &str) -> bool;

    /// Pay a BOLT11 Lightning invoice from `account_id`. Returns the
    /// resulting transaction record.
    async fn pay_invoice(
        &self,
        account_id: &str,
        bolt11: &str,
    ) -> Result<WalletTransaction>;

    /// Create a Lightning invoice on `account_id`; returns the BOLT11 string.
    async fn create_invoice(
        &self,
        account_id: &str,
        amount_sats: u64,
        description: Option<&str>,
    ) -> Result<String>;

    /// Create a Lightning invoice and return the full transaction record
    /// (useful when the caller wants immediate metadata).
    async fn create_invoice_with_transaction(
        &self,
        account_id: &str,
        amount_sats: u64,
        description: Option<&str>,
    ) -> Result<WalletTransaction>;

    /// Sum of balances across all accounts in this provider.
    async fn total_balance(&self) -> Result<u64>;

    /// Whether the provider is currently loading / initialising.
    fn is_loading(&self) -> bool;
}
