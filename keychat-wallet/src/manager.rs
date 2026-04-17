//! `WalletManager` — aggregates multiple `WalletProvider`s (one per protocol).
//!
//! Mirrors the Flutter `UnifiedWalletController` role: route `connection_string`
//! dispatches to the right provider via `can_handle`, aggregate balances
//! across all providers, enumerate every account.

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::debug;

use crate::error::{Result, WalletError};
use crate::provider::WalletProvider;
use crate::types::{WalletAccount, WalletProtocol};

/// Registry of `WalletProvider` instances.
///
/// Providers are stored behind `Arc<dyn WalletProvider>` so callers can clone
/// handles cheaply. At most one provider per protocol should be registered
/// in practice, but the manager does not enforce that.
#[derive(Default)]
pub struct WalletManager {
    providers: RwLock<Vec<Arc<dyn WalletProvider>>>,
}

impl WalletManager {
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(Vec::new()),
        }
    }

    /// Register a provider. No-op if an `Arc` pointer-equal provider is
    /// already registered.
    pub async fn register_provider(&self, provider: Arc<dyn WalletProvider>) {
        let mut guard = self.providers.write().await;
        if !guard.iter().any(|p| Arc::ptr_eq(p, &provider)) {
            guard.push(provider);
        }
    }

    /// All providers currently registered.
    pub async fn providers(&self) -> Vec<Arc<dyn WalletProvider>> {
        self.providers.read().await.clone()
    }

    /// Return the provider matching `protocol`, if any.
    pub async fn provider_for_protocol(
        &self,
        protocol: WalletProtocol,
    ) -> Option<Arc<dyn WalletProvider>> {
        self.providers
            .read()
            .await
            .iter()
            .find(|p| p.protocol_type() == protocol)
            .cloned()
    }

    /// Return the first provider whose `can_handle` accepts `connection_string`.
    pub async fn find_provider_for(
        &self,
        connection_string: &str,
    ) -> Option<Arc<dyn WalletProvider>> {
        self.providers
            .read()
            .await
            .iter()
            .find(|p| p.can_handle(connection_string))
            .cloned()
    }

    /// List every account across every provider (in registration order).
    pub async fn list_all_accounts(&self) -> Result<Vec<WalletAccount>> {
        let providers = self.providers.read().await.clone();
        let mut out = Vec::new();
        for p in providers.iter() {
            match p.list_accounts().await {
                Ok(mut accs) => out.append(&mut accs),
                Err(e) => debug!("list_accounts[{:?}] failed: {}", p.protocol_type(), e),
            }
        }
        Ok(out)
    }

    /// Sum of `total_balance()` across every provider (errors treated as 0).
    pub async fn total_balance(&self) -> Result<u64> {
        let providers = self.providers.read().await.clone();
        let mut total = 0u64;
        for p in providers.iter() {
            match p.total_balance().await {
                Ok(b) => total += b,
                Err(e) => debug!("total_balance[{:?}] failed: {}", p.protocol_type(), e),
            }
        }
        Ok(total)
    }

    /// Route an `add_account` call to the first matching provider.
    pub async fn add_account(&self, connection_string: &str) -> Result<bool> {
        let provider = self
            .find_provider_for(connection_string)
            .await
            .ok_or_else(|| {
                WalletError::Other(format!(
                    "no provider can handle connection string: {}",
                    connection_string
                ))
            })?;
        provider.add_account(connection_string).await
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cashu::CashuProvider;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MINT_A: &str = "https://testnut.cashu.space";
    const MINT_B: &str = "https://mint.minibits.cash/Bitcoin";

    async fn fresh_cashu() -> Arc<CashuProvider> {
        Arc::new(CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap())
    }

    #[tokio::test]
    async fn manager_empty_by_default() {
        let manager = WalletManager::new();
        assert!(manager.providers().await.is_empty());
        assert!(manager.list_all_accounts().await.unwrap().is_empty());
        assert_eq!(manager.total_balance().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn manager_register_and_lookup_by_protocol() {
        let manager = WalletManager::new();
        let cashu = fresh_cashu().await;
        manager.register_provider(cashu.clone()).await;

        let found = manager.provider_for_protocol(WalletProtocol::Cashu).await;
        assert!(found.is_some());
        assert!(manager
            .provider_for_protocol(WalletProtocol::Nwc)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn manager_find_by_connection_string() {
        let manager = WalletManager::new();
        manager.register_provider(fresh_cashu().await).await;

        assert!(manager.find_provider_for(MINT_A).await.is_some());
        assert!(manager.find_provider_for("nostr+walletconnect://x").await.is_none());
    }

    #[tokio::test]
    async fn manager_add_account_routes_to_cashu() {
        let manager = WalletManager::new();
        manager.register_provider(fresh_cashu().await).await;

        assert!(manager.add_account(MINT_A).await.unwrap());
        assert_eq!(manager.list_all_accounts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn manager_add_account_unknown_scheme_errors() {
        let manager = WalletManager::new();
        manager.register_provider(fresh_cashu().await).await;

        let err = manager.add_account("nostr+walletconnect://x").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn manager_total_balance_sums_across_providers() {
        let manager = WalletManager::new();
        let cashu_a = fresh_cashu().await;
        let cashu_b = fresh_cashu().await;
        cashu_a.add_account(MINT_A).await.unwrap();
        cashu_b.add_account(MINT_B).await.unwrap();
        manager.register_provider(cashu_a).await;
        manager.register_provider(cashu_b).await;

        // Fresh wallets → 0 + 0 = 0.
        assert_eq!(manager.total_balance().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn manager_list_all_accounts_across_mints() {
        let manager = WalletManager::new();
        let cashu = fresh_cashu().await;
        cashu.add_account(MINT_A).await.unwrap();
        cashu.add_account(MINT_B).await.unwrap();
        manager.register_provider(cashu).await;

        let accounts = manager.list_all_accounts().await.unwrap();
        assert_eq!(accounts.len(), 2);
    }

    #[tokio::test]
    async fn manager_register_provider_idempotent() {
        let manager = WalletManager::new();
        let cashu = fresh_cashu().await;
        manager.register_provider(cashu.clone()).await;
        manager.register_provider(cashu.clone()).await;
        assert_eq!(manager.providers().await.len(), 1);
    }
}
