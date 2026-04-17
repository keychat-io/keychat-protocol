//! Cashu provider — multi-mint Cashu backend backed by CDK 0.15.1.
//!
//! A single `CashuProvider` instance manages all of a user's mints. Each mint
//! is a separate `cdk::wallet::Wallet` stored in its own SQLite database under
//! the provider's `db_dir`, keyed by mint URL.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip39::Mnemonic;
use cdk::amount::SplitTarget;
use cdk::cdk_database;
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod, ProofsMethods};
use cdk::wallet::{ReceiveOptions, SendOptions, Wallet, WalletBuilder};
use cdk_common::database::WalletDatabase;
use cdk_common::wallet::TransactionDirection as CdkDirection;
use cdk_sqlite::WalletSqliteDatabase;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::error::{Result, WalletError};
use crate::provider::WalletProvider;
use crate::types::{
    MeltResult, MintQuote, MintQuoteStatus, TransactionStatus, WalletAccount, WalletProtocol,
    WalletTransaction,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn normalise_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

fn safe_db_name(url: &str) -> String {
    url.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn derive_display_name(mint_url: &str) -> String {
    // Strip scheme and take the host portion; fall back to the raw URL.
    let without_scheme = mint_url
        .strip_prefix("https://")
        .or_else(|| mint_url.strip_prefix("http://"))
        .unwrap_or(mint_url);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(mint_url)
        .to_string()
}

// ── CashuProvider ────────────────────────────────────────────────────────────

/// Multi-mint Cashu wallet provider.
///
/// All mints share the same BIP-39 seed (so a single restore covers them all)
/// but each mint has its own SQLite database file under `db_dir`.
pub struct CashuProvider {
    db_dir: String,
    seed: [u8; 64],
    /// mint URL (normalised, no trailing slash) → CDK wallet.
    mints: RwLock<HashMap<String, Wallet>>,
}

impl CashuProvider {
    /// Create an empty `CashuProvider`. Call [`add_account`](Self::add_account)
    /// (or the inherent [`add_mint`](Self::add_mint)) to register mints.
    ///
    /// * `db_dir` — directory where per-mint SQLite DBs are placed. Use
    ///   `":memory:"` to force in-memory databases for every mint (tests).
    /// * `seed` — BIP-39 seed bytes.
    pub fn new(db_dir: impl Into<String>, seed: [u8; 64]) -> Self {
        Self {
            db_dir: db_dir.into(),
            seed,
            mints: RwLock::new(HashMap::new()),
        }
    }

    /// Convenience constructor that converts a mnemonic to seed.
    pub fn from_mnemonic(db_dir: impl Into<String>, mnemonic: &str) -> Result<Self> {
        let parsed = Mnemonic::from_str(mnemonic)?;
        Ok(Self::new(db_dir, parsed.to_seed("")))
    }

    fn db_path_for(&self, normalised_url: &str) -> String {
        if self.db_dir == ":memory:" {
            ":memory:".to_string()
        } else {
            format!("{}/{}.db", self.db_dir, safe_db_name(normalised_url))
        }
    }

    /// Build a CDK wallet for `mint_url` (normalised) and return it along with
    /// the parsed `MintUrl`.
    async fn build_wallet(&self, normalised_url: &str) -> Result<(Wallet, MintUrl)> {
        let mint_url = MintUrl::from_str(normalised_url)?;
        let db_path = self.db_path_for(normalised_url);

        let localstore: Arc<dyn WalletDatabase<cdk_database::Error> + Send + Sync> =
            Arc::new(WalletSqliteDatabase::new(db_path.as_str()).await?);

        if localstore.get_mint(mint_url.clone()).await?.is_none() {
            localstore.add_mint(mint_url.clone(), None).await?;
        }

        let wallet = WalletBuilder::new()
            .mint_url(mint_url.clone())
            .unit(CurrencyUnit::Sat)
            .localstore(localstore)
            .seed(self.seed)
            .build()?;

        Ok((wallet, mint_url))
    }

    /// Register a Cashu mint explicitly (same as `add_account` but with a
    /// name that reads better at call sites outside the trait).
    pub async fn add_mint(&self, mint_url: &str) -> Result<bool> {
        self.add_account(mint_url).await
    }

    /// Fetch the CDK wallet for `mint_url` (normalised or not).
    async fn wallet_for(&self, mint_url: &str) -> Result<Wallet> {
        let key = normalise_url(mint_url);
        self.mints
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or(WalletError::MintNotFound(key))
    }

    async fn account_from_wallet(&self, mint_url: &str, wallet: &Wallet) -> WalletAccount {
        let balance_sats = wallet
            .total_balance()
            .await
            .map(|a| *a.as_ref())
            .unwrap_or(0);
        WalletAccount {
            id: mint_url.to_string(),
            display_name: derive_display_name(mint_url),
            subtitle: mint_url.to_string(),
            protocol: WalletProtocol::Cashu,
            balance_sats,
            can_send: balance_sats > 0,
            can_receive: true,
            supports_lightning: true,
        }
    }

    // ── Cashu-specific inherent methods (NOT part of the trait) ──────────────

    /// Prepare and serialise a Cashu token for `amount` sats from `mint_url`.
    pub async fn send_token(&self, mint_url: &str, amount: u64) -> Result<String> {
        if amount == 0 {
            return Err(WalletError::Other("Cannot send 0 sats".into()));
        }
        let wallet = self.wallet_for(mint_url).await?;
        let balance = *wallet.total_balance().await?.as_ref();
        if balance < amount {
            return Err(WalletError::InsufficientFunds {
                needed: amount,
                available: balance,
            });
        }
        let prepared = wallet
            .prepare_send(amount.into(), SendOptions::default())
            .await?;
        let token = prepared.confirm(None).await?;
        let token_str = token.to_string();
        info!("Sent {} sats on {} — token len={}", amount, mint_url, token_str.len());
        Ok(token_str)
    }

    /// Redeem an incoming token string on `mint_url`. Returns amount received.
    pub async fn receive_token(&self, mint_url: &str, token: &str) -> Result<u64> {
        let wallet = self.wallet_for(mint_url).await?;
        let amount = wallet.receive(token, ReceiveOptions::default()).await?;
        let sats = *amount.as_ref();
        info!("Received {} sats on {}", sats, mint_url);
        Ok(sats)
    }

    /// Request a Lightning-invoice mint quote.
    pub async fn mint_quote(&self, mint_url: &str, amount: u64) -> Result<MintQuote> {
        if amount == 0 {
            return Err(WalletError::Other("Cannot mint 0 sats".into()));
        }
        let wallet = self.wallet_for(mint_url).await?;
        let quote = wallet
            .mint_quote(PaymentMethod::BOLT11, Some(amount.into()), None, None)
            .await?;
        info!("Mint quote {} for {} sats on {}", quote.id, amount, mint_url);
        Ok(MintQuote {
            id: quote.id,
            invoice: quote.request,
            amount,
            expiry: quote.expiry,
        })
    }

    /// Poll a mint quote's current state.
    pub async fn check_mint_quote(
        &self,
        mint_url: &str,
        quote_id: &str,
    ) -> Result<MintQuoteStatus> {
        let wallet = self.wallet_for(mint_url).await?;
        let quote = wallet.check_mint_quote_status(quote_id).await?;
        Ok(match quote.state {
            MintQuoteState::Unpaid => MintQuoteStatus::Pending,
            MintQuoteState::Paid | MintQuoteState::Issued => MintQuoteStatus::Paid,
        })
    }

    /// Claim tokens after a Lightning invoice has been paid.
    pub async fn mint_tokens(&self, mint_url: &str, quote_id: &str) -> Result<u64> {
        let wallet = self.wallet_for(mint_url).await?;
        let proofs = wallet.mint(quote_id, SplitTarget::default(), None).await?;
        let amount: u64 = *proofs
            .total_amount()
            .map_err(|e| WalletError::Other(e.to_string()))?
            .as_ref();
        info!("Minted {} sats (quote={}, mint={})", amount, quote_id, mint_url);
        Ok(amount)
    }

    /// Pay a Lightning invoice by melting ecash. Returns a [`MeltResult`].
    ///
    /// This is the raw CDK melt — the trait's `pay_invoice` wraps it in a
    /// [`WalletTransaction`].
    pub async fn melt(&self, mint_url: &str, invoice: &str) -> Result<MeltResult> {
        let wallet = self.wallet_for(mint_url).await?;
        let quote = wallet
            .melt_quote(PaymentMethod::BOLT11, invoice, None, None)
            .await?;
        let fee = *quote.fee_reserve.as_ref();
        info!("Melt quote {} fee_reserve={}", quote.id, fee);

        let prepared = wallet.prepare_melt(&quote.id, HashMap::new()).await?;
        let finalized = prepared.confirm().await?;
        let paid = finalized.state() == cdk::nuts::MeltQuoteState::Paid;
        let preimage = finalized.payment_proof().map(str::to_string);
        let fee_paid = *finalized.fee_paid().as_ref();

        info!("Melt done — paid={} fee_paid={}", paid, fee_paid);
        Ok(MeltResult {
            paid,
            preimage,
            fee: fee_paid,
        })
    }

    /// Restore wallet state for every registered mint.
    ///
    /// Returns the sum of unspent sats across all mints.
    pub async fn restore_all(&self) -> Result<u64> {
        let mints = self.mints.read().await;
        let mut total = 0u64;
        for (url, wallet) in mints.iter() {
            match wallet.restore().await {
                Ok(restored) => {
                    let sats: u64 = *restored.unspent.as_ref();
                    info!(
                        "restore[{}] unspent={} spent={} pending={}",
                        url,
                        sats,
                        *restored.spent.as_ref(),
                        *restored.pending.as_ref()
                    );
                    total += sats;
                }
                Err(e) => debug!("restore[{}] failed: {}", url, e),
            }
        }
        Ok(total)
    }
}

// ── WalletProvider impl ──────────────────────────────────────────────────────

#[async_trait]
impl WalletProvider for CashuProvider {
    fn protocol_type(&self) -> WalletProtocol {
        WalletProtocol::Cashu
    }

    async fn list_accounts(&self) -> Result<Vec<WalletAccount>> {
        let mints = self.mints.read().await;
        let mut out = Vec::with_capacity(mints.len());
        for (url, wallet) in mints.iter() {
            out.push(self.account_from_wallet(url, wallet).await);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn refresh(&self) -> Result<()> {
        // CDK wallets re-read from their local store on every query, so a
        // refresh is a no-op at the provider level.
        Ok(())
    }

    async fn refresh_account(&self, account_id: &str) -> Result<Option<WalletAccount>> {
        let key = normalise_url(account_id);
        let mints = self.mints.read().await;
        if let Some(wallet) = mints.get(&key) {
            Ok(Some(self.account_from_wallet(&key, wallet).await))
        } else {
            Ok(None)
        }
    }

    async fn add_account(&self, connection_string: &str) -> Result<bool> {
        if !self.can_handle(connection_string) {
            return Err(WalletError::Other(format!(
                "CashuProvider cannot handle connection string: {}",
                connection_string
            )));
        }
        let key = normalise_url(connection_string);
        // Fast path: already added.
        if self.mints.read().await.contains_key(&key) {
            return Ok(false);
        }
        let (wallet, mint_url) = self.build_wallet(&key).await?;
        self.mints.write().await.insert(key.clone(), wallet);
        info!("CashuProvider added mint: {}", mint_url);
        Ok(true)
    }

    async fn remove_account(&self, account_id: &str) -> Result<()> {
        let key = normalise_url(account_id);
        self.mints.write().await.remove(&key);
        info!("CashuProvider removed mint: {}", key);
        Ok(())
    }

    async fn transactions(
        &self,
        account_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<WalletTransaction>> {
        // Merge three CDK sources into a unified list:
        //   1. wallet.list_transactions()       → completed rows
        //   2. wallet.get_pending_melt_quotes() → in-flight outbound Lightning
        //   3. localstore.get_mint_quotes()     → outstanding Lightning top-ups
        let wallet = self.wallet_for(account_id).await?;
        let key = normalise_url(account_id);
        let mut out: Vec<WalletTransaction> = Vec::new();

        for tx in wallet.list_transactions(None).await? {
            let is_incoming = matches!(tx.direction, CdkDirection::Incoming);
            let raw_amount = *tx.amount.as_ref() as i64;
            let amount_sats = if is_incoming { raw_amount } else { -raw_amount };
            out.push(WalletTransaction {
                id: tx.id().to_string(),
                account_id: Some(key.clone()),
                amount_sats,
                timestamp: tx.timestamp,
                description: None,
                status: TransactionStatus::Success,
                is_incoming,
                protocol: WalletProtocol::Cashu,
                preimage: None,
                payment_hash: None,
                fee_sats: Some(*tx.fee.as_ref()),
                invoice: tx.payment_request,
            });
        }

        // Pending outbound Lightning (melt in-flight). MeltQuote has no
        // mint_url field in CDK 0.15.1 — filter by unit to scope to this
        // wallet's currency.
        for q in wallet.get_pending_melt_quotes().await? {
            if q.unit != wallet.unit {
                continue;
            }
            let amount = *q.amount.as_ref();
            out.push(WalletTransaction {
                id: q.id,
                account_id: Some(key.clone()),
                amount_sats: -(amount as i64),
                timestamp: q.expiry,
                description: None,
                status: TransactionStatus::Pending,
                is_incoming: false,
                protocol: WalletProtocol::Cashu,
                preimage: None,
                payment_hash: None,
                fee_sats: Some(*q.fee_reserve.as_ref()),
                invoice: Some(q.request),
            });
        }

        // Pending inbound Lightning (mint quote awaiting invoice payment).
        for q in wallet.localstore.get_mint_quotes().await? {
            if q.mint_url != wallet.mint_url || q.unit != wallet.unit {
                continue;
            }
            if q.state != MintQuoteState::Unpaid {
                continue;
            }
            // `amount` is Option<Amount> because BOLT12 offers can be
            // amountless; BOLT11 quotes always carry it. Default to 0.
            let amount = q.amount.map(|a| *a.as_ref()).unwrap_or(0);
            out.push(WalletTransaction {
                id: q.id,
                account_id: Some(key.clone()),
                amount_sats: amount as i64,
                timestamp: q.expiry,
                description: None,
                status: TransactionStatus::Pending,
                is_incoming: true,
                protocol: WalletProtocol::Cashu,
                preimage: None,
                payment_hash: None,
                fee_sats: Some(0),
                invoice: Some(q.request),
            });
        }

        out.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(out.into_iter().skip(offset).take(limit).collect())
    }

    fn can_handle(&self, connection_string: &str) -> bool {
        connection_string.starts_with("http://") || connection_string.starts_with("https://")
    }

    async fn pay_invoice(
        &self,
        account_id: &str,
        bolt11: &str,
    ) -> Result<WalletTransaction> {
        let result = self.melt(account_id, bolt11).await?;
        let status = if result.paid {
            TransactionStatus::Success
        } else {
            TransactionStatus::Failed
        };
        // The CDK melt path does not expose an amount for the outbound tx
        // directly in `MeltResult`. Fee + paid flag are the stable outputs;
        // callers can read full history via `transactions()` afterwards.
        Ok(WalletTransaction {
            id: format!("melt-{}", bolt11.len()),
            account_id: Some(normalise_url(account_id)),
            amount_sats: 0,
            timestamp: now_secs(),
            description: None,
            status,
            is_incoming: false,
            protocol: WalletProtocol::Cashu,
            preimage: result.preimage,
            payment_hash: None,
            fee_sats: Some(result.fee),
            invoice: Some(bolt11.to_string()),
        })
    }

    async fn create_invoice(
        &self,
        account_id: &str,
        amount_sats: u64,
        _description: Option<&str>,
    ) -> Result<String> {
        let quote = self.mint_quote(account_id, amount_sats).await?;
        Ok(quote.invoice)
    }

    async fn create_invoice_with_transaction(
        &self,
        account_id: &str,
        amount_sats: u64,
        description: Option<&str>,
    ) -> Result<WalletTransaction> {
        let quote = self.mint_quote(account_id, amount_sats).await?;
        Ok(WalletTransaction {
            id: quote.id,
            account_id: Some(normalise_url(account_id)),
            amount_sats: amount_sats as i64,
            timestamp: now_secs(),
            description: description.map(str::to_string),
            status: TransactionStatus::Pending,
            is_incoming: true,
            protocol: WalletProtocol::Cashu,
            preimage: None,
            payment_hash: None,
            fee_sats: None,
            invoice: Some(quote.invoice),
        })
    }

    async fn total_balance(&self) -> Result<u64> {
        let mints = self.mints.read().await;
        let mut total = 0u64;
        for (url, wallet) in mints.iter() {
            match wallet.total_balance().await {
                Ok(a) => total += *a.as_ref(),
                Err(e) => debug!("balance[{}] failed: {}", url, e),
            }
        }
        Ok(total)
    }

    fn is_loading(&self) -> bool {
        false
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MINT_A: &str = "https://testnut.cashu.space";
    const MINT_B: &str = "https://mint.minibits.cash/Bitcoin";

    async fn make_provider_with_mint(mint_url: &str) -> CashuProvider {
        let provider = CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap();
        provider.add_account(mint_url).await.expect("add_account");
        provider
    }

    #[tokio::test]
    async fn cashu_provider_new_empty() {
        let provider = CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap();
        assert_eq!(provider.protocol_type(), WalletProtocol::Cashu);
        assert!(provider.list_accounts().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cashu_provider_file_db() {
        let dir = tempdir().unwrap();
        let provider = CashuProvider::from_mnemonic(
            dir.path().to_str().unwrap().to_string(),
            MNEMONIC,
        )
        .unwrap();
        provider.add_account(MINT_A).await.expect("add_account");
        let accounts = provider.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, MINT_A);
    }

    #[tokio::test]
    async fn cashu_manages_multiple_mints() {
        let provider = CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap();
        provider.add_account(MINT_A).await.unwrap();
        provider.add_account(MINT_B).await.unwrap();
        let accounts = provider.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 2);
        let ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&MINT_A));
        assert!(ids.contains(&MINT_B));
    }

    #[tokio::test]
    async fn cashu_account_id_is_mint_url() {
        let provider = make_provider_with_mint(MINT_A).await;
        let accounts = provider.list_accounts().await.unwrap();
        assert_eq!(accounts[0].id, MINT_A);
        assert_eq!(accounts[0].protocol, WalletProtocol::Cashu);
    }

    #[tokio::test]
    async fn cashu_balance_zero_fresh() {
        let provider = make_provider_with_mint(MINT_A).await;
        let balance = provider.total_balance().await.unwrap();
        assert_eq!(balance, 0);
    }

    #[tokio::test]
    async fn cashu_send_zero_errors() {
        let provider = make_provider_with_mint(MINT_A).await;
        let result = provider.send_token(MINT_A, 0).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("0 sats"));
    }

    #[tokio::test]
    async fn cashu_send_insufficient_funds() {
        let provider = make_provider_with_mint(MINT_A).await;
        let result = provider.send_token(MINT_A, 1).await;
        assert!(matches!(
            result.unwrap_err(),
            WalletError::InsufficientFunds { .. }
        ));
    }

    #[tokio::test]
    async fn cashu_receive_invalid_token_rejected() {
        let provider = make_provider_with_mint(MINT_A).await;
        let result = provider.receive_token(MINT_A, "not-a-valid-cashu-token").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cashu_transactions_empty_fresh() {
        let provider = make_provider_with_mint(MINT_A).await;
        let txs = provider.transactions(MINT_A, 100, 0).await.unwrap();
        assert!(txs.is_empty());
    }

    #[tokio::test]
    async fn cashu_transactions_surface_pending_mint_quote() {
        use cdk::Amount;
        use cdk_common::wallet::MintQuote as CdkMintQuote;

        let provider = make_provider_with_mint(MINT_A).await;
        let wallet = provider.wallet_for(MINT_A).await.unwrap();

        let quote = CdkMintQuote::new(
            "test-pending-quote".to_string(),
            wallet.mint_url.clone(),
            PaymentMethod::BOLT11,
            Some(Amount::from(1000u64)),
            CurrencyUnit::Sat,
            "lnbc10u1ptestbolt11invoice".to_string(),
            4_102_444_800,
            None,
        );
        wallet
            .localstore
            .add_mint_quote(quote)
            .await
            .expect("add_mint_quote");

        let txs = provider.transactions(MINT_A, 100, 0).await.unwrap();
        assert_eq!(txs.len(), 1);
        let tx = &txs[0];
        assert_eq!(tx.id, "test-pending-quote");
        assert_eq!(tx.status, TransactionStatus::Pending);
        assert!(tx.is_incoming);
        assert_eq!(tx.amount_sats, 1000);
        assert_eq!(tx.invoice.as_deref(), Some("lnbc10u1ptestbolt11invoice"));
    }

    #[tokio::test]
    async fn cashu_can_handle_http_urls() {
        let provider = CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap();
        assert!(provider.can_handle("https://mint.example.com"));
        assert!(provider.can_handle("http://localhost:3338"));
        assert!(!provider.can_handle("nostr+walletconnect://abcdef"));
        assert!(!provider.can_handle("lndconnect://127.0.0.1:10009"));
    }

    #[tokio::test]
    async fn cashu_add_account_idempotent() {
        let provider = CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap();
        assert!(provider.add_account(MINT_A).await.unwrap());
        // Second add returns false (already present) and does not duplicate.
        assert!(!provider.add_account(MINT_A).await.unwrap());
        assert_eq!(provider.list_accounts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cashu_remove_account() {
        let provider = make_provider_with_mint(MINT_A).await;
        provider.remove_account(MINT_A).await.unwrap();
        assert!(provider.list_accounts().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cashu_refresh_account_roundtrip() {
        let provider = make_provider_with_mint(MINT_A).await;
        let acct = provider.refresh_account(MINT_A).await.unwrap();
        assert!(acct.is_some());
        assert_eq!(acct.unwrap().id, MINT_A);

        let missing = provider.refresh_account("https://ghost.example").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn cashu_add_account_rejects_non_http() {
        let provider = CashuProvider::from_mnemonic(":memory:", MNEMONIC).unwrap();
        let err = provider.add_account("nostr+walletconnect://abc").await;
        assert!(err.is_err());
    }
}
