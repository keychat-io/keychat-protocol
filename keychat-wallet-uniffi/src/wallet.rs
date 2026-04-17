//! UniFFI bindings for the unified wallet API.

use std::sync::Arc;

use keychat_wallet::{
    cashu::CashuProvider, seed_from_mnemonic, MeltResult, MintQuote, MintQuoteStatus,
    TransactionStatus, WalletAccount, WalletProtocol, WalletProvider, WalletTransaction,
};

use crate::error::WalletUniError;

// ─── UniFFI Record types ─────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct UniWalletAccount {
    pub id: String,
    pub display_name: String,
    pub subtitle: String,
    pub protocol: UniWalletProtocol,
    pub balance_sats: u64,
    pub can_send: bool,
    pub can_receive: bool,
    pub supports_lightning: bool,
}

#[derive(uniffi::Record)]
pub struct UniWalletTransaction {
    pub id: String,
    pub account_id: Option<String>,
    pub amount_sats: i64,
    pub timestamp: u64,
    pub description: Option<String>,
    pub status: UniTransactionStatus,
    pub is_incoming: bool,
    pub protocol: UniWalletProtocol,
    pub preimage: Option<String>,
    pub payment_hash: Option<String>,
    pub fee_sats: Option<u64>,
    pub invoice: Option<String>,
}

#[derive(uniffi::Record)]
pub struct UniMintQuote {
    pub id: String,
    pub invoice: String,
    pub amount: u64,
    pub expiry: u64,
}

#[derive(uniffi::Record)]
pub struct UniMeltResult {
    pub paid: bool,
    pub preimage: Option<String>,
    pub fee: u64,
}

// ─── UniFFI Enums ────────────────────────────────────────────────────────────

#[derive(uniffi::Enum)]
pub enum UniWalletProtocol {
    Cashu,
    Nwc,
    Lnd,
    LightningPub,
    Ark,
}

#[derive(uniffi::Enum)]
pub enum UniTransactionStatus {
    Pending,
    Success,
    Failed,
    Expired,
}

#[derive(uniffi::Enum)]
pub enum UniMintQuoteStatus {
    Pending,
    Paid,
    Expired,
}

// ─── Conversions ─────────────────────────────────────────────────────────────

fn to_uni_protocol(p: WalletProtocol) -> UniWalletProtocol {
    match p {
        WalletProtocol::Cashu => UniWalletProtocol::Cashu,
        WalletProtocol::Nwc => UniWalletProtocol::Nwc,
        WalletProtocol::Lnd => UniWalletProtocol::Lnd,
        WalletProtocol::LightningPub => UniWalletProtocol::LightningPub,
        WalletProtocol::Ark => UniWalletProtocol::Ark,
    }
}

fn to_uni_status(s: TransactionStatus) -> UniTransactionStatus {
    match s {
        TransactionStatus::Pending => UniTransactionStatus::Pending,
        TransactionStatus::Success => UniTransactionStatus::Success,
        TransactionStatus::Failed => UniTransactionStatus::Failed,
        TransactionStatus::Expired => UniTransactionStatus::Expired,
    }
}

fn to_uni_quote_status(s: MintQuoteStatus) -> UniMintQuoteStatus {
    match s {
        MintQuoteStatus::Pending => UniMintQuoteStatus::Pending,
        MintQuoteStatus::Paid => UniMintQuoteStatus::Paid,
        MintQuoteStatus::Expired => UniMintQuoteStatus::Expired,
    }
}

fn to_uni_account(a: WalletAccount) -> UniWalletAccount {
    UniWalletAccount {
        id: a.id,
        display_name: a.display_name,
        subtitle: a.subtitle,
        protocol: to_uni_protocol(a.protocol),
        balance_sats: a.balance_sats,
        can_send: a.can_send,
        can_receive: a.can_receive,
        supports_lightning: a.supports_lightning,
    }
}

fn to_uni_transaction(t: WalletTransaction) -> UniWalletTransaction {
    UniWalletTransaction {
        id: t.id,
        account_id: t.account_id,
        amount_sats: t.amount_sats,
        timestamp: t.timestamp,
        description: t.description,
        status: to_uni_status(t.status),
        is_incoming: t.is_incoming,
        protocol: to_uni_protocol(t.protocol),
        preimage: t.preimage,
        payment_hash: t.payment_hash,
        fee_sats: t.fee_sats,
        invoice: t.invoice,
    }
}

fn to_uni_mint_quote(q: MintQuote) -> UniMintQuote {
    UniMintQuote {
        id: q.id,
        invoice: q.invoice,
        amount: q.amount,
        expiry: q.expiry,
    }
}

fn to_uni_melt_result(r: MeltResult) -> UniMeltResult {
    UniMeltResult {
        paid: r.paid,
        preimage: r.preimage,
        fee: r.fee,
    }
}

// ─── WalletClient ────────────────────────────────────────────────────────────

/// UniFFI-exposed wallet client.
///
/// One `WalletClient` wraps a single `CashuProvider` today. NWC/LND/Ark
/// providers will extend this by holding a `WalletManager` with multiple
/// providers; the current trait shape already supports that — we just keep
/// v1 narrow because only Cashu ships.
#[derive(uniffi::Object)]
pub struct WalletClient {
    cashu: Arc<CashuProvider>,
}

#[uniffi::export(async_runtime = "tokio")]
impl WalletClient {
    /// Create a new `WalletClient`.
    ///
    /// The mnemonic is converted to a BIP-39 seed immediately and dropped;
    /// only the seed is retained.
    #[uniffi::constructor]
    pub fn new(db_dir: String, mnemonic: String) -> Result<Self, WalletUniError> {
        let seed = seed_from_mnemonic(&mnemonic)?;
        drop(mnemonic);
        Ok(Self {
            cashu: Arc::new(CashuProvider::new(db_dir, seed)),
        })
    }

    // ── Trait methods ────────────────────────────────────────────────────────

    /// List every account this client knows about.
    pub async fn list_accounts(&self) -> Result<Vec<UniWalletAccount>, WalletUniError> {
        Ok(self
            .cashu
            .list_accounts()
            .await?
            .into_iter()
            .map(to_uni_account)
            .collect())
    }

    /// Refresh all accounts.
    pub async fn refresh(&self) -> Result<(), WalletUniError> {
        self.cashu.refresh().await?;
        Ok(())
    }

    /// Refresh one specific account.
    pub async fn refresh_account(
        &self,
        account_id: String,
    ) -> Result<Option<UniWalletAccount>, WalletUniError> {
        Ok(self
            .cashu
            .refresh_account(&account_id)
            .await?
            .map(to_uni_account))
    }

    /// Add an account by parsing the connection string.
    pub async fn add_account(&self, connection_string: String) -> Result<bool, WalletUniError> {
        Ok(self.cashu.add_account(&connection_string).await?)
    }

    /// Remove an account.
    pub async fn remove_account(&self, account_id: String) -> Result<(), WalletUniError> {
        self.cashu.remove_account(&account_id).await?;
        Ok(())
    }

    /// Paginated transaction history for one account.
    pub async fn transactions(
        &self,
        account_id: String,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<UniWalletTransaction>, WalletUniError> {
        Ok(self
            .cashu
            .transactions(&account_id, limit as usize, offset as usize)
            .await?
            .into_iter()
            .map(to_uni_transaction)
            .collect())
    }

    /// `true` if the underlying provider can parse the given connection string.
    pub fn can_handle(&self, connection_string: String) -> bool {
        self.cashu.can_handle(&connection_string)
    }

    /// Pay a BOLT11 invoice from `account_id`.
    pub async fn pay_invoice(
        &self,
        account_id: String,
        bolt11: String,
    ) -> Result<UniWalletTransaction, WalletUniError> {
        Ok(to_uni_transaction(
            self.cashu.pay_invoice(&account_id, &bolt11).await?,
        ))
    }

    /// Create a BOLT11 invoice; returns the raw invoice string.
    pub async fn create_invoice(
        &self,
        account_id: String,
        amount_sats: u64,
        description: Option<String>,
    ) -> Result<String, WalletUniError> {
        Ok(self
            .cashu
            .create_invoice(&account_id, amount_sats, description.as_deref())
            .await?)
    }

    /// Create a BOLT11 invoice and return the full transaction record.
    pub async fn create_invoice_with_transaction(
        &self,
        account_id: String,
        amount_sats: u64,
        description: Option<String>,
    ) -> Result<UniWalletTransaction, WalletUniError> {
        Ok(to_uni_transaction(
            self.cashu
                .create_invoice_with_transaction(&account_id, amount_sats, description.as_deref())
                .await?,
        ))
    }

    /// Protocol this client handles.
    pub fn protocol_type(&self) -> UniWalletProtocol {
        to_uni_protocol(self.cashu.protocol_type())
    }

    /// Sum of balances across every account.
    pub async fn total_balance(&self) -> Result<u64, WalletUniError> {
        Ok(self.cashu.total_balance().await?)
    }

    /// Whether the provider is currently initialising. Cashu is always false.
    pub fn is_loading(&self) -> bool {
        self.cashu.is_loading()
    }

    // ── Cashu-specific inherent methods ──────────────────────────────────────

    /// Prepare and serialise a Cashu token.
    pub async fn send_token(
        &self,
        account_id: String,
        amount: u64,
    ) -> Result<String, WalletUniError> {
        Ok(self.cashu.send_token(&account_id, amount).await?)
    }

    /// Redeem an incoming token string. Returns sats received.
    pub async fn receive_token(
        &self,
        account_id: String,
        token: String,
    ) -> Result<u64, WalletUniError> {
        Ok(self.cashu.receive_token(&account_id, &token).await?)
    }

    /// Request a Lightning-invoice mint quote.
    pub async fn mint_quote(
        &self,
        account_id: String,
        amount: u64,
    ) -> Result<UniMintQuote, WalletUniError> {
        Ok(to_uni_mint_quote(
            self.cashu.mint_quote(&account_id, amount).await?,
        ))
    }

    /// Poll a mint quote.
    pub async fn check_mint_quote(
        &self,
        account_id: String,
        quote_id: String,
    ) -> Result<UniMintQuoteStatus, WalletUniError> {
        Ok(to_uni_quote_status(
            self.cashu.check_mint_quote(&account_id, &quote_id).await?,
        ))
    }

    /// Claim tokens after the Lightning invoice is paid.
    pub async fn mint_tokens(
        &self,
        account_id: String,
        quote_id: String,
    ) -> Result<u64, WalletUniError> {
        Ok(self.cashu.mint_tokens(&account_id, &quote_id).await?)
    }

    /// Pay a Lightning invoice via Cashu melt (raw CDK melt result).
    pub async fn melt(
        &self,
        account_id: String,
        invoice: String,
    ) -> Result<UniMeltResult, WalletUniError> {
        Ok(to_uni_melt_result(
            self.cashu.melt(&account_id, &invoice).await?,
        ))
    }

    /// Restore wallet state across all mints from the BIP-39 seed.
    /// Returns total unspent sats recovered.
    pub async fn restore(&self) -> Result<u64, WalletUniError> {
        Ok(self.cashu.restore_all().await?)
    }
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

    fn make_client() -> WalletClient {
        WalletClient::new(":memory:".to_string(), MNEMONIC.to_string())
            .expect("WalletClient::new")
    }

    #[tokio::test]
    async fn client_starts_with_no_accounts() {
        let client = make_client();
        assert!(client.list_accounts().await.unwrap().is_empty());
        assert_eq!(client.total_balance().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn client_protocol_type_is_cashu() {
        let client = make_client();
        assert!(matches!(client.protocol_type(), UniWalletProtocol::Cashu));
    }

    #[tokio::test]
    async fn client_is_loading_false() {
        let client = make_client();
        assert!(!client.is_loading());
    }

    #[tokio::test]
    async fn client_new_rejects_invalid_mnemonic() {
        let result = WalletClient::new(":memory:".to_string(), "not a valid mnemonic".into());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn client_new_with_file_db_dir() {
        let dir = tempdir().unwrap();
        let client = WalletClient::new(
            dir.path().to_str().unwrap().to_string(),
            MNEMONIC.to_string(),
        )
        .unwrap();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let accounts = client.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, MINT_A);
    }

    #[tokio::test]
    async fn client_add_account_adds_mint() {
        let client = make_client();
        assert!(client.add_account(MINT_A.to_string()).await.unwrap());
        let accounts = client.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, MINT_A);
        assert!(matches!(accounts[0].protocol, UniWalletProtocol::Cashu));
    }

    #[tokio::test]
    async fn client_add_account_idempotent() {
        let client = make_client();
        assert!(client.add_account(MINT_A.to_string()).await.unwrap());
        assert!(!client.add_account(MINT_A.to_string()).await.unwrap());
        assert_eq!(client.list_accounts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn client_add_account_rejects_non_http() {
        let client = make_client();
        let err = client
            .add_account("nostr+walletconnect://x".to_string())
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn client_remove_account_drops_mint() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        client.remove_account(MINT_A.to_string()).await.unwrap();
        assert!(client.list_accounts().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn client_refresh_account_returns_account() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let account = client.refresh_account(MINT_A.to_string()).await.unwrap();
        assert!(account.is_some());
        assert_eq!(account.unwrap().id, MINT_A);
    }

    #[tokio::test]
    async fn client_refresh_account_unknown_returns_none() {
        let client = make_client();
        let account = client.refresh_account("https://ghost".to_string()).await.unwrap();
        assert!(account.is_none());
    }

    #[tokio::test]
    async fn client_can_handle_http_urls() {
        let client = make_client();
        assert!(client.can_handle("https://m.example".to_string()));
        assert!(client.can_handle("http://localhost".to_string()));
        assert!(!client.can_handle("nostr+walletconnect://x".to_string()));
    }

    #[tokio::test]
    async fn client_send_token_zero_errors() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let result = client.send_token(MINT_A.to_string(), 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn client_send_token_insufficient_funds_mapped() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let err = client.send_token(MINT_A.to_string(), 1).await.unwrap_err();
        assert!(matches!(
            err,
            WalletUniError::InsufficientFunds { .. }
        ));
    }

    #[tokio::test]
    async fn client_receive_token_rejects_garbage() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let result = client
            .receive_token(MINT_A.to_string(), "garbage".to_string())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn client_transactions_empty_fresh() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let txs = client.transactions(MINT_A.to_string(), 100, 0).await.unwrap();
        assert!(txs.is_empty());
    }

    #[tokio::test]
    async fn client_transactions_missing_mint_errors_as_mint_not_found() {
        let client = make_client();
        let result = client
            .transactions("https://ghost.example".to_string(), 10, 0)
            .await;
        match result {
            Err(WalletUniError::MintNotFound { .. }) => {}
            Err(other) => panic!("expected MintNotFound, got: {}", other),
            Ok(_) => panic!("expected MintNotFound, got Ok"),
        }
    }

    #[tokio::test]
    async fn client_multiple_mints_listed() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        client.add_account(MINT_B.to_string()).await.unwrap();
        let accounts = client.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 2);
    }

    #[tokio::test]
    async fn client_total_balance_across_mints() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        client.add_account(MINT_B.to_string()).await.unwrap();
        assert_eq!(client.total_balance().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn client_account_subtitle_contains_mint_url() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let accounts = client.list_accounts().await.unwrap();
        assert_eq!(accounts[0].subtitle, MINT_A);
    }

    #[tokio::test]
    async fn client_account_fresh_cannot_send() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let accounts = client.list_accounts().await.unwrap();
        // Fresh wallet, balance = 0 → cannot send.
        assert!(!accounts[0].can_send);
        assert!(accounts[0].can_receive);
        assert!(accounts[0].supports_lightning);
    }

    #[tokio::test]
    async fn client_account_balance_is_u64_zero() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let accounts = client.list_accounts().await.unwrap();
        assert_eq!(accounts[0].balance_sats, 0u64);
    }

    #[tokio::test]
    async fn client_mint_quote_zero_errors() {
        let client = make_client();
        client.add_account(MINT_A.to_string()).await.unwrap();
        let result = client.mint_quote(MINT_A.to_string(), 0).await;
        assert!(result.is_err());
    }
}
