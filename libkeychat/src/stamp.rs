//! Ecash stamp mechanism: relay fee discovery, CDK wallet integration, and auto-stamp.
//!
//! Implements the full ecash stamp workflow per §13.1:
//! 1. Fetch relay fee rules via NIP-11 relay info document
//! 2. Cache fee rules with TTL
//! 3. Mint/manage Cashu tokens via CDK wallet
//! 4. Auto-attach ecash stamps when publishing events to paid relays

use crate::error::{KeychatError, Result};
#[cfg(feature = "cashu")]
use crate::payment::attach_ecash_stamp;
#[cfg(feature = "cashu")]
use nostr::{Event, Kind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "cashu")]
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(feature = "cashu")]
use tokio::sync::RwLock;
#[cfg(feature = "cashu")]
use tracing::{debug, warn};

// ─── NIP-11 Types ───────────────────────────────────────────────────────────

/// Fee method specifying how a relay accepts payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashuFeeMethod {
    /// Accepted mint URLs for Cashu tokens.
    #[serde(rename = "Cashu")]
    pub cashu: Option<CashuMintList>,
}

/// List of accepted Cashu mints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CashuMintList {
    pub mints: Vec<String>,
}

/// A single publication fee rule from NIP-11 relay info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFeeRule {
    /// Fee amount (e.g., 1).
    pub amount: u64,
    /// Unit (e.g., "sat").
    pub unit: String,
    /// Payment method (Cashu mints).
    pub method: Option<CashuFeeMethod>,
    /// Event kinds this fee applies to (e.g., [4, 1059]).
    pub kinds: Option<Vec<u16>>,
}

impl RelayFeeRule {
    /// Check if this rule applies to a given event kind.
    pub fn applies_to_kind(&self, kind: u16) -> bool {
        match &self.kinds {
            Some(kinds) => kinds.contains(&kind),
            None => true, // No kinds filter means applies to all
        }
    }

    /// Get the list of accepted mint URLs, if any.
    pub fn accepted_mints(&self) -> Vec<String> {
        self.method
            .as_ref()
            .and_then(|m| m.cashu.as_ref())
            .map(|c| c.mints.clone())
            .unwrap_or_default()
    }
}

/// Parsed NIP-11 relay fee information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFees {
    /// Publication fee rules.
    #[serde(default)]
    pub publication: Vec<RelayFeeRule>,
}

/// NIP-11 relay information document (fee-relevant fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Relay name.
    #[serde(default)]
    pub name: Option<String>,
    /// Fee structure.
    #[serde(default)]
    pub fees: Option<RelayFees>,
}

// ─── NIP-11 Fetch ───────────────────────────────────────────────────────────

/// Fetch NIP-11 relay information document from a relay URL.
///
/// Converts `wss://relay.example.com` to `https://relay.example.com` and
/// sends a GET request with `Accept: application/nostr+json` header.
pub async fn fetch_relay_info(relay_url: &str) -> Result<RelayInfo> {
    let http_url = relay_url_to_http(relay_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| KeychatError::Stamp(format!("HTTP client error: {e}")))?;

    let resp = client
        .get(&http_url)
        .header("Accept", "application/nostr+json")
        .send()
        .await
        .map_err(|e| KeychatError::Stamp(format!("NIP-11 fetch failed for {relay_url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(KeychatError::Stamp(format!(
            "NIP-11 fetch returned {} for {relay_url}",
            resp.status()
        )));
    }

    let info: RelayInfo = resp
        .json()
        .await
        .map_err(|e| KeychatError::Stamp(format!("NIP-11 parse failed for {relay_url}: {e}")))?;

    Ok(info)
}

/// Convert a WebSocket relay URL to an HTTP URL for NIP-11 fetching.
fn relay_url_to_http(url: &str) -> String {
    url.replace("wss://", "https://")
        .replace("ws://", "http://")
}

// ─── Fee Cache ──────────────────────────────────────────────────────────────

#[cfg(feature = "cashu")]
/// Cached fee rules for a single relay.
#[derive(Debug, Clone)]
struct CachedFees {
    rules: Vec<RelayFeeRule>,
    fetched_at: Instant,
}

#[cfg(feature = "cashu")]
/// Cache for relay fee rules with configurable TTL.
#[derive(Debug)]
struct FeeCache {
    entries: HashMap<String, CachedFees>,
    ttl: Duration,
}

#[cfg(feature = "cashu")]
impl FeeCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Store fee rules for a relay.
    fn insert(&mut self, relay_url: String, rules: Vec<RelayFeeRule>) {
        self.entries.insert(
            relay_url,
            CachedFees {
                rules,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Get fee rules for a relay, returning None if expired or missing.
    fn get(&self, relay_url: &str) -> Option<&[RelayFeeRule]> {
        self.entries.get(relay_url).and_then(|cached| {
            if cached.fetched_at.elapsed() < self.ttl {
                Some(cached.rules.as_slice())
            } else {
                None
            }
        })
    }

    /// Get the fee rule that applies to a specific event kind.
    fn get_fee_for_kind(&self, relay_url: &str, kind: u16) -> Option<RelayFeeRule> {
        self.get(relay_url)?
            .iter()
            .find(|rule| rule.applies_to_kind(kind))
            .cloned()
    }

    /// Check if a relay has cached (non-expired) fee data.
    fn has_valid(&self, relay_url: &str) -> bool {
        self.get(relay_url).is_some()
    }

    /// Remove expired entries.
    fn evict_expired(&mut self) {
        self.entries
            .retain(|_, cached| cached.fetched_at.elapsed() < self.ttl);
    }
}

// ─── CDK Wallet Wrapper ─────────────────────────────────────────────────────

#[cfg(feature = "cashu")]
/// Wrapper around a CDK Cashu wallet for minting and sending ecash tokens.
///
/// The caller is responsible for constructing the CDK `Wallet` with appropriate
/// storage (e.g., `cdk-sqlite`, `cdk-redb`). This avoids coupling to a specific
/// storage backend and prevents dependency version conflicts.
pub struct CashuWallet {
    wallet: cdk::wallet::Wallet,
}

#[cfg(feature = "cashu")]
impl CashuWallet {
    /// Wrap an existing CDK wallet.
    ///
    /// The caller constructs the wallet with their choice of storage backend:
    /// ```ignore
    /// let store = cdk_sqlite::WalletSqliteDatabase::new("wallet.db").await?;
    /// let wallet = cdk::wallet::Wallet::new(
    ///     "https://8333.space:3338/",
    ///     CurrencyUnit::Sat,
    ///     Arc::new(store),
    ///     seed,
    ///     None,
    /// )?;
    /// let cashu = CashuWallet::from_wallet(wallet);
    /// ```
    pub fn from_wallet(wallet: cdk::wallet::Wallet) -> Self {
        Self { wallet }
    }

    /// Create a new CDK wallet from mint URL, seed, and a WalletDatabase store.
    pub fn new(
        mint_url: &str,
        seed: [u8; 64],
        localstore: Arc<
            dyn cdk_common::database::WalletDatabase<cdk_common::database::Error> + Send + Sync,
        >,
    ) -> Result<Self> {
        let wallet = cdk::wallet::Wallet::new(
            mint_url,
            cdk::nuts::CurrencyUnit::Sat,
            localstore,
            seed,
            None,
        )
        .map_err(|e| KeychatError::Stamp(format!("CDK wallet init failed: {e}")))?;

        Ok(Self { wallet })
    }

    /// Request a mint quote via Bolt11 (returns a quote ID).
    ///
    /// After paying the Lightning invoice, call `mint_tokens` to claim the ecash.
    pub async fn mint_quote(&self, amount: u64) -> Result<String> {
        let amount = cdk::amount::Amount::from(amount);
        let quote = self
            .wallet
            .mint_quote("bolt11", Some(amount), None, None)
            .await
            .map_err(|e| KeychatError::Stamp(format!("mint quote failed: {e}")))?;

        Ok(quote.id)
    }

    /// Mint tokens after a quote has been paid.
    pub async fn mint_tokens(&self, quote_id: &str) -> Result<()> {
        let _proofs = self
            .wallet
            .mint(quote_id, cdk::amount::SplitTarget::default(), None)
            .await
            .map_err(|e| KeychatError::Stamp(format!("mint failed: {e}")))?;

        Ok(())
    }

    /// Create a sendable Cashu token string of the given amount.
    ///
    /// Returns a token string starting with "cashuA" or "cashuB".
    pub async fn send(&self, amount: u64) -> Result<String> {
        let amount = cdk::amount::Amount::from(amount);
        let prepared = self
            .wallet
            .prepare_send(amount, cdk::wallet::SendOptions::default())
            .await
            .map_err(|e| KeychatError::Stamp(format!("prepare send failed: {e}")))?;

        let token = prepared
            .confirm(None)
            .await
            .map_err(|e| KeychatError::Stamp(format!("send confirm failed: {e}")))?;

        Ok(token.to_string())
    }

    /// Get the current wallet balance.
    pub async fn balance(&self) -> Result<u64> {
        let balance = self
            .wallet
            .total_balance()
            .await
            .map_err(|e| KeychatError::Stamp(format!("balance check failed: {e}")))?;

        Ok(balance.into())
    }

    /// Receive a Cashu token (claim proofs into this wallet).
    pub async fn receive(&self, token: &str) -> Result<u64> {
        let amount = self
            .wallet
            .receive(token, cdk::wallet::ReceiveOptions::default())
            .await
            .map_err(|e| KeychatError::Stamp(format!("receive failed: {e}")))?;

        Ok(amount.into())
    }
}

#[cfg(feature = "cashu")]
impl std::fmt::Debug for CashuWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CashuWallet").finish_non_exhaustive()
    }
}

// ─── Stamp Manager ──────────────────────────────────────────────────────────

#[cfg(feature = "cashu")]
/// Default fee cache TTL: 1 hour.
const DEFAULT_FEE_CACHE_TTL: Duration = Duration::from_secs(3600);

#[cfg(feature = "cashu")]
/// Manages relay fee discovery, ecash wallet, and stamp creation.
///
/// The StampManager is optional — if no wallet is configured, stamps are skipped
/// and events are published normally.
#[derive(Debug)]
pub struct StampManager {
    fee_cache: Arc<RwLock<FeeCache>>,
    wallet: Option<CashuWallet>,
}

#[cfg(feature = "cashu")]
impl StampManager {
    /// Create a new StampManager with a pre-built CDK wallet.
    pub fn new(wallet: cdk::wallet::Wallet) -> Self {
        Self {
            fee_cache: Arc::new(RwLock::new(FeeCache::new(DEFAULT_FEE_CACHE_TTL))),
            wallet: Some(CashuWallet::from_wallet(wallet)),
        }
    }

    /// Create a new StampManager from a CashuWallet.
    pub fn with_cashu_wallet(wallet: CashuWallet) -> Self {
        Self {
            fee_cache: Arc::new(RwLock::new(FeeCache::new(DEFAULT_FEE_CACHE_TTL))),
            wallet: Some(wallet),
        }
    }

    /// Create a StampManager without a wallet (fee lookups only, no stamp creation).
    pub fn without_wallet() -> Self {
        Self {
            fee_cache: Arc::new(RwLock::new(FeeCache::new(DEFAULT_FEE_CACHE_TTL))),
            wallet: None,
        }
    }

    /// Fetch and cache fee rules from multiple relays.
    ///
    /// Fetches NIP-11 info from each relay concurrently and caches the fee rules.
    /// Errors for individual relays are logged as warnings but don't fail the batch.
    pub async fn fetch_and_cache_fees(&self, relay_urls: &[&str]) {
        let futures: Vec<_> = relay_urls
            .iter()
            .map(|url| {
                let url = url.to_string();
                async move {
                    let result = fetch_relay_info(&url).await;
                    (url, result)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;
        let mut cache = self.fee_cache.write().await;
        cache.evict_expired();

        for (url, result) in results {
            match result {
                Ok(info) => {
                    let rules = info.fees.map(|f| f.publication).unwrap_or_default();
                    debug!("cached {} fee rules for {url}", rules.len());
                    cache.insert(url, rules);
                }
                Err(e) => {
                    warn!("failed to fetch NIP-11 for {url}: {e}");
                    // Cache empty rules so we don't re-fetch immediately
                    cache.insert(url, Vec::new());
                }
            }
        }
    }

    /// Get the fee rule for a specific relay and event kind.
    pub async fn get_fee_for_kind(
        &self,
        relay_url: &str,
        event_kind: Kind,
    ) -> Option<RelayFeeRule> {
        let cache = self.fee_cache.read().await;
        cache.get_fee_for_kind(relay_url, event_kind.as_u16())
    }

    /// Create an ecash stamp token for the given relay and event kind.
    ///
    /// Returns `Ok(None)` if the relay is free (no fee rule), or if no wallet is configured.
    /// Returns `Ok(Some(token))` with a Cashu token string if a stamp is needed.
    pub async fn create_stamp(&self, relay_url: &str, event_kind: Kind) -> Result<Option<String>> {
        // Check if relay requires a fee for this kind
        let fee_rule = match self.get_fee_for_kind(relay_url, event_kind).await {
            Some(rule) => rule,
            None => return Ok(None), // Free relay
        };

        if fee_rule.amount == 0 {
            return Ok(None);
        }

        // Need a wallet to create stamps
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                warn!("relay {relay_url} requires stamp but no wallet configured");
                return Ok(None);
            }
        };

        // Create a token for the required amount
        let token = wallet.send(fee_rule.amount).await?;
        debug!(
            "created stamp: {} {} for {relay_url} kind:{}",
            fee_rule.amount,
            fee_rule.unit,
            event_kind.as_u16()
        );

        Ok(Some(token))
    }

    /// Format an event for relay delivery, attaching a stamp if required.
    ///
    /// If the relay requires a stamp, returns `["EVENT", <event>, <token>]`.
    /// Otherwise returns the standard `["EVENT", <event>]` format.
    pub async fn stamp_event(&self, event: &Event, relay_url: &str) -> Result<String> {
        // Ensure fee cache is populated for this relay
        if !self.fee_cache.read().await.has_valid(relay_url) {
            self.fetch_and_cache_fees(&[relay_url]).await;
        }

        match self.create_stamp(relay_url, event.kind).await? {
            Some(token) => Ok(attach_ecash_stamp(event, &token)),
            None => {
                // Standard Nostr EVENT message (no stamp needed)
                let event_json = serde_json::to_value(event)
                    .map_err(|e| KeychatError::Stamp(format!("event serialize: {e}")))?;
                Ok(serde_json::json!(["EVENT", event_json]).to_string())
            }
        }
    }

    /// Check if a wallet is configured.
    pub fn has_wallet(&self) -> bool {
        self.wallet.is_some()
    }

    /// Get the wallet balance, if a wallet is configured.
    pub async fn wallet_balance(&self) -> Result<Option<u64>> {
        match &self.wallet {
            Some(w) => Ok(Some(w.balance().await?)),
            None => Ok(None),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_url_to_http_wss() {
        assert_eq!(
            relay_url_to_http("wss://relay.keychat.io"),
            "https://relay.keychat.io"
        );
    }

    #[test]
    fn relay_url_to_http_ws() {
        assert_eq!(
            relay_url_to_http("ws://localhost:8080"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn parse_nip11_fee_rules() {
        let json = r#"{
            "name": "relay.keychat.io",
            "fees": {
                "publication": [{
                    "amount": 1,
                    "unit": "sat",
                    "method": {"Cashu": {"mints": ["https://8333.space:3338/"]}},
                    "kinds": [4, 1059]
                }]
            }
        }"#;

        let info: RelayInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.name.as_deref(), Some("relay.keychat.io"));

        let fees = info.fees.unwrap();
        assert_eq!(fees.publication.len(), 1);

        let rule = &fees.publication[0];
        assert_eq!(rule.amount, 1);
        assert_eq!(rule.unit, "sat");
        assert!(rule.applies_to_kind(1059));
        assert!(rule.applies_to_kind(4));
        assert!(!rule.applies_to_kind(1));

        let mints = rule.accepted_mints();
        assert_eq!(mints, vec!["https://8333.space:3338/"]);
    }

    #[test]
    fn parse_nip11_no_fees() {
        let json = r#"{"name": "free-relay"}"#;
        let info: RelayInfo = serde_json::from_str(json).unwrap();
        assert!(info.fees.is_none());
    }

    #[test]
    fn parse_nip11_empty_fees() {
        let json = r#"{"fees": {"publication": []}}"#;
        let info: RelayInfo = serde_json::from_str(json).unwrap();
        let fees = info.fees.unwrap();
        assert!(fees.publication.is_empty());
    }

    #[test]
    fn fee_rule_applies_to_kind_wildcard() {
        let rule = RelayFeeRule {
            amount: 1,
            unit: "sat".to_string(),
            method: None,
            kinds: None, // No kinds filter = applies to all
        };
        assert!(rule.applies_to_kind(1));
        assert!(rule.applies_to_kind(1059));
        assert!(rule.applies_to_kind(4));
    }

    #[test]
    fn fee_cache_insert_and_get() {
        let mut cache = FeeCache::new(Duration::from_secs(3600));
        let rules = vec![RelayFeeRule {
            amount: 1,
            unit: "sat".to_string(),
            method: None,
            kinds: Some(vec![1059]),
        }];

        cache.insert("wss://relay.example.com".to_string(), rules);

        assert!(cache.has_valid("wss://relay.example.com"));
        assert!(!cache.has_valid("wss://other.relay.com"));

        let fee = cache.get_fee_for_kind("wss://relay.example.com", 1059);
        assert!(fee.is_some());
        assert_eq!(fee.unwrap().amount, 1);

        // Kind not in the rule
        let fee = cache.get_fee_for_kind("wss://relay.example.com", 1);
        assert!(fee.is_none());
    }

    #[test]
    fn fee_cache_ttl_expiry() {
        let mut cache = FeeCache::new(Duration::from_millis(0)); // Immediate expiry
        cache.insert(
            "wss://relay.example.com".to_string(),
            vec![RelayFeeRule {
                amount: 1,
                unit: "sat".to_string(),
                method: None,
                kinds: None,
            }],
        );

        // Should be expired immediately
        assert!(!cache.has_valid("wss://relay.example.com"));
        assert!(cache
            .get_fee_for_kind("wss://relay.example.com", 1059)
            .is_none());
    }

    #[test]
    fn stamp_event_format_with_token() {
        use nostr::Keys;

        let keys = Keys::generate();
        let event = nostr::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();

        let token = "cashuAeyJhbGciOiJIUzI1NiJ9";
        let result = attach_ecash_stamp(&event, token);

        let arr: serde_json::Value = serde_json::from_str(&result).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "EVENT");
        assert!(arr[1].is_object());
        assert_eq!(arr[2], token);
    }

    #[test]
    fn stamp_event_format_without_stamp() {
        use nostr::Keys;

        let keys = Keys::generate();
        let event = nostr::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .unwrap();

        // Standard format without stamp
        let event_json = serde_json::to_value(&event).unwrap();
        let msg = serde_json::json!(["EVENT", event_json]).to_string();

        let arr: serde_json::Value = serde_json::from_str(&msg).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], "EVENT");
        assert!(arr[1].is_object());
    }

    #[cfg(feature = "cashu")]
    #[tokio::test]
    async fn stamp_manager_without_wallet() {
        let mgr = StampManager::without_wallet();
        assert!(!mgr.has_wallet());

        // No fee cached — should return None (free relay)
        let stamp = mgr
            .create_stamp("wss://relay.example.com", Kind::GiftWrap)
            .await
            .unwrap();
        assert!(stamp.is_none());

        let balance = mgr.wallet_balance().await.unwrap();
        assert!(balance.is_none());
    }

    #[cfg(feature = "cashu")]
    #[tokio::test]
    async fn stamp_manager_fee_lookup() {
        let mgr = StampManager::without_wallet();

        // Manually populate the cache
        {
            let mut cache = mgr.fee_cache.write().await;
            cache.insert(
                "wss://relay.keychat.io".to_string(),
                vec![RelayFeeRule {
                    amount: 1,
                    unit: "sat".to_string(),
                    method: Some(CashuFeeMethod {
                        cashu: Some(CashuMintList {
                            mints: vec!["https://8333.space:3338/".to_string()],
                        }),
                    }),
                    kinds: Some(vec![1059]),
                }],
            );
        }

        // Kind 1059 should have a fee
        let fee = mgr
            .get_fee_for_kind("wss://relay.keychat.io", Kind::GiftWrap)
            .await;
        assert!(fee.is_some());
        let fee = fee.unwrap();
        assert_eq!(fee.amount, 1);
        assert_eq!(fee.unit, "sat");
        assert_eq!(fee.accepted_mints(), vec!["https://8333.space:3338/"]);

        // Kind 1 should have no fee
        let fee = mgr
            .get_fee_for_kind("wss://relay.keychat.io", Kind::TextNote)
            .await;
        assert!(fee.is_none());

        // No wallet — stamp creation should return None even with fee rule
        let stamp = mgr
            .create_stamp("wss://relay.keychat.io", Kind::GiftWrap)
            .await
            .unwrap();
        assert!(stamp.is_none());
    }
}
