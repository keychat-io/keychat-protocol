//! Unified wallet type system.
//!
//! Mirrors the Flutter `unified_wallet` architecture: every wallet protocol
//! (Cashu, NWC, LND, Lightning.Pub, Ark) presents itself to the UI through the
//! same [`WalletAccount`] / [`WalletTransaction`] types so a single UI can
//! render any backend.

use serde::{Deserialize, Serialize};

// ── Protocol enum ────────────────────────────────────────────────────────────

/// Underlying protocol backing a wallet account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletProtocol {
    /// Cashu ecash — mint-based, blind-signed tokens stored locally.
    Cashu,
    /// Nostr Wallet Connect (NIP-47) — remote Lightning wallet over Nostr.
    Nwc,
    /// LND — direct REST connection to a Lightning node.
    Lnd,
    /// Lightning.Pub — public Lightning wallet service.
    LightningPub,
    /// Ark — reserved for future Ark-based wallet support.
    Ark,
}

// ── WalletAccount ────────────────────────────────────────────────────────────

/// One account inside a [`WalletProtocol`].
///
/// A `WalletAccount` is the Rust analogue of Flutter's `WalletBase`. One
/// account maps to one mint (Cashu), one NWC connection, one LND node, etc.
/// A single provider instance owns many `WalletAccount`s — e.g. one
/// `CashuProvider` can manage several mints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    /// Non-secret stable identifier.
    ///
    /// * Cashu: the mint URL
    /// * NWC: the wallet-service pubkey
    /// * LND: `host:port`
    ///
    /// Safe to log, display, and persist.
    pub id: String,

    /// Human-readable name (derived from the URI or user-set).
    pub display_name: String,

    /// Secondary line shown in UI (e.g. the mint URL, relay domain).
    pub subtitle: String,

    /// The protocol this account belongs to.
    pub protocol: WalletProtocol,

    /// Current balance in satoshis.
    pub balance_sats: u64,

    /// Whether this account can send payments.
    pub can_send: bool,

    /// Whether this account can receive payments.
    pub can_receive: bool,

    /// Whether this account speaks Lightning.
    ///
    /// Cashu accounts with melt support: `true`.
    /// NWC/LND: always `true`.
    pub supports_lightning: bool,
}

// ── Transaction types ────────────────────────────────────────────────────────

/// Outcome of a single wallet transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    Pending,
    Success,
    Failed,
    Expired,
}

/// A single transaction in unified form.
///
/// `amount_sats` is signed: positive for incoming, negative for outgoing.
/// This matches the Flutter `WalletTransactionBase.amountSats` contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    /// Unique transaction identifier (scope varies by protocol).
    pub id: String,

    /// Account this transaction belongs to. `None` for synthetic rows that
    /// were not produced from a specific account context.
    pub account_id: Option<String>,

    /// Signed amount in satoshis. `+n` = incoming, `-n` = outgoing.
    pub amount_sats: i64,

    /// Unix timestamp in seconds.
    pub timestamp: u64,

    /// Human-readable description / memo, if any.
    pub description: Option<String>,

    /// Transaction status.
    pub status: TransactionStatus,

    /// `true` if this is an incoming transaction. Equivalent to
    /// `amount_sats > 0` but exposed explicitly to match Flutter.
    pub is_incoming: bool,

    /// Protocol that produced this transaction.
    pub protocol: WalletProtocol,

    /// Lightning preimage, if known.
    pub preimage: Option<String>,

    /// Lightning payment hash, if known.
    pub payment_hash: Option<String>,

    /// Fee paid in satoshis, if known.
    pub fee_sats: Option<u64>,

    /// Invoice or token string associated with this transaction.
    ///
    /// * Cashu: the serialised Cashu token (for ecash) or BOLT11 (for melt/mint)
    /// * NWC/LND: the BOLT11 invoice string
    pub invoice: Option<String>,
}

// ── Cashu-specific inherent types (not in the trait) ─────────────────────────

/// Lightning mint quote — returned by Cashu when topping up via Lightning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintQuote {
    pub id: String,
    pub invoice: String,
    pub amount: u64,
    pub expiry: u64,
}

/// State of a Cashu mint quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MintQuoteStatus {
    Pending,
    Paid,
    Expired,
}

/// Outcome of a Cashu melt (paying a Lightning invoice with ecash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeltResult {
    pub paid: bool,
    pub preimage: Option<String>,
    pub fee: u64,
}
