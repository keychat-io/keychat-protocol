use std::collections::BTreeMap;

use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};

use crate::error::{KeychatError, Result};

/// Relay stamp fee requirements for a single relay.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayStampFee {
    pub amount: u64,
    pub unit: String,
    pub mints: Vec<String>,
}

/// Relay URL -> stamp fee mapping.
#[derive(Clone, Debug, Default)]
pub struct StampConfig {
    relay_fees: BTreeMap<String, RelayStampFee>,
}

impl StampConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, relay_url: impl Into<String>, fee: RelayStampFee) {
        self.relay_fees.insert(relay_url.into(), fee);
    }

    pub fn get(&self, relay_url: &str) -> Option<&RelayStampFee> {
        if let Some(fee) = self.relay_fees.get(relay_url) {
            return Some(fee);
        }

        let trimmed = relay_url.trim_end_matches('/');
        self.relay_fees.get(trimmed)
    }
}

/// Fetch a relay's NIP-11 info and extract the first `fees.stamp` entry.
///
/// Returns `Ok(None)` when no stamp fee is advertised.
pub async fn fetch_relay_stamp_info(relay_url: &str) -> Result<Option<RelayStampFee>> {
    let info_url = relay_info_url(relay_url)?;
    let client = reqwest::Client::new();
    let response = client
        .get(&info_url)
        .header(ACCEPT, "application/nostr+json")
        .send()
        .await
        .map_err(|err| KeychatError::Nostr(format!("fetch NIP-11 from {info_url}: {err}")))?;

    let status = response.status();
    if !status.is_success() {
        return Err(KeychatError::Nostr(format!(
            "relay info request failed: {info_url} returned {status}"
        )));
    }

    let doc: Nip11Info = response
        .json()
        .await
        .map_err(|err| KeychatError::Nostr(format!("parse NIP-11 from {info_url}: {err}")))?;

    Ok(doc.fees.and_then(|f| f.stamp).and_then(|mut s| s.drain(..1).next()))
}

fn relay_info_url(relay_url: &str) -> Result<String> {
    if relay_url.starts_with("wss://") {
        return Ok(format!("https://{}", &relay_url["wss://".len()..]));
    }
    if relay_url.starts_with("ws://") {
        return Ok(format!("http://{}", &relay_url["ws://".len()..]));
    }
    if relay_url.starts_with("https://") || relay_url.starts_with("http://") {
        return Ok(relay_url.to_owned());
    }

    Err(KeychatError::InvalidRelayUrl(relay_url.to_owned()))
}

/// Client-provided stamp creation abstraction.
///
/// Implement this trait with your own Cashu wallet integration
/// (for example via the `cdk` crate in your application).
pub trait StampProvider: Send + Sync {
    /// Create a Cashu token string covering `amount` in `unit`,
    /// from one of the provided `mints`.
    fn create_stamp(&self, amount: u64, unit: &str, mints: &[String]) -> Result<String>;
}

/// Default provider that does not create stamps.
pub struct NoopStampProvider;

impl StampProvider for NoopStampProvider {
    fn create_stamp(&self, _amount: u64, _unit: &str, _mints: &[String]) -> Result<String> {
        Err(KeychatError::InvalidArgument(
            "stamp provider is not configured".to_owned(),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct Nip11Info {
    #[serde(default)]
    fees: Option<Nip11Fees>,
}

#[derive(Debug, Deserialize)]
struct Nip11Fees {
    #[serde(default)]
    stamp: Option<Vec<RelayStampFee>>,
}
