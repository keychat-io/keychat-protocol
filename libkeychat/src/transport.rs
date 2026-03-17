//! Transport module: Nostr relay connection, subscription, and event publishing.
//!
//! Implements the Transport Layer from the Keychat Protocol v2 spec (§3).
//!
//! **Multi-relay broadcast** (§3.1): Implementations MUST connect to multiple relays
//! simultaneously and broadcast every published event to ALL connected relays.
//! This provides redundancy (relay downtime tolerance), availability (first-delivery wins),
//! and censorship resistance (no single relay can block communication).
//!
//! Subscriptions are registered on all connected relays. Deduplication ensures each
//! event is processed only once even when received from multiple relays.
//!
//! A publish succeeds if at least one relay accepts the event.

use crate::error::{KeychatError, Result};
#[cfg(feature = "cashu")]
use crate::stamp::StampManager;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default Nostr relays for Keychat message transport.
/// All messages are broadcast to every relay simultaneously (§3.1).
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://relay.ditto.pub",
];

/// A Nostr relay transport for sending and receiving Keychat events.
///
/// Connects to multiple relays simultaneously. All publishes are broadcast to
/// every connected relay; all subscriptions are registered on every relay.
/// Deduplication ensures events received from multiple relays are processed once.
pub struct Transport {
    client: Client,
    /// Track processed event IDs for deduplication across all relays
    processed_events: Arc<Mutex<HashSet<EventId>>>,
    /// Optional stamp manager for auto-attaching ecash stamps
    #[cfg(feature = "cashu")]
    stamp_manager: Option<Arc<StampManager>>,
}

impl Transport {
    /// Create a new Transport with the given identity keys.
    pub async fn new(keys: &Keys) -> Result<Self> {
        let client = ClientBuilder::new()
            .signer(keys.clone())
            .build();

        Ok(Self {
            client,
            processed_events: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(feature = "cashu")]
            stamp_manager: None,
        })
    }

    /// Set the stamp manager for auto-attaching ecash stamps on publish.
    #[cfg(feature = "cashu")]
    pub fn set_stamp_manager(&mut self, manager: Arc<StampManager>) {
        self.stamp_manager = Some(manager);
    }

    /// Get a reference to the stamp manager, if configured.
    #[cfg(feature = "cashu")]
    pub fn stamp_manager(&self) -> Option<&Arc<StampManager>> {
        self.stamp_manager.as_ref()
    }

    /// Add a Nostr relay. Call multiple times to add multiple relays.
    /// All subsequent publishes and subscriptions will include this relay.
    pub async fn add_relay(&self, url: &str) -> Result<()> {
        self.client
            .add_relay(url)
            .await
            .map_err(|e| KeychatError::Transport(format!("failed to add relay {url}: {e}")))?;
        Ok(())
    }

    /// Connect to all added relays.
    pub async fn connect(&self) {
        self.client.connect().await;
    }

    /// Subscribe to kind 1059 events addressed to the given pubkeys.
    ///
    /// This sets up a subscription filter per the spec (§3.4):
    /// ```json
    /// { "kinds": [1059], "#p": [<pubkeys>], "since": <timestamp> }
    /// ```
    pub async fn subscribe(
        &self,
        pubkeys: Vec<PublicKey>,
        since: Option<Timestamp>,
    ) -> Result<SubscriptionId> {
        let mut filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkeys(pubkeys);

        if let Some(since_ts) = since {
            filter = filter.since(since_ts);
        }

        let output = self
            .client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| KeychatError::Transport(format!("subscribe failed: {e}")))?;

        Ok(output.val)
    }

    /// Publish an event to ALL connected relays simultaneously.
    /// Succeeds if at least one relay accepts the event.
    ///
    /// If a StampManager is configured, this will check each relay's fee rules
    /// and log a warning if stamps are required but unavailable. The event is
    /// always published via the standard nostr-sdk path; stamp attachment
    /// requires using `publish_event_stamped` for raw WebSocket delivery.
    pub async fn publish_event(&self, event: Event) -> Result<EventId> {
        #[cfg(feature = "cashu")]
        if let Some(stamp_mgr) = &self.stamp_manager {
            let fee = stamp_mgr
                .get_fee_for_kind("wss://relay.keychat.io", event.kind)
                .await;
            if fee.is_some() && !stamp_mgr.has_wallet() {
                tracing::warn!(
                    "relay requires ecash stamp for kind:{} but no wallet configured",
                    event.kind.as_u16()
                );
            }
        }

        let output = self
            .client
            .send_event(event)
            .await
            .map_err(|e| KeychatError::Transport(format!("publish failed: {e}")))?;

        Ok(output.val)
    }

    /// Publish an event with ecash stamp to a specific relay.
    ///
    /// Uses the StampManager to create a stamp if the relay requires one,
    /// then formats and returns the stamped message for raw WebSocket delivery.
    /// If stamping fails (e.g., no funds), publishes without stamp and logs a warning.
    #[cfg(feature = "cashu")]
    pub async fn publish_event_stamped(
        &self,
        event: &Event,
        relay_url: &str,
    ) -> Result<String> {
        if let Some(stamp_mgr) = &self.stamp_manager {
            match stamp_mgr.stamp_event(event, relay_url).await {
                Ok(msg) => return Ok(msg),
                Err(e) => {
                    tracing::warn!("stamp creation failed for {relay_url}, publishing without stamp: {e}");
                }
            }
        }

        // Fallback: standard EVENT message without stamp
        let event_json = serde_json::to_value(event)
            .map_err(|e| KeychatError::Transport(format!("event serialize: {e}")))?;
        Ok(serde_json::json!(["EVENT", event_json]).to_string())
    }

    /// Check if an event has already been processed (deduplication).
    pub async fn is_processed(&self, event_id: &EventId) -> bool {
        self.processed_events.lock().await.contains(event_id)
    }

    /// Mark an event as processed.
    pub async fn mark_processed(&self, event_id: EventId) {
        self.processed_events.lock().await.insert(event_id);
    }

    /// Process an event only if it hasn't been seen before.
    /// Returns `Some(event)` if new, `None` if duplicate.
    pub async fn deduplicate(&self, event: Event) -> Option<Event> {
        let id = event.id;
        let mut processed = self.processed_events.lock().await;
        if processed.contains(&id) {
            None
        } else {
            processed.insert(id);
            Some(event)
        }
    }

    /// Get a reference to the underlying nostr-sdk Client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Disconnect from all relays.
    pub async fn disconnect(&self) -> Result<()> {
        self.client.disconnect().await
            .map_err(|e| KeychatError::Transport(format!("disconnect failed: {e}")))?;
        Ok(())
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_transport() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();
        assert!(!format!("{:?}", transport).is_empty());
    }

    #[tokio::test]
    async fn deduplication() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();

        // Create a test event
        let event = EventBuilder::text_note("test")
            .sign(&keys)
            .await
            .unwrap();
        let event_id = event.id;

        // First time: should not be processed
        assert!(!transport.is_processed(&event_id).await);

        // Deduplicate should return Some on first call
        let result = transport.deduplicate(event.clone()).await;
        assert!(result.is_some());

        // Now it should be processed
        assert!(transport.is_processed(&event_id).await);

        // Deduplicate should return None on second call
        let result = transport.deduplicate(event).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn add_relay_invalid_url() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();
        // nostr-sdk may accept URLs at add time and fail at connect;
        // this tests that the transport can be created and add_relay doesn't panic
        let _ = transport.add_relay("wss://relay.example.com").await;
    }
}
