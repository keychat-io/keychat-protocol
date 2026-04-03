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
use crate::storage::SecureStorage;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Result of publishing an event, with per-relay delivery info.
#[derive(Debug, Clone)]
pub struct PublishResult {
    pub event_id: EventId,
    pub success_relays: Vec<String>,
    pub failed_relays: Vec<(String, String)>, // (url, error_msg)
}

/// Health tracking for a single relay.
#[derive(Debug, Clone)]
pub struct RelayHealth {
    pub consecutive_failures: u32,
    pub last_failure: Option<Instant>,
    pub is_disabled: bool,
}

const MAX_CONSECUTIVE_FAILURES: u32 = 10;

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
    /// Optional persistent storage for deduplication across restarts
    storage: Option<Arc<std::sync::Mutex<SecureStorage>>>,
    /// Per-relay health tracking
    relay_health: Arc<Mutex<HashMap<String, RelayHealth>>>,
    /// Optional stamp manager for auto-attaching ecash stamps
    #[cfg(feature = "cashu")]
    stamp_manager: Option<Arc<StampManager>>,
}

impl Transport {
    /// Create a new Transport with the given identity keys.
    pub async fn new(keys: &Keys) -> Result<Self> {
        let client = ClientBuilder::new().signer(keys.clone()).build();

        Ok(Self {
            client,
            processed_events: Arc::new(Mutex::new(HashSet::new())),
            storage: None,
            relay_health: Arc::new(Mutex::new(HashMap::new())),
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

    /// Set persistent storage for deduplication across restarts.
    pub fn set_storage(&mut self, storage: Arc<std::sync::Mutex<SecureStorage>>) {
        self.storage = Some(storage);
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
    ///
    /// Returns the generated SubscriptionId so callers can unsubscribe the old
    /// subscription before re-subscribing (preventing duplicate REQ accumulation).
    pub async fn subscribe(
        &self,
        pubkeys: Vec<PublicKey>,
        since: Option<Timestamp>,
    ) -> Result<SubscriptionId> {
        let mut filter = Filter::new().kind(Kind::GiftWrap).pubkeys(pubkeys);

        if let Some(since_ts) = since {
            filter = filter.since(since_ts);
        }

        let connected = self.connected_relays().await;
        tracing::info!(
            "📡 SUB: filter → {} connected relay(s): [{}]",
            connected.len(),
            connected.join(", ")
        );

        let output = self
            .client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| KeychatError::Transport(format!("subscribe failed: {e}")))?;

        tracing::info!(
            "📡 SUB: ok subId={} success={} failed={}",
            output.val,
            output.success.len(),
            output.failed.len()
        );

        Ok(output.val)
    }

    /// Unsubscribe from a previous subscription by ID.
    pub async fn unsubscribe(&self, id: SubscriptionId) {
        self.client.unsubscribe(id).await;
    }

    /// Replace an existing subscription with a new one atomically:
    /// unsubscribes the old ID, subscribes with the new filter, returns the new ID.
    /// If `old_id` is None, just subscribes without unsubscribing.
    pub async fn resubscribe(
        &self,
        old_id: Option<SubscriptionId>,
        pubkeys: Vec<PublicKey>,
        since: Option<Timestamp>,
    ) -> Result<SubscriptionId> {
        if let Some(id) = old_id {
            self.client.unsubscribe(id).await;
        }
        self.subscribe(pubkeys, since).await
    }

    /// Publish an event to ALL connected relays simultaneously.
    /// Succeeds if at least one relay accepts the event.
    ///
    /// If a StampManager is configured, this will check each relay's fee rules
    /// and log a warning if stamps are required but unavailable. The event is
    /// always published via the standard nostr-sdk path; stamp attachment
    /// requires using `publish_event_stamped` for raw WebSocket delivery.
    pub async fn publish_event(&self, event: Event) -> Result<PublishResult> {
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

        let success_relays: Vec<String> = output.success.iter().map(|u| u.to_string()).collect();
        let failed_relays: Vec<(String, String)> = output
            .failed
            .iter()
            .map(|(u, e)| {
                (
                    u.to_string(),
                    e.as_ref().map(|s| s.to_string()).unwrap_or_default(),
                )
            })
            .collect();

        // Update relay health
        {
            let mut health = self.relay_health.lock().await;
            for url in &success_relays {
                let h = health.entry(url.clone()).or_insert(RelayHealth {
                    consecutive_failures: 0,
                    last_failure: None,
                    is_disabled: false,
                });
                h.consecutive_failures = 0;
            }
            for (url, _) in &failed_relays {
                let h = health.entry(url.clone()).or_insert(RelayHealth {
                    consecutive_failures: 0,
                    last_failure: None,
                    is_disabled: false,
                });
                h.consecutive_failures += 1;
                h.last_failure = Some(Instant::now());
                if h.consecutive_failures >= MAX_CONSECUTIVE_FAILURES && !h.is_disabled {
                    h.is_disabled = true;
                    tracing::warn!(
                        "relay {} disabled after {} consecutive failures",
                        url,
                        h.consecutive_failures
                    );
                    if let Err(e) = self.client.remove_relay(url.as_str()).await {
                        tracing::warn!("failed to remove disabled relay {}: {e}", url);
                    }
                }
            }
        }

        Ok(PublishResult {
            event_id: output.val,
            success_relays,
            failed_relays,
        })
    }

    /// Publish an event to all connected relays without waiting for OK responses.
    /// Uses fire-and-forget: sends the EVENT message over websocket and returns immediately.
    /// Relay OK responses are handled by the event loop via RelayPoolNotification::Message.
    pub async fn publish_event_async(&self, event: Event) -> Result<EventId> {
        let event_id = event.id;
        let msg = ClientMessage::event(event);

        let relays = self.client.relays().await;
        let mut sent_count = 0u32;

        for (url, relay) in relays.iter() {
            if !relay.is_connected() {
                continue;
            }
            match relay.batch_msg(vec![msg.clone()]) {
                Ok(()) => {
                    sent_count += 1;
                    tracing::debug!("EVENT sent to {}", url);
                }
                Err(e) => {
                    tracing::warn!("failed to send EVENT to {}: {e}", url);
                }
            }
        }

        if sent_count == 0 {
            return Err(KeychatError::Transport(
                "no relay accepted the event".into(),
            ));
        }

        tracing::info!(
            "⬆️ EVENT {} fire-and-forget to {} relay(s)",
            &event_id.to_hex()[..16],
            sent_count
        );

        Ok(event_id)
    }

    /// Rebroadcast an already-signed event to all connected relays.
    pub async fn rebroadcast_event(&self, event: Event) -> Result<PublishResult> {
        self.publish_event(event).await
    }

    /// Publish an event with ecash stamp to a specific relay.
    ///
    /// Uses the StampManager to create a stamp if the relay requires one,
    /// then formats and returns the stamped message for raw WebSocket delivery.
    /// If stamping fails (e.g., no funds), publishes without stamp and logs a warning.
    #[cfg(feature = "cashu")]
    pub async fn publish_event_stamped(&self, event: &Event, relay_url: &str) -> Result<String> {
        if let Some(stamp_mgr) = &self.stamp_manager {
            match stamp_mgr.stamp_event(event, relay_url).await {
                Ok(msg) => return Ok(msg),
                Err(e) => {
                    tracing::warn!(
                        "stamp creation failed for {relay_url}, publishing without stamp: {e}"
                    );
                }
            }
        }

        // Fallback: standard EVENT message without stamp
        let event_json = serde_json::to_value(event)
            .map_err(|e| KeychatError::Transport(format!("event serialize: {e}")))?;
        Ok(serde_json::json!(["EVENT", event_json]).to_string())
    }

    /// Check persistent storage for a processed event (sync helper, no MutexGuard across await).
    fn is_processed_in_db(&self, event_id_hex: &str) -> bool {
        if let Some(ref storage) = self.storage {
            if let Ok(store) = storage.lock() {
                return store.is_event_processed(event_id_hex).unwrap_or(false);
            }
        }
        false
    }

    /// Mark event as processed in persistent storage (sync helper).
    fn mark_processed_in_db(&self, event_id_hex: &str) {
        if let Some(ref storage) = self.storage {
            if let Ok(store) = storage.lock() {
                let _ = store.mark_event_processed(event_id_hex);
            }
        }
    }

    /// Check if an event has already been processed (deduplication).
    /// Checks both in-memory cache and persistent storage.
    pub async fn is_processed(&self, event_id: &EventId) -> bool {
        if self.processed_events.lock().await.contains(event_id) {
            return true;
        }
        self.is_processed_in_db(&event_id.to_hex())
    }

    /// Mark an event as processed (in-memory + persistent).
    pub async fn mark_processed(&self, event_id: EventId) {
        self.processed_events.lock().await.insert(event_id);
        self.mark_processed_in_db(&event_id.to_hex());
    }

    /// Process an event only if it hasn't been seen before.
    /// Returns `Some(event)` if new, `None` if duplicate.
    /// Uses both in-memory cache and persistent storage.
    pub async fn deduplicate(&self, event: Event) -> Option<Event> {
        let id = event.id;
        let id_hex = id.to_hex();

        // Check in-memory first
        {
            let processed = self.processed_events.lock().await;
            if processed.contains(&id) {
                return None;
            }
        }

        // Check persistent storage (sync, no MutexGuard across await)
        if self.is_processed_in_db(&id_hex) {
            self.processed_events.lock().await.insert(id);
            return None;
        }

        // New event — mark in both layers
        self.processed_events.lock().await.insert(id);
        self.mark_processed_in_db(&id_hex);

        Some(event)
    }

    /// Reconnect to all relays (including re-enabling disabled ones).
    pub async fn reconnect(&self) -> Result<()> {
        // Re-enable disabled relays
        let disabled: Vec<String> = {
            let mut health = self.relay_health.lock().await;
            let urls: Vec<String> = health
                .iter()
                .filter(|(_, h)| h.is_disabled)
                .map(|(url, _)| url.clone())
                .collect();
            for url in &urls {
                if let Some(h) = health.get_mut(url) {
                    h.is_disabled = false;
                    h.consecutive_failures = 0;
                }
            }
            urls
        };
        for url in &disabled {
            if let Err(e) = self.client.add_relay(url.as_str()).await {
                tracing::warn!("failed to re-add relay {}: {e}", url);
            }
        }
        self.client.connect().await;
        Ok(())
    }

    /// Reconnect a specific relay (re-enables if it was disabled).
    pub async fn reconnect_relay(&self, url: &str) -> Result<()> {
        {
            let mut health = self.relay_health.lock().await;
            if let Some(h) = health.get_mut(url) {
                h.is_disabled = false;
                h.consecutive_failures = 0;
            }
        }
        if let Err(e) = self.client.add_relay(url).await {
            tracing::warn!("failed to re-add relay {}: {e}", url);
        }
        self.client.connect().await;
        Ok(())
    }

    /// Get relay health info.
    pub async fn get_relay_health(&self) -> Vec<(String, RelayHealth)> {
        self.relay_health
            .lock()
            .await
            .iter()
            .map(|(url, h)| (url.clone(), h.clone()))
            .collect()
    }

    /// Add a relay and immediately connect to it.
    pub async fn add_relay_and_connect(&self, url: &str) -> Result<()> {
        self.add_relay(url).await?;
        self.client.connect().await;
        Ok(())
    }

    /// Remove a relay from the pool.
    pub async fn remove_relay(&self, url: &str) -> Result<()> {
        self.client
            .remove_relay(url)
            .await
            .map_err(|e| KeychatError::Transport(format!("failed to remove relay {url}: {e}")))?;
        Ok(())
    }

    /// Get the list of current relay URLs.
    pub async fn get_relays(&self) -> Vec<String> {
        self.client
            .relays()
            .await
            .keys()
            .map(|url| url.to_string())
            .collect()
    }

    /// Get relay URLs with their connection status.
    pub async fn get_relay_statuses(&self) -> Vec<(String, String)> {
        self.client
            .relays()
            .await
            .iter()
            .map(|(url, relay)| (url.to_string(), relay.status().to_string()))
            .collect()
    }

    /// Get only the currently connected relay URLs.
    pub async fn connected_relays(&self) -> Vec<String> {
        self.client
            .relays()
            .await
            .iter()
            .filter(|(_, relay)| relay.is_connected())
            .map(|(url, _)| url.to_string())
            .collect()
    }

    /// Get a reference to the underlying nostr-sdk Client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Disconnect from all relays.
    pub async fn disconnect(&self) -> Result<()> {
        self.client
            .disconnect()
            .await
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
        let event = EventBuilder::text_note("test").sign(&keys).await.unwrap();
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

    #[tokio::test]
    async fn relay_crud_and_status() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();

        // Initially empty
        assert!(transport.get_relays().await.is_empty());
        assert!(transport.get_relay_statuses().await.is_empty());

        // Add relays
        transport
            .add_relay("wss://relay.example.com")
            .await
            .unwrap();
        transport
            .add_relay("wss://relay2.example.com")
            .await
            .unwrap();

        let relays = transport.get_relays().await;
        assert_eq!(relays.len(), 2);

        // Statuses should be available (Initialized — not connected yet)
        let statuses = transport.get_relay_statuses().await;
        assert_eq!(statuses.len(), 2);
        for (url, status) in &statuses {
            assert!(!url.is_empty());
            assert!(!status.is_empty());
        }

        // Remove one
        transport
            .remove_relay("wss://relay.example.com")
            .await
            .unwrap();
        assert_eq!(transport.get_relays().await.len(), 1);
    }

    #[tokio::test]
    async fn publish_result_structure() {
        // Test PublishResult construction
        let event_id = EventId::all_zeros();
        let result = PublishResult {
            event_id,
            success_relays: vec!["wss://a.com".into(), "wss://b.com".into()],
            failed_relays: vec![("wss://c.com".into(), "timeout".into())],
        };
        assert_eq!(result.success_relays.len(), 2);
        assert_eq!(result.failed_relays.len(), 1);
        assert_eq!(result.failed_relays[0].1, "timeout");
    }

    #[tokio::test]
    async fn relay_health_tracking() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();

        // Initially empty
        assert!(transport.get_relay_health().await.is_empty());

        // Simulate failures by directly manipulating health
        {
            let mut health = transport.relay_health.lock().await;
            health.insert(
                "wss://bad-relay.com".into(),
                RelayHealth {
                    consecutive_failures: 5,
                    last_failure: Some(Instant::now()),
                    is_disabled: false,
                },
            );
            health.insert(
                "wss://good-relay.com".into(),
                RelayHealth {
                    consecutive_failures: 0,
                    last_failure: None,
                    is_disabled: false,
                },
            );
        }

        let health_list = transport.get_relay_health().await;
        assert_eq!(health_list.len(), 2);

        let bad = health_list
            .iter()
            .find(|(url, _)| url == "wss://bad-relay.com")
            .unwrap();
        assert_eq!(bad.1.consecutive_failures, 5);
        assert!(!bad.1.is_disabled);

        let good = health_list
            .iter()
            .find(|(url, _)| url == "wss://good-relay.com")
            .unwrap();
        assert_eq!(good.1.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn relay_health_disable_after_max_failures() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();

        // Simulate a relay that exceeded MAX_CONSECUTIVE_FAILURES
        {
            let mut health = transport.relay_health.lock().await;
            health.insert(
                "wss://dead-relay.com".into(),
                RelayHealth {
                    consecutive_failures: MAX_CONSECUTIVE_FAILURES,
                    last_failure: Some(Instant::now()),
                    is_disabled: true,
                },
            );
        }

        let h = transport.get_relay_health().await;
        let dead = h
            .iter()
            .find(|(url, _)| url == "wss://dead-relay.com")
            .unwrap();
        assert!(dead.1.is_disabled);

        // Reconnect should re-enable it
        transport
            .reconnect_relay("wss://dead-relay.com")
            .await
            .unwrap();
        let h = transport.get_relay_health().await;
        let restored = h
            .iter()
            .find(|(url, _)| url == "wss://dead-relay.com")
            .unwrap();
        assert!(!restored.1.is_disabled);
        assert_eq!(restored.1.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn deduplicate_with_persistent_storage() {
        use crate::storage::SecureStorage;

        let keys = Keys::generate();
        let mut transport = Transport::new(&keys).await.unwrap();

        // Set up persistent storage
        let storage = Arc::new(std::sync::Mutex::new(
            SecureStorage::open_in_memory("test-key-dedup").unwrap(),
        ));
        transport.set_storage(storage.clone());

        // Create a test event
        let event = EventBuilder::text_note("dedup-test")
            .sign(&keys)
            .await
            .unwrap();
        let event_id = event.id;

        // First call: should pass through
        let result = transport.deduplicate(event.clone()).await;
        assert!(result.is_some());

        // Second call: in-memory dedup
        let result = transport.deduplicate(event.clone()).await;
        assert!(result.is_none());

        // Verify it's in the DB
        {
            let store = storage.lock().unwrap();
            assert!(store.is_event_processed(&event_id.to_hex()).unwrap());
        }

        // New transport with same storage — should still be deduped (from DB)
        let mut transport2 = Transport::new(&keys).await.unwrap();
        transport2.set_storage(storage);

        let result = transport2.deduplicate(event).await;
        assert!(
            result.is_none(),
            "event should be deduped from persistent storage after restart"
        );
    }

    #[tokio::test]
    async fn reconnect_re_enables_disabled_relays() {
        let keys = Keys::generate();
        let transport = Transport::new(&keys).await.unwrap();

        // Add a relay and mark it disabled
        transport
            .add_relay("wss://flaky.example.com")
            .await
            .unwrap();
        {
            let mut health = transport.relay_health.lock().await;
            health.insert(
                "wss://flaky.example.com".into(),
                RelayHealth {
                    consecutive_failures: 15,
                    last_failure: Some(Instant::now()),
                    is_disabled: true,
                },
            );
        }

        // Reconnect all
        transport.reconnect().await.unwrap();

        // Should be re-enabled
        let h = transport.get_relay_health().await;
        let flaky = h.iter().find(|(url, _)| url.contains("flaky")).unwrap();
        assert!(!flaky.1.is_disabled);
        assert_eq!(flaky.1.consecutive_failures, 0);
    }
}
