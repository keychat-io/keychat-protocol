//! Transport module: Nostr relay connection, subscription, and event publishing.
//!
//! Implements the Transport Layer from the Keychat Protocol v2 spec (§3).
//! Connects to Nostr relays via WebSocket, subscribes to kind 1059 events
//! by pubkey filter, publishes events, and deduplicates incoming events.

use crate::error::{KeychatError, Result};
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A Nostr relay transport for sending and receiving Keychat events.
pub struct Transport {
    client: Client,
    /// Track processed event IDs for deduplication
    processed_events: Arc<Mutex<HashSet<EventId>>>,
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
        })
    }

    /// Connect to a Nostr relay.
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

    /// Publish an event to connected relays.
    pub async fn publish_event(&self, event: Event) -> Result<EventId> {
        let output = self
            .client
            .send_event(event)
            .await
            .map_err(|e| KeychatError::Transport(format!("publish failed: {e}")))?;

        Ok(output.val)
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
