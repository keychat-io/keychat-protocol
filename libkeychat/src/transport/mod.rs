pub mod relay;

use std::sync::Arc;
use std::sync::RwLock;

use tokio::sync::mpsc;

use crate::error::{KeychatError, Result};
use crate::nostr::NostrEvent;
use crate::stamp::{NoopStampProvider, StampConfig, StampProvider};
use crate::transport::relay::{RelayConnection, RelayFilter};

pub struct RelayPool {
    relays: Vec<RelayConnection>,
    events: mpsc::Receiver<NostrEvent>,
    stamp_provider: Arc<RwLock<Box<dyn StampProvider>>>,
}

impl RelayPool {
    pub async fn connect(urls: &[&str]) -> Result<Self> {
        if urls.is_empty() {
            return Err(KeychatError::InvalidRelayUrl(
                "no relays configured".to_owned(),
            ));
        }

        let (event_tx, event_rx) = mpsc::channel(256);
        let mut relays = Vec::with_capacity(urls.len());
        for url in urls {
            relays.push(
                RelayConnection::connect_with_forwarder((*url).to_owned(), Some(event_tx.clone()))
                    .await?,
            );
        }

        Ok(Self {
            relays,
            events: event_rx,
            stamp_provider: Arc::new(RwLock::new(Box::new(NoopStampProvider))),
        })
    }

    pub fn relays(&self) -> &[RelayConnection] {
        &self.relays
    }

    pub async fn publish(&self, event: &NostrEvent) -> Result<()> {
        if self.relays.is_empty() {
            return Err(KeychatError::InvalidRelayUrl(
                "no relays configured".to_owned(),
            ));
        }

        let futures: Vec<_> = self.relays.iter().map(|r| r.publish(event)).collect();
        let results = futures::future::join_all(futures).await;

        // Succeed if at least one relay accepted
        let mut last_err = None;
        let mut any_ok = false;
        for r in results {
            match r {
                Ok(()) => any_ok = true,
                Err(e) => {
                    // eprintln!("[relay] publish failed on one relay: {e}");
                    last_err = Some(e);
                }
            }
        }
        if any_ok {
            Ok(())
        } else {
            Err(last_err.unwrap_or_else(|| KeychatError::Nostr("all relays failed".to_owned())))
        }
    }

    pub async fn publish_with_stamps(&self, event: &NostrEvent, stamp_config: &StampConfig) -> Result<()> {
        if self.relays.is_empty() {
            return Err(KeychatError::InvalidRelayUrl(
                "no relays configured".to_owned(),
            ));
        }

        let provider = self
            .stamp_provider
            .read()
            .map_err(|_| KeychatError::Nostr("stamp provider lock poisoned".to_owned()))?;
        let mut publish_plan = Vec::with_capacity(self.relays.len());
        let mut last_err = None;
        let mut any_ok = false;

        for relay in &self.relays {
            let stamp = if let Some(fee) = stamp_config.get(relay.url()) {
                match provider.create_stamp(fee.amount, fee.unit.as_str(), &fee.mints) {
                    Ok(token) => Some(token),
                    Err(e) => {
                        // eprintln!("[relay] stamp creation failed for {}: {e}", relay.url());
                        last_err = Some(e);
                        continue;
                    }
                }
            } else {
                None
            };

            publish_plan.push((relay, stamp));
        }
        drop(provider);

        for (relay, stamp) in publish_plan {
            match relay.publish_with_stamp(event, stamp).await {
                Ok(()) => any_ok = true,
                Err(e) => {
                    // eprintln!("[relay] publish failed on one relay: {e}");
                    last_err = Some(e);
                }
            }
        }
        if any_ok {
            Ok(())
        } else {
            Err(last_err.unwrap_or_else(|| KeychatError::Nostr("all relays failed".to_owned())))
        }
    }

    pub fn set_stamp_provider(&self, provider: Box<dyn StampProvider>) -> Result<()> {
        let mut guard = self
            .stamp_provider
            .write()
            .map_err(|_| KeychatError::Nostr("stamp provider lock poisoned".to_owned()))?;
        *guard = provider;
        Ok(())
    }

    pub async fn subscribe(&self, filter: RelayFilter) -> Result<String> {
        let sub_id = format!("sub-{:016x}", rand::random::<u64>());
        for relay in &self.relays {
            relay.subscribe(sub_id.clone(), filter.clone()).await?;
        }
        Ok(sub_id)
    }

    /// Subscribe with a specific subscription ID.
    pub async fn subscribe_with_id(&self, sub_id: &str, filter: RelayFilter) -> Result<()> {
        for relay in &self.relays {
            relay.subscribe(sub_id.to_owned(), filter.clone()).await?;
        }
        Ok(())
    }

    pub async fn unsubscribe(&self, sub_id: &str) -> Result<()> {
        for relay in &self.relays {
            relay.unsubscribe(sub_id.to_owned()).await?;
        }
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        for relay in &self.relays {
            relay.disconnect().await?;
        }
        Ok(())
    }

    pub async fn next_event(&mut self) -> Option<NostrEvent> {
        self.events.recv().await
    }
}
