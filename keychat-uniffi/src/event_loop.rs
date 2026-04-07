//! Event loop — thin UniFFI wrapper.
//!
//! The event processing logic lives in keychat-app-core/src/event_loop.rs.
//! This file only provides the #[uniffi::export] annotations for Swift/Kotlin.
//! CLI uses AppClient.start_event_loop(Arc<Self>) directly.

use std::sync::Arc;

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Start the event loop: subscribe to relay notifications and dispatch events.
    /// Delegates to AppClient.start_event_loop() via an internal Arc.
    pub async fn start_event_loop(self: Arc<Self>) -> Result<(), KeychatUniError> {
        // AppClient.start_event_loop needs Arc<AppClient>.
        // Since KeychatClient holds AppClient by value, we need a workaround.
        // The event loop only accesses self.app.inner (RwLock) which is shared.
        // We re-implement the minimal subscribe + spawn logic here, delegating
        // the actual event handling to AppClient methods.

        // 1. Subscribe
        {
            let mut inner = self.app.inner.write().await;
            inner.protocol.refresh_subscriptions().await?;
        }

        // 2. Create stop channel
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        {
            let mut inner = self.app.inner.write().await;
            inner.event_loop_stop = Some(stop_tx);
        }

        // 3. Spawn timeout checker
        let self_t = Arc::clone(&self);
        let mut timeout_stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = timeout_stop.changed() => break,
                    _ = interval.tick() => {
                        let updates = {
                            let mut t = self_t.app.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
                            t.check_timeouts(5)
                        };
                        for u in updates { self_t.app.apply_relay_status_update(u).await; }
                    }
                }
            }
        });

        // 4. Spawn main event loop — delegates to AppClient.handle_incoming_event()
        let self_e = Arc::clone(&self);
        let mut stop = stop_rx;
        tokio::spawn(async move {
            let nostr_client = {
                let inner = self_e.app.inner.read().await;
                match inner.protocol.transport.as_ref() {
                    Some(t) => t.client().clone(),
                    None => return,
                }
            };
            let mut notifications = nostr_client.notifications();

            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    result = notifications.recv() => {
                        match result {
                            Ok(libkeychat::RelayPoolNotification::Event { relay_url, event, .. }) => {
                                let deduped = {
                                    let inner = self_e.app.inner.read().await;
                                    match inner.protocol.transport.as_ref() {
                                        Some(t) => t.deduplicate((*event).clone()).await,
                                        None => None,
                                    }
                                };
                                if let Some(event) = deduped {
                                    if event.kind == libkeychat::Kind::GiftWrap {
                                        let relay = relay_url.to_string();
                                        let event_json = serde_json::to_string(&event).ok();
                                        self_e.app.handle_incoming_event(&event, Some(relay), event_json).await;
                                    }
                                }
                            }
                            Ok(libkeychat::RelayPoolNotification::Message { relay_url, message }) => {
                                // Handle relay OK responses
                                if let libkeychat::RelayMessage::Ok { event_id, status, message: msg } = message {
                                    self_e.app.handle_relay_ok(&event_id.to_hex(), &relay_url.to_string(), status, &msg).await;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                tracing::error!("event loop notification error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn stop_event_loop(&self) {
        self.app.stop_event_loop().await;
    }

    pub async fn enable_auto_reconnect(
        self: Arc<Self>,
        max_delay_secs: u32,
    ) -> Result<(), KeychatUniError> {
        self.app.enable_auto_reconnect(max_delay_secs).await.map_err(Into::into)
    }

    pub async fn disable_auto_reconnect(&self) {
        self.app.disable_auto_reconnect().await;
    }

    pub async fn check_connection(self: Arc<Self>) -> ConnectionStatus {
        let core_status = self.app.check_connection().await;
        match core_status {
            keychat_app_core::ConnectionStatus::Disconnected => ConnectionStatus::Disconnected,
            keychat_app_core::ConnectionStatus::Connecting => ConnectionStatus::Connecting,
            keychat_app_core::ConnectionStatus::Connected => ConnectionStatus::Connected,
            keychat_app_core::ConnectionStatus::Reconnecting => ConnectionStatus::Reconnecting,
            keychat_app_core::ConnectionStatus::Failed => ConnectionStatus::Failed,
        }
    }
}
