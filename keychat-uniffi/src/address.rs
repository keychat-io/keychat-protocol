use crate::client::KeychatClient;
use crate::error::KeychatUniError;

impl KeychatClient {
    /// Re-subscribe to current identity + all receiving addresses.
    /// Called after address rotation or on reconnect.
    pub(crate) async fn refresh_subscriptions(&self) -> Result<(), KeychatUniError> {
        let pubkeys = self.collect_subscribe_pubkeys().await;
        if pubkeys.is_empty() {
            tracing::debug!("📡 SUB: no pubkeys to subscribe");
            return Ok(());
        }

        tracing::info!(
            "📡 SUB: subscribing to {} pubkeys: [{}]",
            pubkeys.len(),
            pubkeys
                .iter()
                .map(|pk| {
                    let h = pk.to_hex();
                    h[..16.min(h.len())].to_string()
                })
                .collect::<Vec<_>>()
                .join(", ")
        );

        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        transport.subscribe(pubkeys, None).await?;
        Ok(())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Get all current receiving addresses (for debugging/monitoring).
    /// C-FFI1: uses .lock().await to avoid silently skipping busy sessions.
    pub async fn get_all_receiving_addresses(&self) -> Vec<String> {
        let session_arcs: Vec<_> = {
            let inner = self.inner.read().await;
            inner.sessions.values().cloned().collect()
        };
        let mut addrs = Vec::new();
        for session_mutex in &session_arcs {
            let session = session_mutex.lock().await;
            addrs.extend(session.addresses.get_all_receiving_address_strings());
        }
        addrs
    }
}
