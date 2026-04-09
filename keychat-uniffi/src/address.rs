use crate::client::KeychatClient;
use crate::error::KeychatUniError;

impl KeychatClient {
    /// Re-subscribe to current identity + all receiving addresses.
    /// Called after address rotation or on reconnect.
    /// Uses cursor-based `since` for identity keys, `now()` for ratchet keys.
    pub(crate) async fn refresh_subscriptions(&self) -> Result<(), KeychatUniError> {
        let (identity_pubkeys, ratchet_pubkeys) = {
            let inner = self.app.inner.read().await;
            inner.protocol.collect_subscribe_pubkeys().await
        };
        let total = identity_pubkeys.len() + ratchet_pubkeys.len();
        if total == 0 {
            tracing::debug!("📡 SUB: no pubkeys to subscribe");
            return Ok(());
        }

        let all_pubkeys: Vec<_> = identity_pubkeys
            .iter()
            .chain(ratchet_pubkeys.iter())
            .collect();
        tracing::info!(
            "📡 SUB: subscribing to {} pubkeys ({} identity, {} ratchet): [{}]",
            total,
            identity_pubkeys.len(),
            ratchet_pubkeys.len(),
            all_pubkeys
                .iter()
                .map(|pk| {
                    let h = pk.to_hex();
                    h[..16.min(h.len())].to_string()
                })
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Read cursor for identity key since parameter
        let identity_since = {
            let inner = self.app.inner.read().await;
            let storage = inner
                .protocol
                .storage()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cursor = storage.get_min_relay_cursor().unwrap_or(0);
            if cursor > 0 {
                let two_days_secs: u64 = 2 * 24 * 60 * 60;
                Some(libkeychat::Timestamp::from(
                    cursor.saturating_sub(two_days_secs),
                ))
            } else {
                None
            }
        };
        let ratchet_since = Some(libkeychat::Timestamp::now());

        let inner = self.app.inner.read().await;
        let transport = inner
            .protocol
            .transport()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;

        if !identity_pubkeys.is_empty() {
            transport
                .subscribe(identity_pubkeys, identity_since)
                .await?;
        }
        if !ratchet_pubkeys.is_empty() {
            transport.subscribe(ratchet_pubkeys, ratchet_since).await?;
        }
        Ok(())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Get all current receiving addresses (for debugging/monitoring).
    /// C-FFI1: uses .lock().await to avoid silently skipping busy sessions.
    pub async fn get_all_receiving_addresses(&self) -> Vec<String> {
        let session_arcs: Vec<_> = {
            let inner = self.app.inner.read().await;
            inner.protocol.all_session_arcs()
        };
        let mut addrs = Vec::new();
        for session_mutex in &session_arcs {
            let session = session_mutex.lock().await;
            addrs.extend(session.addresses.get_all_receiving_address_strings());
        }
        addrs
    }
}
