use libkeychat::{DeviceId, KCMessage, ProtocolAddress};

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn send_text(
        &self,
        room_id: String,
        text: String,
        _format: Option<String>,
        _reply_to: Option<ReplyToPayload>,
        _thread_id: Option<String>,
    ) -> Result<SentMessage, KeychatUniError> {
        // 1. Get Arc<Mutex<ChatSession>> and check transport exists
        let (session_mutex, peer_signal_hex) = {
            let inner = self.inner.read().await;
            let signal_hex = inner
                .peer_nostr_to_signal
                .get(&room_id)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: room_id.clone(),
                })?
                .clone();
            let session = inner
                .sessions
                .get(&signal_hex)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: signal_hex.clone(),
                })?
                .clone();
            // Verify transport is available
            if inner.transport.is_none() {
                return Err(KeychatUniError::NotInitialized {
                    msg: "not connected".into(),
                });
            }
            (session, signal_hex)
        }; // RwLock dropped here

        // 2. Lock only the specific peer session — encrypt the message
        let remote_addr = ProtocolAddress::new(peer_signal_hex.clone(), DeviceId::new(1).unwrap());
        let msg = KCMessage::text(&text);
        let payload_json = msg.to_json().ok();

        let (event, addr_update) = {
            let mut session = session_mutex.lock().await;
            session
                .send_message(&peer_signal_hex, &remote_addr, &msg)
                .await?
        };

        // 3. Serialize event before publishing (for resend support)
        let nostr_event_json = serde_json::to_string(&event).ok();
        let event_id = event.id.to_hex();

        // 4. Get connected relays list before publishing
        let connected = {
            let inner = self.inner.read().await;
            let transport = inner.transport.as_ref().ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
            transport.connected_relays().await
        };

        if connected.is_empty() {
            return Err(KeychatUniError::Transport {
                msg: "no relay connected".into(),
            });
        }

        // 5. Publish to relays — relay OK responses come via event loop
        let inner = self.inner.read().await;
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::NotInitialized {
            msg: "not connected".into(),
        })?;
        let _published_id = transport.publish_event_async(event).await?;
        tracing::info!(
            "⬆️ SENT eventId={} to {} relays (async OK)",
            &event_id[..16.min(event_id.len())],
            connected.len()
        );

        Ok(SentMessage {
            event_id,
            payload_json,
            nostr_event_json,
            connected_relays: connected,
            new_receiving_addresses: addr_update.new_receiving,
            dropped_receiving_addresses: addr_update.dropped_receiving,
            new_sending_address: addr_update.new_sending,
        })
    }
}
