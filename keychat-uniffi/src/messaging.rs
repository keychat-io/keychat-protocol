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
        // 1. Get Arc<Mutex<ChatSession>> and transport, then drop RwLock
        let (session_mutex, peer_signal_hex, transport) = {
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
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "not connected".into(),
                })?;
            // Clone the fields we need so we can drop the RwLock
            (session, signal_hex, transport as *const _ as usize)
        }; // RwLock dropped here

        // 2. Lock only the specific peer session
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

        // 4. Publish via transport for per-relay results
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::NotInitialized {
                msg: "not connected".into(),
            })?;
        let publish_result = transport.publish_event(event).await?;

        Ok(SentMessage {
            event_id,
            payload_json,
            nostr_event_json,
            success_relays: publish_result.success_relays,
            failed_relays: publish_result
                .failed_relays
                .into_iter()
                .map(|(url, error)| FailedRelayInfo { url, error })
                .collect(),
            new_receiving_addresses: addr_update.new_receiving,
            dropped_receiving_addresses: addr_update.dropped_receiving,
            new_sending_address: addr_update.new_sending,
        })
    }
}
