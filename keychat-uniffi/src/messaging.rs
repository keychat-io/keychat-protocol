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
        // 1. Get Arc<Mutex<ChatSession>> and transport client (clone), then drop RwLock
        let (session_mutex, peer_signal_hex, nostr_client) = {
            let inner = self.inner.read().await;
            // room_id for 1v1 is the peer's nostr pubkey
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
                .clone(); // Arc clone — cheap
            let client = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "not connected".into(),
                })?
                .client()
                .clone();
            (session, signal_hex, client)
        }; // RwLock dropped here

        // 2. Lock only the specific peer session (other peers unblocked)
        let remote_addr = ProtocolAddress::new(peer_signal_hex.clone(), DeviceId::new(1).unwrap());
        let msg = KCMessage::text(&text);

        let (event, addr_update) = {
            let mut session = session_mutex.lock().await;
            session
                .send_message(&peer_signal_hex, &remote_addr, &msg)
                .await?
        }; // session Mutex dropped

        let event_id = event.id.to_hex();

        // 3. Publish event (no locks held)
        nostr_client
            .send_event(event)
            .await
            .map_err(|e| KeychatUniError::Transport { msg: e.to_string() })?;

        Ok(SentMessage {
            event_id,
            new_receiving_addresses: addr_update.new_receiving,
            dropped_receiving_addresses: addr_update.dropped_receiving,
            new_sending_address: addr_update.new_sending,
        })
    }
}
