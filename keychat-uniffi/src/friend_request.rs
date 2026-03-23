use std::sync::Arc;

use libkeychat::{
    accept_friend_request_persistent, generate_prekey_material, send_friend_request_persistent,
    AddressManager, ChatSession,
};

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn send_friend_request(
        &self,
        peer_nostr_pubkey: String,
        my_name: String,
        device_id: String,
    ) -> Result<PendingFriendRequest, KeychatUniError> {
        // 1. Extract needed data, drop lock before async
        let (identity, storage, signal_device_id) = {
            let mut inner = self.inner.write().await;
            let id = inner.identity.clone().ok_or(
                KeychatUniError::NotInitialized { msg: "no identity".into() }
            )?;
            let did = inner.next_signal_device_id;
            inner.next_signal_device_id += 1;
            (id, inner.storage.clone(), did)
        }; // lock dropped

        // 2. Generate keys and send (async, no lock held)
        let keys = generate_prekey_material()?;
        let (event, state) = send_friend_request_persistent(
            &identity,
            &peer_nostr_pubkey,
            &my_name,
            &device_id,
            keys,
            storage,
            signal_device_id,
        ).await?;

        let request_id = state.request_id.clone();

        // 3. Publish — get client clone, drop lock, then await
        let nostr_client = {
            let inner = self.inner.read().await;
            inner.transport.as_ref()
                .ok_or(KeychatUniError::NotInitialized { msg: "not connected".into() })?
                .client().clone()
        }; // lock dropped
        nostr_client.send_event(event).await
            .map_err(|e| KeychatUniError::Transport { msg: e.to_string() })?;

        // 4. Store pending state
        {
            let mut inner = self.inner.write().await;
            inner.pending_outbound.insert(request_id.clone(), state);
        }

        Ok(PendingFriendRequest {
            request_id,
            peer_nostr_pubkey,
        })
    }

    pub async fn accept_friend_request(
        &self,
        request_id: String,
        my_name: String,
    ) -> Result<ContactInfo, KeychatUniError> {
        // 1. Extract needed data, drop lock
        let (identity, storage, signal_device_id, received) = {
            let mut inner = self.inner.write().await;
            let id = inner.identity.clone().ok_or(
                KeychatUniError::NotInitialized { msg: "no identity".into() }
            )?;
            let received = inner.pending_inbound.remove(&request_id).ok_or(
                KeychatUniError::InvalidArgument { msg: format!("no pending request: {request_id}") }
            )?;
            let did = inner.next_signal_device_id;
            inner.next_signal_device_id += 1;
            (id, inner.storage.clone(), did, received)
        }; // lock dropped

        // 2. Accept (async, no lock)
        let keys = generate_prekey_material()?;
        let accepted = accept_friend_request_persistent(
            &identity,
            &received,
            &my_name,
            keys,
            storage,
            signal_device_id,
        ).await?;

        let peer_signal_hex = accepted.signal_participant.identity_public_key_hex();
        let peer_nostr_hex = received.sender_pubkey_hex.clone();
        let peer_name = received.payload.name.clone();

        // 3. Publish approval event
        let nostr_client = {
            let inner = self.inner.read().await;
            inner.transport.as_ref()
                .ok_or(KeychatUniError::NotInitialized { msg: "not connected".into() })?
                .client().clone()
        };
        nostr_client.send_event(accepted.event).await
            .map_err(|e| KeychatUniError::Transport { msg: e.to_string() })?;

        // 4. Create ChatSession and store
        let mut addresses = AddressManager::new();
        addresses.add_peer(
            &peer_signal_hex,
            Some(received.payload.first_inbox.clone()),
            Some(peer_nostr_hex.clone()),
        );
        let session = ChatSession::new(
            accepted.signal_participant,
            addresses,
            identity,
        );

        {
            let mut inner = self.inner.write().await;
            inner.sessions.insert(
                peer_signal_hex.clone(),
                Arc::new(tokio::sync::Mutex::new(session)),
            );
            inner.peer_nostr_to_signal.insert(peer_nostr_hex.clone(), peer_signal_hex.clone());
        }

        Ok(ContactInfo {
            nostr_pubkey_hex: peer_nostr_hex,
            signal_id_hex: peer_signal_hex,
            display_name: peer_name,
        })
    }

    pub async fn reject_friend_request(
        &self,
        request_id: String,
        _message: Option<String>,
    ) -> Result<(), KeychatUniError> {
        // Just remove from pending. Optionally could send a reject message in the future.
        let mut inner = self.inner.write().await;
        inner.pending_inbound.remove(&request_id);
        Ok(())
    }
}
