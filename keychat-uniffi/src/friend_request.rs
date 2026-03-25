use std::sync::Arc;

use libkeychat::{
    accept_friend_request_persistent, generate_prekey_material, send_friend_request_persistent,
    serialize_prekey_material, AddressManager, ChatSession, FriendRequestReceived,
    KCFriendRequestPayload, KCMessage,
};
use nostr::PublicKey;

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
            let id = inner
                .identity
                .clone()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "no identity".into(),
                })?;
            let did = inner.next_signal_device_id;
            inner.next_signal_device_id += 1;
            (id, inner.storage.clone(), did)
        }; // lock dropped

        // 2. Generate keys and send (async, no lock held)
        let keys = generate_prekey_material()?;

        // Serialize keys for persistence before they're consumed
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
            serialize_prekey_material(&keys)?;

        let (event, state) = send_friend_request_persistent(
            &identity,
            &peer_nostr_pubkey,
            &my_name,
            &device_id,
            keys,
            storage.clone(),
            signal_device_id,
        )
        .await?;

        let request_id = state.request_id.clone();
        let first_inbox_secret = state.first_inbox_keys.secret_hex();

        // 2b. Persist pending FR to SQLCipher
        {
            let store = storage.lock().map_err(|e| KeychatUniError::Storage {
                msg: format!("storage lock: {e}"),
            })?;
            store.save_pending_fr(
                &request_id,
                signal_device_id,
                &id_pub,
                &id_priv,
                reg_id,
                spk_id,
                &spk_rec,
                pk_id,
                &pk_rec,
                kpk_id,
                &kpk_rec,
                &first_inbox_secret,
                &peer_nostr_pubkey,
            )?;
        }
        tracing::info!(
            "persisted pending FR reqId={}",
            &request_id[..16.min(request_id.len())]
        );

        // 3. Publish async — don't block waiting for relay OK responses
        {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "not connected".into(),
                })?;
            transport.publish_event_async(event).await?;
        }

        // 4. Store pending state in memory
        {
            let mut inner = self.inner.write().await;
            inner.pending_outbound.insert(request_id.clone(), state);
        }

        // 5. Refresh subscriptions to include first_inbox for this pending FR
        let _ = self.refresh_subscriptions().await;

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
        // 1. Load inbound FR from DB, extract needed data
        let (identity, storage, signal_device_id, received) = {
            let mut inner = self.inner.write().await;
            let id = inner
                .identity
                .clone()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "no identity".into(),
                })?;

            // Load from SQLCipher instead of in-memory HashMap
            let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
                msg: format!("storage lock: {e}"),
            })?;
            let (sender_pubkey_hex, message_json, payload_json) = store
                .load_inbound_fr(&request_id)
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("load_inbound_fr: {e}"),
                })?
                .ok_or(KeychatUniError::InvalidArgument {
                    msg: format!("no pending inbound request: {request_id}"),
                })?;
            drop(store);

            let message: KCMessage = serde_json::from_str(&message_json).map_err(|e| {
                KeychatUniError::InvalidArgument {
                    msg: format!("deserialize message: {e}"),
                }
            })?;
            let payload: KCFriendRequestPayload =
                serde_json::from_str(&payload_json).map_err(|e| {
                    KeychatUniError::InvalidArgument {
                        msg: format!("deserialize payload: {e}"),
                    }
                })?;
            let sender_pubkey = PublicKey::from_hex(&sender_pubkey_hex).map_err(|e| {
                KeychatUniError::InvalidArgument {
                    msg: format!("parse sender pubkey: {e}"),
                }
            })?;

            let received = FriendRequestReceived {
                sender_pubkey,
                sender_pubkey_hex,
                message,
                payload,
                created_at: 0, // Restored from DB, original rumor timestamp not preserved
            };

            let did = inner.next_signal_device_id;
            inner.next_signal_device_id += 1;
            (id, inner.storage.clone(), did, received)
        }; // lock dropped

        // 2. Accept (async, no lock)
        let keys = generate_prekey_material()?;

        // Serialize keys for persistence
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
            serialize_prekey_material(&keys)?;

        let accepted = accept_friend_request_persistent(
            &identity,
            &received,
            &my_name,
            keys,
            storage.clone(),
            signal_device_id,
        )
        .await?;

        // Use the PEER's Signal identity key (from their FR payload), not our own.
        // The session in our SignalParticipant is stored under this key as remote_address.
        let peer_signal_hex = received.payload.signal_identity_key.clone();
        let peer_nostr_hex = received.sender_pubkey_hex.clone();
        let peer_name = received.payload.name.clone();

        // 3. Publish approval event async — don't block waiting for relay OK responses
        {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "not connected".into(),
                })?;
            transport.publish_event_async(accepted.event).await?;
        }

        // 4. Create ChatSession and store
        let mut addresses = AddressManager::new();
        addresses.add_peer(
            &peer_signal_hex,
            Some(received.payload.first_inbox.clone()),
            Some(peer_nostr_hex.clone()),
        );
        // Register ratchet-derived receiving address from the acceptance encrypt.
        // This ensures we subscribe to the address that the peer will send messages to.
        if accepted.sender_address.is_some() {
            let _ = addresses.on_encrypt(&peer_signal_hex, accepted.sender_address.as_deref());
        }
        let session = ChatSession::new(accepted.signal_participant, addresses, identity);

        // 4b. Persist to SQLCipher: signal participant, peer addresses, peer mapping
        {
            let store = storage.lock().map_err(|e| KeychatUniError::Storage {
                msg: format!("storage lock: {e}"),
            })?;
            store.save_signal_participant(
                &peer_signal_hex,
                signal_device_id,
                &id_pub,
                &id_priv,
                reg_id,
                spk_id,
                &spk_rec,
                pk_id,
                &pk_rec,
                kpk_id,
                &kpk_rec,
            )?;

            // Serialize and save address state
            let sess = &session;
            if let Some(addr_state) = sess.addresses.to_serialized(&peer_signal_hex) {
                store.save_peer_addresses(&peer_signal_hex, &addr_state)?;
            }

            store.save_peer_mapping(&peer_nostr_hex, &peer_signal_hex, &peer_name)?;

            // Remove the inbound FR now that it's been accepted
            let _ = store.delete_inbound_fr(&request_id);
        }
        tracing::info!(
            "persisted accepted session: signal={} nostr={}",
            &peer_signal_hex[..16.min(peer_signal_hex.len())],
            &peer_nostr_hex[..16.min(peer_nostr_hex.len())]
        );

        {
            let mut inner = self.inner.write().await;
            inner.sessions.insert(
                peer_signal_hex.clone(),
                Arc::new(tokio::sync::Mutex::new(session)),
            );
            inner
                .peer_nostr_to_signal
                .insert(peer_nostr_hex.clone(), peer_signal_hex.clone());
        }

        // Refresh relay subscriptions to include the new session's receiving addresses
        let _ = self.refresh_subscriptions().await;

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
        // Remove from DB. Optionally could send a reject message in the future.
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .delete_inbound_fr(&request_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("delete_inbound_fr: {e}"),
            })?;
        Ok(())
    }
}
