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
        let (identity, storage, signal_device_id, identity_pubkey) = {
            let mut inner = self.inner.write().await;
            let id = inner
                .identity
                .clone()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "no identity".into(),
                })?;
            let pubkey_hex = id.pubkey_hex();
            let did = inner.next_signal_device_id;
            inner.next_signal_device_id += 1;
            (id, inner.storage.clone(), did, pubkey_hex)
        }; // lock dropped

        // 2. Generate keys and send (async, no lock held)
        let keys = generate_prekey_material()?;
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
        let event_id_hex = event.id.to_hex();

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

        // 6. Write to app_* tables: room (status=0 requesting) + contact + message
        let peer_npub = crate::npub_from_hex(peer_nostr_pubkey.clone()).unwrap_or_default();
        let room_id = format!("{}:{}", peer_nostr_pubkey, identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let fr_storage = self.inner.read().await.storage.clone();
        if let Some(store) = fr_storage.lock().ok() {
            if let Err(e) = store.transaction(|_| {
                store.save_app_room(&peer_nostr_pubkey, &identity_pubkey, 0, 0, None, None)?;
                store.save_app_contact(&peer_nostr_pubkey, &peer_npub, &identity_pubkey, None)?;
                store.save_app_message(
                    &request_id, Some(&event_id_hex), &room_id, &identity_pubkey,
                    &identity.pubkey_hex(), "[Friend Request Sent]", true, 1, now,
                )?;
                store.update_app_room(&room_id, None, None, Some("[Friend Request Sent]"), Some(now))?;
                Ok(())
            }) {
                tracing::warn!("send_friend_request app tables: {e}");
            }
        }
        drop(fr_storage);

        self.emit_data_change(DataChange::RoomListChanged).await;
        self.emit_data_change(DataChange::ContactListChanged).await;
        self.emit_data_change(DataChange::MessageAdded {
            room_id: room_id.clone(),
            msgid: request_id.clone(),
        })
        .await;

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
                created_at: 0,
            };

            let did = inner.next_signal_device_id;
            inner.next_signal_device_id += 1;
            (id, inner.storage.clone(), did, received)
        }; // lock dropped

        // 2. Accept (async, no lock)
        let keys = generate_prekey_material()?;
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

        let peer_signal_hex = received.payload.signal_identity_key.clone();
        let peer_nostr_hex = received.sender_pubkey_hex.clone();
        let peer_name = received.payload.name.clone();

        // 3. Publish approval event async
        let accept_event_id_hex = accepted.event.id.to_hex();
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
        if accepted.sender_address.is_some() {
            let _ = addresses.on_encrypt(&peer_signal_hex, accepted.sender_address.as_deref());
        }
        let session = ChatSession::new(accepted.signal_participant, addresses, identity.clone());

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

            if let Some(addr_state) = session.addresses.to_serialized(&peer_signal_hex) {
                store.save_peer_addresses(&peer_signal_hex, &addr_state)?;
            }

            store.save_peer_mapping(&peer_nostr_hex, &peer_signal_hex, &peer_name)?;

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

        let _ = self.refresh_subscriptions().await;

        // 5. Write to app_* tables: update room status to enabled, create acceptance message
        let identity_pubkey = identity.pubkey_hex();
        let room_id = format!("{}:{}", peer_nostr_hex, identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let msgid = format!("accept-{}", request_id);
        let accept_storage = self.inner.read().await.storage.clone();
        if let Some(store) = accept_storage.lock().ok() {
            if let Err(e) = store.transaction(|_| {
                store.update_app_room(&room_id, Some(1), None, Some("[Friend Request Accepted]"), Some(now))?;
                store.update_app_contact(&peer_nostr_hex, &identity_pubkey, None, Some(&peer_name), None)?;
                store.save_app_message(
                    &msgid, Some(&accept_event_id_hex), &room_id, &identity_pubkey,
                    &identity.pubkey_hex(), "[Friend Request Accepted]", true, 1, now,
                )?;
                Ok(())
            }) {
                tracing::warn!("accept_friend_request app tables: {e}");
            }
        }
        drop(accept_storage);

        self.emit_data_change(DataChange::RoomUpdated {
            room_id: room_id.clone(),
        })
        .await;
        self.emit_data_change(DataChange::ContactListChanged).await;
        self.emit_data_change(DataChange::MessageAdded {
            room_id,
            msgid,
        })
        .await;

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
        // Load sender info before deleting
        let (sender_pubkey_hex, identity_pubkey) = {
            let inner = self.inner.read().await;
            let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
                msg: format!("storage lock: {e}"),
            })?;
            let fr = store
                .load_inbound_fr(&request_id)
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("load_inbound_fr: {e}"),
                })?;
            let pubkey_hex = inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default();
            let sender = fr.map(|(pubkey, _, _)| pubkey).unwrap_or_default();

            // Delete from DB
            store
                .delete_inbound_fr(&request_id)
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("delete_inbound_fr: {e}"),
                })?;

            (sender, pubkey_hex)
        };

        // Update room status to rejected (-1)
        if !sender_pubkey_hex.is_empty() && !identity_pubkey.is_empty() {
            let room_id = format!("{}:{}", sender_pubkey_hex, identity_pubkey);
            let rej_storage = self.inner.read().await.storage.clone();
            if let Some(store) = rej_storage.lock().ok() {
                if let Err(e) = store.update_app_room(
                    &room_id, Some(-1), None, Some("[Friend Request Rejected]"), None,
                ) {
                    tracing::warn!("reject_friend_request update_app_room: {e}");
                }
            }
            drop(rej_storage);
            self.emit_data_change(DataChange::RoomUpdated { room_id }).await;
        }

        Ok(())
    }
}
