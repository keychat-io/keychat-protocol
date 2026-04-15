//! Friend request business logic — delegates protocol to ProtocolClient,
//! handles app-layer persistence (rooms, contacts, messages, DataChange).

use crate::app_client::{lock_app_storage, npub_from_hex, AppClient, AppError, AppResult};
use crate::types::*;

impl AppClient {
    pub async fn send_friend_request(
        &self,
        peer_nostr_pubkey: String,
        my_name: String,
        device_id: String,
    ) -> AppResult<PendingFriendRequest> {
        let identity_pubkey = self.cached_identity_pubkey();

        // 1. Protocol: generate keys, publish, persist to SecureStorage, store in memory
        let (request_id, event_id_hex) = {
            let mut inner = self.inner.write().await;
            inner
                .protocol
                .send_friend_request_protocol(&peer_nostr_pubkey, &my_name, &device_id)
                .await?
        };

        // 2. App: persist to app_storage
        let peer_npub = npub_from_hex(peer_nostr_pubkey.clone()).unwrap_or_default();
        let room_id = make_room_id(&peer_nostr_pubkey, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.transaction(|_| {
                store.save_app_room(
                    &peer_nostr_pubkey,
                    &identity_pubkey,
                    RoomStatus::Requesting.to_i32(),
                    RoomType::Dm.to_i32(),
                    None,
                    None,
                    None,
                )?;
                store.save_app_contact(&peer_nostr_pubkey, &peer_npub, &identity_pubkey, None)?;
                store.save_app_message(
                    &request_id,
                    Some(&event_id_hex),
                    &room_id,
                    &identity_pubkey,
                    &identity_pubkey,
                    "[Friend Request Sent]",
                    true,
                    MessageStatus::Success.to_i32(),
                    now,
                )?;
                store.update_app_room(
                    &room_id,
                    None,
                    None,
                    Some("[Friend Request Sent]"),
                    Some(now),
                )?;
                Ok(())
            });
        }

        self.emit_data_change(DataChange::RoomListChanged).await;
        self.emit_data_change(DataChange::ContactListChanged).await;
        self.emit_data_change(DataChange::MessageAdded {
            room_id,
            msgid: request_id.clone(),
        })
        .await;

        // Re-subscribe to include the new first_inbox address for receiving the approve response
        {
            let mut inner = self.inner.write().await;
            if let Err(e) = inner.protocol.refresh_subscriptions().await {
                tracing::warn!("refresh_subscriptions after send_friend_request: {e}");
            }
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
    ) -> AppResult<ContactInfo> {
        // 1. Protocol: load FR, generate keys, accept, create session, persist, publish
        let (peer_signal_hex, peer_nostr_hex, peer_name, event_id_hex) = {
            let mut inner = self.inner.write().await;
            inner
                .protocol
                .accept_friend_request_protocol(&request_id, &my_name)
                .await?
        };

        // 2. App: update room, create message
        let identity_pubkey = self.cached_identity_pubkey();
        let room_id = make_room_id(&peer_nostr_hex, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let msgid = format!("accept-{}", request_id);
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.transaction(|_| {
                store.update_app_room(
                    &room_id,
                    Some(RoomStatus::Enabled.to_i32()),
                    None,
                    Some("[Friend Request Accepted]"),
                    Some(now),
                )?;
                store.update_contact_name(&peer_nostr_hex, &identity_pubkey, &peer_name)?;
                store.save_app_message(
                    &msgid,
                    Some(&event_id_hex),
                    &room_id,
                    &identity_pubkey,
                    &identity_pubkey,
                    "[Friend Request Accepted]",
                    true,
                    MessageStatus::Success.to_i32(),
                    now,
                )?;
                Ok(())
            });
        }

        self.emit_data_change(DataChange::RoomUpdated {
            room_id: room_id.clone(),
        })
        .await;
        self.emit_data_change(DataChange::ContactListChanged).await;
        self.emit_data_change(DataChange::MessageAdded { room_id, msgid })
            .await;

        // Re-subscribe to include new ratchet-derived addresses
        {
            let mut inner = self.inner.write().await;
            if let Err(e) = inner.protocol.refresh_subscriptions().await {
                tracing::warn!("refresh_subscriptions after accept_friend_request: {e}");
            }
        }

        Ok(ContactInfo {
            nostr_pubkey_hex: peer_nostr_hex,
            signal_id_hex: peer_signal_hex,
            display_name: peer_name,
        })
    }

    /// Export my contact bundle (§6.5 offline/QR mode).
    ///
    /// Returns a JSON string encoding a `KCFriendRequestPayload`. The caller
    /// shares this out-of-band (QR code, copy-paste, etc); the receiver feeds
    /// it into `add_contact_via_bundle` to establish a session.
    ///
    /// No relay event is published here. A `pending_outbound` entry is saved
    /// so the eventual PreKey reply decrypts (same contract as the online FR
    /// path). `firstInbox` is added to the identity-key subscription filter.
    pub async fn export_contact_bundle(
        &self,
        my_name: String,
        device_id: String,
    ) -> AppResult<String> {
        let mut inner = self.inner.write().await;
        let bundle = inner
            .protocol
            .export_bundle_protocol(&my_name, &device_id)
            .await?;
        Ok(bundle)
    }

    /// Add a contact from a peer-supplied bundle (§6.5 offline/QR mode).
    ///
    /// Consumes the bundle (a JSON `KCFriendRequestPayload` from the peer,
    /// delivered out-of-band), runs the standard accept path end-to-end:
    /// process X3DH, encrypt a `friendApprove` PreKey message, publish to
    /// peer's `firstInbox`, establish session, persist everything.
    ///
    /// The app-layer persistence mirrors `accept_friend_request`: a new
    /// room is created (status=Enabled), a contact row written, an
    /// "[Friend Added via Bundle]" marker message saved.
    pub async fn add_contact_via_bundle(
        &self,
        bundle_json: String,
        my_name: String,
    ) -> AppResult<ContactInfo> {
        // 1. Protocol: parse, X3DH, publish PreKey, create session, persist.
        let (peer_signal_hex, peer_nostr_hex, peer_name, event_id_hex) = {
            let mut inner = self.inner.write().await;
            inner
                .protocol
                .add_contact_via_bundle_protocol(&bundle_json, &my_name)
                .await?
        };

        // 2. App: create room as already-enabled, save contact + marker message.
        let identity_pubkey = self.cached_identity_pubkey();
        let peer_npub = npub_from_hex(peer_nostr_hex.clone()).unwrap_or_default();
        let room_id = make_room_id(&peer_nostr_hex, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let msgid = format!("bundle-add-{}", event_id_hex);
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.transaction(|_| {
                store.save_app_room(
                    &peer_nostr_hex,
                    &identity_pubkey,
                    RoomStatus::Enabled.to_i32(),
                    RoomType::Dm.to_i32(),
                    None,
                    None,
                    None,
                )?;
                store.save_app_contact(&peer_nostr_hex, &peer_npub, &identity_pubkey, None)?;
                store.update_contact_name(&peer_nostr_hex, &identity_pubkey, &peer_name)?;
                store.save_app_message(
                    &msgid,
                    Some(&event_id_hex),
                    &room_id,
                    &identity_pubkey,
                    &identity_pubkey,
                    "[Friend Added via Bundle]",
                    true,
                    MessageStatus::Success.to_i32(),
                    now,
                )?;
                store.update_app_room(
                    &room_id,
                    None,
                    None,
                    Some("[Friend Added via Bundle]"),
                    Some(now),
                )?;
                Ok(())
            });
        }

        self.emit_data_change(DataChange::RoomListChanged).await;
        self.emit_data_change(DataChange::ContactListChanged).await;
        self.emit_data_change(DataChange::MessageAdded {
            room_id: room_id.clone(),
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
    ) -> AppResult<()> {
        // 1. Protocol: delete from SecureStorage
        let sender_pubkey_hex = {
            let inner = self.inner.read().await;
            inner.protocol.reject_friend_request_protocol(&request_id)?
        };

        // 2. App: update room status
        let identity_pubkey = self.cached_identity_pubkey();
        if !sender_pubkey_hex.is_empty() && !identity_pubkey.is_empty() {
            let room_id = make_room_id(&sender_pubkey_hex, &identity_pubkey);
            {
                let app_storage = self.inner.read().await.app_storage.clone();
                let store = lock_app_storage(&app_storage);
                let _ = store.update_app_room(
                    &room_id,
                    Some(RoomStatus::Rejected.to_i32()),
                    None,
                    Some("[Friend Request Rejected]"),
                    None,
                );
            }
            self.emit_data_change(DataChange::RoomUpdated { room_id })
                .await;
        }

        Ok(())
    }
}
