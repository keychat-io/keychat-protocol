//! Event loop: subscribes to Nostr relay notifications and dispatches
//! incoming events to Swift via the EventListener callback interface.

use std::sync::Arc;

use libkeychat::{
    receive_friend_request, receive_group_invite, receive_signal_message,
    serialize_prekey_material, AddressManager, ChatSession, Event, KCMessageKind, Kind,
    ProtocolAddress, PublicKey, RelayMessage, RelayPoolNotification, Timestamp,
};

use tracing::warn;

use crate::client::{default_device_id, KeychatClient};
use crate::types::*;

/// Context for dispatching a successfully decrypted message.
struct DecryptedContext {
    msg: libkeychat::KCMessage,
    metadata: libkeychat::MessageMetadata,
    sender_nostr_pubkey: String,
    peer_signal_hex: String,
    session_mutex: Arc<tokio::sync::Mutex<ChatSession>>,
    event: Event,
    relay_url: Option<String>,
    nostr_event_json: Option<String>,
}

impl KeychatClient {
    /// Run the event loop, dispatching relay notifications to EventListener.
    /// Exits when stop_rx receives true or on fatal error.
    pub(crate) async fn run_event_loop(
        self: Arc<Self>,
        mut stop_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        // Get the nostr client (clone) under read lock, then drop lock
        let nostr_client = {
            let inner = self.inner.read().await;
            match inner.transport.as_ref() {
                Some(t) => t.client().clone(),
                None => {
                    self.emit_event(ClientEvent::EventLoopError {
                        description: "transport not initialized".into(),
                    })
                    .await;
                    return;
                }
            }
        }; // lock dropped

        let mut notifications = nostr_client.notifications();

        // Periodic relay tracker timeout check (every 5 seconds)
        let self_timeout = Arc::clone(&self);
        let mut timeout_stop_rx = stop_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = timeout_stop_rx.changed() => {
                        tracing::info!("relay timeout task: stop signal received");
                        // Final cleanup of any resolved entries before exit
                        let mut tracker = self_timeout
                            .relay_tracker
                            .lock()
                            .unwrap_or_else(|e: std::sync::PoisonError<_>| e.into_inner());
                        tracker.cleanup_resolved();
                        break;
                    }
                    _ = interval.tick() => {
                        let updates = {
                            let mut tracker = self_timeout
                                .relay_tracker
                                .lock()
                                .unwrap_or_else(|e: std::sync::PoisonError<_>| e.into_inner());
                            tracker.check_timeouts(5)
                        };
                        for update in updates {
                            self_timeout.apply_relay_status_update(update).await;
                        }
                    }
                }
            }
        });

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    tracing::info!("event loop: stop signal received");
                    break;
                }
                result = notifications.recv() => {
                    match result {
                        Ok(RelayPoolNotification::Event {
                            relay_url,
                            event,
                            ..
                        }) => {
                            let eid = event.id.to_hex();
                            let eid_short = &eid[..16.min(eid.len())];

                            // Deduplicate via Transport
                            let deduped = {
                                let inner = self.inner.read().await;
                                match inner.transport.as_ref() {
                                    Some(t) => t.deduplicate((*event).clone()).await,
                                    None => None,
                                }
                            };

                            if let Some(event) = deduped {
                                if event.kind == Kind::GiftWrap {
                                    tracing::info!(
                                        "⬇️ RECV kind={} id={} from={}",
                                        event.kind.as_u16(),
                                        eid_short,
                                        relay_url
                                    );
                                    let relay = relay_url.to_string();
                                    let event_json =
                                        serde_json::to_string(&event).ok();
                                    self.handle_incoming_event(
                                        &event,
                                        Some(relay),
                                        event_json,
                                    )
                                    .await;
                                } else {
                                    tracing::debug!(
                                        "⬇️ RECV kind={} id={} from={} (ignored, not GiftWrap)",
                                        event.kind.as_u16(),
                                        eid_short,
                                        relay_url
                                    );
                                }
                            } else {
                                tracing::debug!(
                                    "⬇️ DUP id={} from={}",
                                    eid_short,
                                    relay_url
                                );
                            }
                        }
                        Ok(RelayPoolNotification::Message {
                            relay_url,
                            message: RelayMessage::Ok { event_id, status, message },
                        }) => {
                            // NIP-01 relay OK response: ["OK", event_id, true/false, message]
                            let eid = event_id.to_hex();
                            tracing::info!(
                                "⬆️ RELAY_OK relay={} eventId={} ok={} msg={}",
                                relay_url,
                                &eid[..16.min(eid.len())],
                                status,
                                &message[..80.min(message.len())]
                            );
                            // Update relay tracker and persist status change
                            let update = {
                                let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
                                tracker.handle_relay_ok(&eid, &relay_url.to_string(), status, &message)
                            };
                            if let Some(update) = update {
                                self.apply_relay_status_update(update).await;
                            }

                            self.emit_event(ClientEvent::RelayOk {
                                event_id: eid,
                                relay_url: relay_url.to_string(),
                                success: status,
                                message,
                            }).await;
                        }
                        Ok(RelayPoolNotification::Shutdown) => {
                            tracing::info!("event loop: relay pool shutdown");
                            break;
                        }
                        Ok(_) => {
                            // Other notification types — ignore
                        }
                        Err(e) => {
                            tracing::warn!("event loop: notification recv error: {e}");
                            // broadcast::RecvError::Lagged — continue
                            // broadcast::RecvError::Closed — break
                            if matches!(e, tokio::sync::broadcast::error::RecvError::Closed) {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handle a single incoming kind:1059 GiftWrap event.
    ///
    /// Tries in order:
    /// 1. Friend request (NIP-17 unwrap → KCMessage FriendRequest)
    /// 2. Friend approve/reject response (pending outbound states)
    /// 3. Existing Signal session message
    /// 4. NIP-17 DM fallback (unwrap succeeds but not a keychat protocol message)
    async fn handle_incoming_event(
        &self,
        event: &Event,
        relay_url: Option<String>,
        nostr_event_json: Option<String>,
    ) {
        let event_hex = event.id.to_hex();
        tracing::info!(
            "[RECV] GiftWrap event_id={}",
            &event_hex[..16.min(event_hex.len())]
        );

        let handled;

        // Step 1: Try as inbound friend request
        if self.try_handle_friend_request(event).await {
            handled = true;
        }
        // Step 2: Try as friend approve/reject on pending outbound
        else if self.try_handle_friend_approve(event).await {
            handled = true;
        }
        // Step 3: Try decrypt with existing sessions
        else if self
            .try_handle_session_message(event, relay_url.clone(), nostr_event_json.clone())
            .await
        {
            handled = true;
        }
        // Step 4: NIP-17 DM fallback — standard NIP-17 message from non-keychat app
        else if self
            .try_handle_nip17_dm(event, relay_url.clone(), nostr_event_json)
            .await
        {
            handled = true;
        } else {
            handled = false;
            tracing::debug!(
                "[UNHANDLED]: no step matched event_id={}",
                &event_hex[..16.min(event_hex.len())]
            );
        }

        // Update relay subscription cursor after successfully processing an event.
        // NIP-17 gift wrap uses randomized outer created_at (±2 days), so the
        // event timestamp can be in the future. Clamp to now to prevent the cursor
        // from advancing past events that haven't been delivered yet.
        if handled {
            if let Some(ref url) = relay_url {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let event_ts = event.created_at.as_u64().min(now);
                let inner = self.inner.read().await;
                let storage = inner.storage.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = storage.update_relay_cursor(url, event_ts) {
                    tracing::error!("failed to update relay cursor for {}: {e}", url);
                }
            }
        }
    }

    /// Step 1: Try to parse as an inbound friend request.
    async fn try_handle_friend_request(&self, event: &Event) -> bool {
        let identity = {
            let inner = self.inner.read().await;
            inner.identity.clone()
        };
        let Some(identity) = identity else {
            tracing::warn!("Step1: no identity set, skipping friend request check");
            return false;
        };

        tracing::debug!("Step1: trying receive_friend_request...");
        let received = match receive_friend_request(&identity, event) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("Step1: not a friend request: {e}");
                return false;
            }
        };

        let request_id = received
            .message
            .id
            .clone()
            .unwrap_or_else(|| format!("fr-{}", event.id.to_hex()));
        let sender_pubkey = received.sender_pubkey_hex.clone();
        let sender_name = received.payload.name.clone();
        let message = received.payload.message.clone();
        let created_at = received.created_at;

        tracing::info!(
            "[Step1] OK: friendRequest from={} name={:?} reqId={}",
            &sender_pubkey[..16.min(sender_pubkey.len())],
            sender_name,
            &request_id[..16.min(request_id.len())]
        );

        // Persist inbound FR to SQLCipher
        {
            let message_json = match serde_json::to_string(&received.message) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!("serialize inbound FR message failed: {e}");
                    return true; // handled (but couldn't persist)
                }
            };
            let payload_json = match serde_json::to_string(&received.payload) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!("serialize inbound FR payload failed: {e}");
                    return true;
                }
            };
            let storage = self.inner.read().await.storage.clone();
            let result = (|| -> std::result::Result<(), Box<dyn std::error::Error>> {
                let store = storage.lock().map_err(|e| format!("{e}"))?;
                store.save_inbound_fr(
                    &request_id,
                    &received.sender_pubkey_hex,
                    &message_json,
                    &payload_json,
                )?;
                Ok(())
            })();
            if let Err(e) = result {
                tracing::error!("persist inbound FR failed: {e}");
            }
        }

        // ── Persist to app_* tables ──────────────────────────────
        let identity_pubkey = self.cached_identity_pubkey();

        if !identity_pubkey.is_empty() {
            let fr_content = message.as_deref().unwrap_or("[Friend Request]");
            let sender_npub = crate::npub_from_hex(sender_pubkey.clone()).unwrap_or_default();
            let msgid = format!("fr-recv-{}", &request_id);
            let event_id_hex = event.id.to_hex();

            // Check if this sender is already a friend (room exists with status=Enabled).
            // If so, auto-approve instead of requiring manual confirmation.
            let existing_room_status = {
                let app_storage = self.inner.read().await.app_storage.clone();
                let store = crate::client::lock_app_storage(&app_storage);
                let room_id = crate::types::make_room_id(&sender_pubkey, &identity_pubkey);
                store
                    .get_app_room(&room_id)
                    .ok()
                    .flatten()
                    .map(|r| r.status)
            };
            let is_existing_friend = existing_room_status == Some(RoomStatus::Enabled.to_i32());

            // DB writes under sync lock (no await while lock held)
            let saved_room_id = {
                let app_storage = self.inner.read().await.app_storage.clone();
                let store = crate::client::lock_app_storage(&app_storage);
                // Dedup: skip if this event was already persisted
                if store
                    .is_app_message_duplicate(&event_id_hex)
                    .unwrap_or(false)
                {
                    tracing::info!(
                        "friend request event already persisted, skipping: {}",
                        &event_id_hex[..16.min(event_id_hex.len())]
                    );
                    None
                } else {
                    // If already a friend, keep status=Enabled (1); otherwise set Approving (2)
                    let room_status = if is_existing_friend { RoomStatus::Enabled.to_i32() } else { RoomStatus::Approving.to_i32() };
                    store
                        .transaction(|_| {
                            let room_id = store.save_app_room(
                                &sender_pubkey,
                                &identity_pubkey,
                                room_status,
                                RoomType::Dm.to_i32(),
                                Some(&sender_name),
                                None,
                                None,
                            )?;
                            store.save_app_contact(
                                &sender_pubkey,
                                &sender_npub,
                                &identity_pubkey,
                                Some(&sender_name),
                            )?;
                            store.save_app_message(
                                &msgid,
                                Some(&event_id_hex),
                                &room_id,
                                &identity_pubkey,
                                &sender_pubkey,
                                fr_content,
                                false,
                                MessageStatus::Success.to_i32(),
                                created_at as i64,
                            )?;
                            store.update_app_room(
                                &room_id,
                                None,
                                None,
                                Some(fr_content),
                                Some(created_at as i64),
                            )?;
                            store.increment_app_room_unread(&room_id)?;
                            Ok(room_id)
                        })
                        .map_err(|e| tracing::error!("PERSIST FAILED: friend request: {e}"))
                        .ok()
                }
            }; // app_storage + MutexGuard dropped

            // Auto-approve if existing friend
            if is_existing_friend {
                tracing::info!(
                    "auto-approving friend request from existing friend: {}",
                    &sender_pubkey[..16.min(sender_pubkey.len())]
                );
                let my_name = {
                    let app_storage = self.inner.read().await.app_storage.clone();
                    let store = crate::client::lock_app_storage(&app_storage);
                    store
                        .get_setting("owner_name")
                        .unwrap_or(None)
                        .unwrap_or_default()
                };
                match self
                    .accept_friend_request(request_id.clone(), my_name)
                    .await
                {
                    Ok(_) => tracing::info!("auto-approved friend request from existing friend"),
                    Err(e) => tracing::warn!("auto-approve failed: {e}"),
                }
            }

            if let Some(room_id) = saved_room_id {
                self.emit_data_change(DataChange::RoomListChanged).await;
                self.emit_data_change(DataChange::ContactListChanged).await;
                self.emit_data_change(DataChange::MessageAdded { room_id, msgid })
                    .await;
            }
        }

        self.emit_event(ClientEvent::FriendRequestReceived {
            request_id,
            sender_pubkey,
            sender_name,
            message,
            created_at,
        })
        .await;

        true
    }

    /// Step 2: Try to decrypt with pending outbound FR states (looking for approve/reject).
    async fn try_handle_friend_approve(&self, event: &Event) -> bool {
        let pending_keys: Vec<(String, String, String)> = {
            let inner = self.inner.read().await;
            inner
                .pending_outbound
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.signal_participant.identity_public_key_hex(),
                        v.peer_nostr_pubkey.clone(),
                    )
                })
                .collect()
        };

        tracing::debug!(
            "Step2: trying {} pending outbound states",
            pending_keys.len()
        );

        // Try each pending outbound state — need &mut signal_participant
        for (request_id, signal_id_hex, peer_nostr_pubkey) in &pending_keys {
            tracing::debug!(
                "Step2: trying reqId={} signal={} peer={}",
                &request_id[..16.min(request_id.len())],
                &signal_id_hex[..16.min(signal_id_hex.len())],
                &peer_nostr_pubkey[..16.min(peer_nostr_pubkey.len())]
            );

            let remote_address = ProtocolAddress::new(signal_id_hex.clone(), default_device_id());

            // Try decrypt under write lock (need &mut signal_participant)
            let result = {
                let mut inner = self.inner.write().await;
                if let Some(state) = inner.pending_outbound.get_mut(request_id) {
                    let r = receive_signal_message(
                        &mut state.signal_participant,
                        &remote_address,
                        event,
                    );
                    Some(r)
                } else {
                    None
                }
            }; // write lock dropped

            match &result {
                Some(Ok((msg, _))) => {
                    tracing::info!(
                        "[Step2] decrypt OK: kind={:?} reqId={}",
                        msg.kind,
                        &request_id[..16.min(request_id.len())]
                    );
                }
                Some(Err(e)) => {
                    tracing::debug!(
                        "Step2: decrypt failed for reqId={}: {e}",
                        &request_id[..16.min(request_id.len())]
                    );
                }
                None => {
                    tracing::debug!(
                        "Step2: reqId={} no longer in pending",
                        &request_id[..16.min(request_id.len())]
                    );
                }
            }

            if let Some(Ok((msg, decrypt_result))) = result {
                if msg.kind == KCMessageKind::FriendApprove {
                    tracing::info!(
                        "[Step2]: FriendApprove from peer={} reqId={}",
                        &peer_nostr_pubkey[..16.min(peer_nostr_pubkey.len())],
                        &request_id[..16.min(request_id.len())]
                    );

                    // Extract the peer info from signal_prekey_auth
                    let peer_name = msg
                        .signal_prekey_auth
                        .as_ref()
                        .map(|auth| auth.name.clone())
                        .unwrap_or_default();
                    let peer_signal_id = msg
                        .signal_prekey_auth
                        .as_ref()
                        .map(|auth| auth.signal_id.clone())
                        .unwrap_or_default();
                    let peer_nostr_id = msg
                        .signal_prekey_auth
                        .as_ref()
                        .map(|auth| auth.nostr_id.clone())
                        .unwrap_or_else(|| peer_nostr_pubkey.clone());

                    tracing::info!(
                        "[Step2]: peer_name={:?} peer_signal_id={} peer_nostr_id={}",
                        peer_name,
                        &peer_signal_id[..16.min(peer_signal_id.len())],
                        &peer_nostr_id[..16.min(peer_nostr_id.len())]
                    );

                    // Take the state out and create ChatSession
                    let mut inner = self.inner.write().await;
                    if let Some(mut state) = inner.pending_outbound.remove(request_id) {
                        let identity = match inner.identity.clone() {
                            Some(id) => id,
                            None => continue,
                        };

                        // Save our first_inbox pubkey before state is consumed.
                        // We need to keep subscribing to it until ratchet takes over,
                        // because the peer sends to our first_inbox before the first
                        // message exchange establishes ratchet-derived addresses.
                        let my_first_inbox_hex = state.first_inbox_keys.pubkey_hex();

                        // Create AddressManager and ChatSession
                        let mut addresses = AddressManager::new();
                        let peer_signal_hex = if peer_signal_id.is_empty() {
                            peer_nostr_id.clone()
                        } else {
                            peer_signal_id
                        };

                        // Fix session address: decrypt used our own identity key
                        // as remote_address (we didn't know the peer's key yet).
                        // Now that we know peer_signal_hex, relocate the session
                        // so encrypt() can find it under the correct address.
                        if peer_signal_hex != *signal_id_hex {
                            let from_addr =
                                ProtocolAddress::new(signal_id_hex.clone(), default_device_id());
                            let to_addr =
                                ProtocolAddress::new(peer_signal_hex.clone(), default_device_id());
                            if let Err(e) = state
                                .signal_participant
                                .relocate_session(&from_addr, &to_addr)
                            {
                                tracing::error!(
                                    "failed to relocate session from {} to {}: {}",
                                    &signal_id_hex[..16.min(signal_id_hex.len())],
                                    &peer_signal_hex[..16.min(peer_signal_hex.len())],
                                    e
                                );
                            }
                        }

                        addresses.add_peer(&peer_signal_hex, None, Some(peer_nostr_id.clone()));

                        // Process decrypt result to register ratchet-derived addresses
                        // (mirroring V2 complete_friend_request behavior)
                        let new_receiving =
                            if let Some(bob_addr) = decrypt_result.bob_derived_address.as_deref() {
                                match addresses.on_decrypt(
                                    &peer_signal_hex,
                                    Some(bob_addr),
                                    decrypt_result.alice_addrs.as_deref(),
                                ) {
                                    Ok(update) => update.new_receiving,
                                    Err(e) => {
                                        tracing::warn!(
                                            "event loop: on_decrypt failed for {}: {}",
                                            peer_signal_hex,
                                            e
                                        );
                                        Vec::new()
                                    }
                                }
                            } else {
                                Vec::new()
                            };

                        // Serialize keys BEFORE signal_participant is moved into ChatSession
                        let serialized_keys = state.signal_participant.keys()
                            .and_then(|k| serialize_prekey_material(k).ok());
                        let signal_device_id =
                            u32::from(state.signal_participant.address().device_id());

                        // Capture receiving addresses before AddressManager is moved
                        let recv_addrs = addresses.get_all_receiving_address_strings();

                        let session =
                            ChatSession::new(state.signal_participant, addresses, identity);

                        inner.sessions.insert(
                            peer_signal_hex.clone(),
                            Arc::new(tokio::sync::Mutex::new(session)),
                        );
                        inner
                            .peer_nostr_to_signal
                            .insert(peer_nostr_id.clone(), peer_signal_hex.clone());
                        inner
                            .peer_signal_to_nostr
                            .insert(peer_signal_hex.clone(), peer_nostr_id.clone());
                        // Update reverse index for O(1) message routing
                        for addr in &recv_addrs {
                            inner.receiving_addr_to_peer.insert(addr.clone(), peer_signal_hex.clone());
                        }

                        tracing::info!(
                            "[Step2]: ChatSession created, peer_signal={} new_receiving={}",
                            &peer_signal_hex[..16.min(peer_signal_hex.len())],
                            new_receiving.len()
                        );

                        // Persist session state to SQLCipher
                        {
                            let store_result = inner.storage.lock();
                            if let Err(ref e) = store_result {
                                tracing::error!(
                                    "[Step2]: storage lock poisoned, session NOT persisted: {e}"
                                );
                            }
                            if let Ok(store) = store_result {
                                // Save peer mapping
                                if let Err(e) = store.save_peer_mapping(
                                    &peer_nostr_id,
                                    &peer_signal_hex,
                                    &peer_name,
                                ) {
                                    tracing::error!("persist peer_mapping failed: {e}");
                                }
                                // Save signal participant (per-peer identity, no one-time prekeys)
                                if let Some((
                                    id_pub, id_priv, reg_id,
                                    spk_id, spk_rec,
                                    _pk_id, _pk_rec, _kpk_id, _kpk_rec,
                                )) = &serialized_keys
                                {
                                    if let Err(e) = store.save_signal_participant(
                                        &peer_signal_hex,
                                        signal_device_id,
                                        id_pub,
                                        id_priv,
                                        *reg_id,
                                        *spk_id,
                                        spk_rec,
                                    ) {
                                        tracing::error!("persist signal_participant failed: {e}");
                                    }
                                }
                                // Delete the pending FR (now an active session)
                                if let Err(e) = store.delete_pending_fr(request_id) {
                                    warn!("delete_pending_fr: {e}");
                                }
                                tracing::info!("[Step2]: persisted session to SQLCipher");
                            }
                        } // store MutexGuard dropped here

                        // Save address state (after store lock released, safe to await session)
                        let storage_for_addr = inner.storage.clone();
                        if let Some(session_mutex) = inner.sessions.get(&peer_signal_hex) {
                            let sess = session_mutex.lock().await;
                            if let Some(addr_state) = sess.addresses.to_serialized(&peer_signal_hex)
                            {
                                if let Ok(store) = storage_for_addr.lock() {
                                    if let Err(e) =
                                        store.save_peer_addresses(&peer_signal_hex, &addr_state)
                                    {
                                        tracing::error!("persist peer_addresses failed: {e}");
                                    }
                                }
                            }
                        }

                        // Collect subscribe pubkeys while still in scope
                        let mut sub_pubkeys: Vec<PublicKey> = new_receiving
                            .iter()
                            .filter_map(|addr| PublicKey::from_hex(addr).ok())
                            .collect();
                        if let Ok(pk) = PublicKey::from_hex(&my_first_inbox_hex) {
                            sub_pubkeys.push(pk);
                        }
                        drop(inner); // C-SEC1: drop write lock BEFORE async subscribe

                        // Re-subscribe with the full current ratchet key set.
                        // Use resubscribe() to unsubscribe previous ratchet slot atomically.
                        let (_, all_ratchet_pubkeys) = self.collect_subscribe_pubkeys().await;
                        if !all_ratchet_pubkeys.is_empty() {
                            let old_ratchet_id = {
                                let inner = self.inner.read().await;
                                inner.subscription_ids.last().map(|s| libkeychat::SubscriptionId::new(s))
                            };
                            let inner = self.inner.read().await;
                            if let Some(transport) = inner.transport.as_ref() {
                                if let Ok(new_id) = transport
                                    .resubscribe(old_ratchet_id, all_ratchet_pubkeys, Some(Timestamp::now()))
                                    .await
                                {
                                    drop(inner);
                                    let mut inner = self.inner.write().await;
                                    if let Some(last) = inner.subscription_ids.last_mut() {
                                        *last = new_id.to_string();
                                    } else {
                                        inner.subscription_ids.push(new_id.to_string());
                                    }
                                }
                            }
                        }
                    } else {
                        drop(inner);
                    }

                    // ── Persist to app_* tables ──────────────────
                    {
                        let identity_pubkey = self.cached_identity_pubkey();
                        if !identity_pubkey.is_empty() {
                            let peer_npub =
                                crate::npub_from_hex(peer_nostr_id.clone()).unwrap_or_default();
                            let msgid = format!("fr-accept-{}", request_id);
                            let event_id_hex = event.id.to_hex();

                            // DB writes under sync lock (no await while lock held)
                            let saved_room_id = {
                                let app_storage = self.inner.read().await.app_storage.clone();
                                {
                                    let store = crate::client::lock_app_storage(&app_storage);
                                    // Dedup: skip if this event was already persisted
                                    if store
                                        .is_app_message_duplicate(&event_id_hex)
                                        .unwrap_or(false)
                                    {
                                        tracing::info!(
                                            "friend accept event already persisted, skipping: {}",
                                            &event_id_hex[..16.min(event_id_hex.len())]
                                        );
                                        None
                                    } else {
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs()
                                            as i64;
                                        store
                                            .transaction(|_| {
                                                let room_id = store.save_app_room(
                                                    &peer_nostr_id,
                                                    &identity_pubkey,
                                                    RoomStatus::Enabled.to_i32(),
                                                    RoomType::Dm.to_i32(),
                                                    Some(&peer_name),
                                                    Some(signal_id_hex),
                                                    None,
                                                )?;
                                                store.save_app_contact(
                                                    &peer_nostr_id,
                                                    &peer_npub,
                                                    &identity_pubkey,
                                                    Some(&peer_name),
                                                )?;
                                                store.save_app_message(
                                                    &msgid,
                                                    Some(&event_id_hex),
                                                    &room_id,
                                                    &identity_pubkey,
                                                    &peer_nostr_id,
                                                    "[Friend Request Accepted]",
                                                    false,
                                                    MessageStatus::Success.to_i32(),
                                                    now,
                                                )?;
                                                store.update_app_room(
                                                    &room_id,
                                                    Some(RoomStatus::Enabled.to_i32()),
                                                    None,
                                                    Some("[Friend Request Accepted]"),
                                                    Some(now),
                                                )?;
                                                store.increment_app_room_unread(&room_id)?;
                                                Ok(room_id)
                                            })
                                            .map_err(|e| tracing::error!("PERSIST FAILED: friend approve: {e}"))
                                            .ok()
                                    }
                                }
                            }; // app_storage + MutexGuard dropped

                            if let Some(room_id) = saved_room_id {
                                self.emit_data_change(DataChange::RoomUpdated {
                                    room_id: room_id.clone(),
                                })
                                .await;
                                self.emit_data_change(DataChange::ContactListChanged).await;
                                self.emit_data_change(DataChange::MessageAdded { room_id, msgid })
                                    .await;
                            }
                        }
                    }

                    self.emit_event(ClientEvent::FriendRequestAccepted {
                        peer_pubkey: peer_nostr_id,
                        peer_name,
                    })
                    .await;

                    return true;
                } else if msg.kind == KCMessageKind::FriendReject {
                    tracing::info!(
                        "[Step2]: FriendReject from peer={} reqId={}",
                        &peer_nostr_pubkey[..16.min(peer_nostr_pubkey.len())],
                        &request_id[..16.min(request_id.len())]
                    );
                    let peer_pubkey = peer_nostr_pubkey.clone();

                    // Remove from pending
                    let mut inner = self.inner.write().await;
                    inner.pending_outbound.remove(request_id);

                    // Update room status to rejected
                    let identity_pubkey = self.cached_identity_pubkey();
                    if !identity_pubkey.is_empty() {
                        let room_id = crate::types::make_room_id(&peer_pubkey, &identity_pubkey);
                        {
                            let store = crate::client::lock_app_storage(&inner.app_storage);
                            if let Err(e) = store.update_app_room(
                                &room_id,
                                Some(RoomStatus::Rejected.to_i32()),
                                None,
                                Some("[Friend Request Rejected]"),
                                None,
                            ) {
                                warn!("update_app_room reject: {e}");
                            }
                        }
                        drop(inner);
                        self.emit_data_change(DataChange::RoomUpdated { room_id })
                            .await;
                    } else {
                        drop(inner);
                    }

                    self.emit_event(ClientEvent::FriendRequestRejected { peer_pubkey })
                        .await;

                    return true;
                }
            }
        }
        false
    }

    /// Step 3: Try to decrypt with existing ChatSessions.
    ///
    /// Uses O(1) p-tag routing: the GiftWrap event's first p-tag is the ratchet-derived
    /// receiving address, which maps to the correct peer session via `receiving_addr_to_peer`.
    /// If no p-tag match, the message is dropped (not for us or index bug — check logs).
    async fn try_handle_session_message(
        &self,
        event: &Event,
        relay_url: Option<String>,
        nostr_event_json: Option<String>,
    ) -> bool {
        // ── O(1) p-tag routing ──
        let p_tags = libkeychat::extract_p_tags(event);
        let first_p = match p_tags.first() {
            Some(p) => p.clone(),
            None => {
                tracing::warn!("Step3: event {} has no p-tag, dropping", &event.id.to_hex()[..16]);
                return false;
            }
        };

        let (peer_id, session_arc) = {
            let inner = self.inner.read().await;
            let peer_id = match inner.receiving_addr_to_peer.get(&first_p) {
                Some(id) => id.clone(),
                None => {
                    tracing::warn!(
                        "Step3: p-tag {} not in reverse index, dropping event {}",
                        &first_p[..16.min(first_p.len())],
                        &event.id.to_hex()[..16]
                    );
                    return false;
                }
            };
            let session = match inner.sessions.get(&peer_id) {
                Some(s) => s.clone(),
                None => {
                    tracing::warn!(
                        "Step3: peer {} found in index but no session, dropping event {}",
                        &peer_id[..16.min(peer_id.len())],
                        &event.id.to_hex()[..16]
                    );
                    return false;
                }
            };
            (peer_id, session)
        }; // RwLock dropped

        tracing::debug!("Step3: O(1) route via p-tag → peer={}", &peer_id[..16.min(peer_id.len())]);

        let peer_signal_hex = &peer_id;
        let session_mutex = &session_arc;
        {
            let remote_address = ProtocolAddress::new(peer_signal_hex.clone(), default_device_id());

            // Lock only this peer's session
            let result = {
                let mut session = session_mutex.lock().await;
                session.receive_message(peer_signal_hex, &remote_address, event)
            }; // session mutex dropped

            match &result {
                Ok((msg, metadata, _)) => {
                    tracing::info!(
                        "[event] Step3 decrypt OK: kind={:?} eventId={} peer={}",
                        msg.kind,
                        &metadata.event_id.to_hex()[..16],
                        &peer_signal_hex[..16.min(peer_signal_hex.len())]
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Step3: decrypt failed for routed peer={}: {e}",
                        &peer_signal_hex[..16.min(peer_signal_hex.len())]
                    );
                    return false;
                }
            }

            if let Ok((msg, metadata, addr_update)) = result {
                self.update_addresses_after_decrypt(
                    peer_signal_hex, session_mutex, &addr_update,
                ).await;

                let sender_nostr_pubkey = {
                    let inner = self.inner.read().await;
                    inner
                        .peer_signal_to_nostr
                        .get(peer_signal_hex)
                        .cloned()
                        .unwrap_or_else(|| peer_signal_hex.clone())
                };

                self.handle_decrypted_message(DecryptedContext {
                    msg, metadata,
                    sender_nostr_pubkey,
                    peer_signal_hex: peer_signal_hex.to_string(),
                    session_mutex: session_mutex.clone(),
                    event: event.clone(),
                    relay_url, nostr_event_json,
                }).await;
                return true;
            }
        }
        false
    }

    /// Step 4: NIP-17 DM fallback — unwrap gift wrap and treat as plain DM.
    /// Called after Steps 1-3 all fail, meaning this is not a keychat protocol message
    /// but a standard NIP-17 DM from another Nostr app.
    async fn try_handle_nip17_dm(
        &self,
        event: &Event,
        relay_url: Option<String>,
        nostr_event_json: Option<String>,
    ) -> bool {
        let identity = {
            let inner = self.inner.read().await;
            inner.identity.clone()
        };
        let Some(identity) = identity else {
            return false;
        };

        // Try to unwrap the gift wrap
        let unwrapped = match libkeychat::giftwrap::unwrap_gift_wrap(identity.keys(), event) {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!("Step4: gift wrap unwrap failed: {e}");
                return false;
            }
        };

        let sender_pubkey = unwrapped.sender_pubkey.to_hex();
        let content = unwrapped.content.clone();
        let event_id = event.id.to_hex();
        let identity_pubkey = identity.pubkey_hex();
        let created_at = unwrapped.created_at.as_u64() as i64;

        tracing::info!(
            "[Step4] NIP-17 DM from={} content_len={} event_id={}",
            &sender_pubkey[..16.min(sender_pubkey.len())],
            content.len(),
            &event_id[..16.min(event_id.len())]
        );

        // Build room_id and persist room + message
        let room_id = crate::types::make_room_id(&sender_pubkey, &identity_pubkey);
        let msgid = event_id.clone();

        // Build a display name from sender pubkey (npub short form)
        let sender_npub = crate::npub_from_hex(sender_pubkey.clone())
            .unwrap_or_else(|_| sender_pubkey.clone());
        let short_name = if sender_npub.len() > 16 {
            format!("{}…", &sender_npub[..16])
        } else {
            sender_npub.clone()
        };

        // Persist to app DB
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = crate::client::lock_app_storage(&app_storage);

            // Create or update room (type = Nip17Dm = 3)
            if let Err(e) = store.save_app_room(
                &sender_pubkey,
                &identity_pubkey,
                1,  // status = enabled
                3,  // room_type = Nip17Dm
                Some(&short_name),
                None, // no signal identity key
                None, // no parent room
            ) {
                tracing::error!("Step4: save_app_room failed: {e}");
                return false;
            }

            // Save message
            if let Err(e) = store.save_app_message(
                &msgid,
                Some(&event_id),
                &room_id,
                &identity_pubkey,
                &sender_pubkey,
                &content,
                false, // is_me_send = false
                1,     // status = success
                created_at,
            ) {
                tracing::error!("Step4: save_app_message failed: {e}");
                return false;
            }

            // Update room last message
            if let Err(e) = store.update_app_room(
                &room_id,
                None,
                None,
                Some(if content.len() > 50 { &content[..50] } else { &content }),
                Some(created_at),
            ) {
                tracing::warn!("Step4: update_app_room failed: {e}");
            }

            // Increment unread count
            if let Err(e) = store.increment_app_room_unread(&room_id) {
                tracing::warn!("Step4: increment_unread failed: {e}");
            }
        }

        // Emit data changes
        self.emit_data_change(crate::types::DataChange::MessageAdded {
            room_id: room_id.clone(),
            msgid: msgid.clone(),
        })
        .await;
        self.emit_data_change(crate::types::DataChange::RoomUpdated {
            room_id: room_id.clone(),
        })
        .await;

        // Emit event to Swift
        self.emit_event(crate::types::ClientEvent::MessageReceived {
            room_id,
            sender_pubkey: sender_pubkey.clone(),
            kind: crate::types::MessageKind::Text,
            content: Some(content),
            payload: None,
            event_id,
            fallback: None,
            reply_to_event_id: None,
            group_id: None,
            thread_id: None,
            nostr_event_json,
            relay_url,
        })
        .await;

        true
    }

    /// Update address state, reverse index, and relay subscriptions after a successful decrypt.
    async fn update_addresses_after_decrypt(
        &self,
        peer_signal_hex: &str,
        session_mutex: &Arc<tokio::sync::Mutex<ChatSession>>,
        addr_update: &libkeychat::AddressUpdate,
    ) {
        if !addr_update.new_receiving.is_empty() {
            let (_, all_ratchet_pubkeys) = self.collect_subscribe_pubkeys().await;
            if !all_ratchet_pubkeys.is_empty() {
                let old_ratchet_id = {
                    let inner = self.inner.read().await;
                    inner.subscription_ids.last().map(|s| libkeychat::SubscriptionId::new(s))
                };
                let inner = self.inner.read().await;
                if let Some(transport) = inner.transport.as_ref() {
                    if let Ok(new_id) = transport
                        .resubscribe(old_ratchet_id, all_ratchet_pubkeys, Some(Timestamp::now()))
                        .await
                    {
                        drop(inner);
                        let mut inner = self.inner.write().await;
                        if let Some(last) = inner.subscription_ids.last_mut() {
                            *last = new_id.to_string();
                        } else {
                            inner.subscription_ids.push(new_id.to_string());
                        }
                    }
                }
            }
        }

        if !addr_update.new_receiving.is_empty() || addr_update.new_sending.is_some() {
            let addr_state_opt = {
                let session = session_mutex.lock().await;
                session.addresses.to_serialized(peer_signal_hex)
            };
            if let Some(addr_state) = addr_state_opt {
                let storage = {
                    let inner = self.inner.read().await;
                    inner.storage.clone()
                };
                let save_result =
                    storage.lock().map_err(|e| e.to_string()).and_then(|store| {
                        store
                            .save_peer_addresses(peer_signal_hex, &addr_state)
                            .map_err(|e| e.to_string())
                    });
                if let Err(e) = save_result {
                    tracing::error!("persist address state failed: {e}");
                }
            }

            let mut inner = self.inner.write().await;
            for addr in &addr_update.new_receiving {
                inner.receiving_addr_to_peer.insert(addr.clone(), peer_signal_hex.to_string());
            }
            for addr in &addr_update.dropped_receiving {
                inner.receiving_addr_to_peer.remove(addr);
            }
        }
    }

    /// Dispatch a decrypted message by kind: group events or regular chat messages.
    async fn handle_decrypted_message(&self, ctx: DecryptedContext) {
        let DecryptedContext {
            msg, metadata, sender_nostr_pubkey, peer_signal_hex,
            session_mutex, event, relay_url, nostr_event_json,
        } = ctx;
                match msg.kind {
                    KCMessageKind::SignalGroupInvite => {
                        // Use our Signal identity key as my_signal_id.
                        // This must match what the group creator stored for us.
                        let my_signal_id = {
                            let session = session_mutex.lock().await;
                            session.signal.identity_public_key_hex()
                        };

                        match receive_group_invite(&msg, &my_signal_id) {
                            Ok(group) => {
                                let group_id = group.group_id.clone();
                                let group_name = group.name.clone();

                                tracing::info!(
                                    "[group] invite received: id={} name={} from={}",
                                    &group_id[..16.min(group_id.len())],
                                    group_name,
                                    &sender_nostr_pubkey[..16.min(sender_nostr_pubkey.len())]
                                );

                                // Store in GroupManager + persist
                                {
                                    let mut inner = self.inner.write().await;
                                    let gid = group.group_id.clone();
                                    inner.group_manager.add_group(group);
                                    if let Ok(store) = inner.storage.clone().lock() {
                                        let _ = inner.group_manager.save_group(&gid, &store);
                                    }
                                }

                                // Persist group room to app_* tables
                                {
                                    let identity_pubkey = self.cached_identity_pubkey();
                                    if !identity_pubkey.is_empty() {
                                        let saved = {
                                            let app_storage =
                                                self.inner.read().await.app_storage.clone();
                                            let store =
                                                crate::client::lock_app_storage(&app_storage);
                                            store
                                                .save_app_room(
                                                    &group_id,
                                                    &identity_pubkey,
                                                    RoomStatus::Enabled.to_i32(),
                                                    RoomType::SignalGroup.to_i32(),
                                                    Some(&group_name),
                                                    None,
                                                    None,
                                                )
                                                .ok()
                                        };
                                        if saved.is_some() {
                                            self.emit_data_change(DataChange::RoomListChanged)
                                                .await;
                                        }
                                    }
                                }

                                self.emit_event(ClientEvent::GroupInviteReceived {
                                    room_id: group_id,
                                    group_type: "signal".into(),
                                    group_name,
                                    inviter_pubkey: sender_nostr_pubkey.to_string(),
                                })
                                .await;
                            }
                            Err(e) => {
                                tracing::error!("failed to parse group invite: {e}");
                            }
                        }
                        return;
                    }

                    KCMessageKind::SignalGroupMemberRemoved => {
                        let group_id = msg.group_id.clone().unwrap_or_default();
                        let admin_payload = msg.extra.get("signalGroupAdmin");
                        let removed_member = admin_payload
                            .and_then(|v| v.get("memberId"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        tracing::info!(
                            "[group] member removed: group={} member={:?}",
                            &group_id[..16.min(group_id.len())],
                            removed_member
                        );

                        let identity_pubkey = self.cached_identity_pubkey();

                        // Update GroupManager + persist
                        if let Some(ref member_id) = removed_member {
                            let mut inner = self.inner.write().await;
                            if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
                                g.remove_member(member_id);
                            }
                            if let Ok(store) = inner.storage.clone().lock() {
                                let _ = inner.group_manager.save_group(&group_id, &store);
                            }
                        }

                        let full_room_id = crate::types::make_room_id(&group_id, &identity_pubkey);
                        self.emit_data_change(DataChange::RoomUpdated {
                            room_id: full_room_id,
                        })
                        .await;

                        self.emit_event(ClientEvent::GroupMemberChanged {
                            room_id: group_id,
                            kind: GroupChangeKind::MemberRemoved,
                            member_pubkey: removed_member,
                            new_value: None,
                        })
                        .await;
                        return;
                    }

                    KCMessageKind::SignalGroupSelfLeave => {
                        let group_id = msg.group_id.clone().unwrap_or_default();
                        let admin_payload = msg.extra.get("signalGroupAdmin");
                        let left_member = admin_payload
                            .and_then(|v| v.get("memberId"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        tracing::info!(
                            "[group] member left: group={} member={:?}",
                            &group_id[..16.min(group_id.len())],
                            left_member
                        );

                        let identity_pubkey = self.cached_identity_pubkey();

                        // Remove member from group + persist
                        if let Some(ref member_id) = left_member {
                            let mut inner = self.inner.write().await;
                            if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
                                g.remove_member(member_id);
                            }
                            if let Ok(store) = inner.storage.clone().lock() {
                                let _ = inner.group_manager.save_group(&group_id, &store);
                            }
                        }

                        let full_room_id = crate::types::make_room_id(&group_id, &identity_pubkey);
                        self.emit_data_change(DataChange::RoomUpdated {
                            room_id: full_room_id,
                        })
                        .await;

                        self.emit_event(ClientEvent::GroupMemberChanged {
                            room_id: group_id,
                            kind: GroupChangeKind::SelfLeave,
                            member_pubkey: left_member,
                            new_value: None,
                        })
                        .await;
                        return;
                    }

                    KCMessageKind::SignalGroupDissolve => {
                        let group_id = msg.group_id.clone().unwrap_or_default();

                        tracing::info!(
                            "[group] dissolved: group={}",
                            &group_id[..16.min(group_id.len())]
                        );

                        let identity_pubkey = self.cached_identity_pubkey();

                        // Remove group from manager + protocol storage
                        let app_storage_clone = {
                            let mut inner = self.inner.write().await;
                            if let Ok(store) = inner.storage.clone().lock() {
                                if let Err(e) = inner
                                    .group_manager
                                    .remove_group_persistent(&group_id, &store)
                                {
                                    warn!("remove_group_persistent: {e}");
                                }
                            } else {
                                inner.group_manager.remove_group(&group_id);
                            }
                            inner.app_storage.clone()
                        };
                        // Delete app room (separate DB)
                        {
                            let full_room_id = crate::types::make_room_id(&group_id, &identity_pubkey);
                            let app_store = crate::client::lock_app_storage(&app_storage_clone);
                            if let Err(e) = app_store.delete_app_room(&full_room_id) {
                                warn!("delete_app_room: {e}");
                            }
                        }

                        self.emit_data_change(DataChange::RoomDeleted {
                            room_id: crate::types::make_room_id(&group_id, &identity_pubkey),
                        })
                        .await;

                        self.emit_event(ClientEvent::GroupDissolved { room_id: group_id })
                            .await;
                        return;
                    }

                    KCMessageKind::SignalGroupNameChanged => {
                        let group_id = msg.group_id.clone().unwrap_or_default();
                        let admin_payload = msg.extra.get("signalGroupAdmin");
                        let new_name = admin_payload
                            .and_then(|v| v.get("newName"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        tracing::info!(
                            "[group] renamed: group={} newName={:?}",
                            &group_id[..16.min(group_id.len())],
                            new_name
                        );

                        let identity_pubkey = self.cached_identity_pubkey();

                        // Update group name + persist
                        if let Some(ref name) = new_name {
                            let app_storage_clone;
                            {
                                let mut inner = self.inner.write().await;
                                if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
                                    g.name = name.clone();
                                }
                                if let Ok(store) = inner.storage.clone().lock() {
                                    if let Err(e) =
                                        inner.group_manager.save_group(&group_id, &store)
                                    {
                                        warn!("save_group: {e}");
                                    }
                                }
                                app_storage_clone = inner.app_storage.clone();
                            }
                            // Update app room name (separate DB)
                            let full_room_id = crate::types::make_room_id(&group_id, &identity_pubkey);
                            {
                                let app_store = crate::client::lock_app_storage(&app_storage_clone);
                                if let Err(e) = app_store.update_app_room(
                                    &full_room_id,
                                    None,
                                    Some(name),
                                    None,
                                    None,
                                ) {
                                    warn!("update_app_room name: {e}");
                                }
                            }
                        }

                        let full_room_id = crate::types::make_room_id(&group_id, &identity_pubkey);
                        self.emit_data_change(DataChange::RoomUpdated {
                            room_id: full_room_id,
                        })
                        .await;

                        self.emit_event(ClientEvent::GroupMemberChanged {
                            room_id: group_id,
                            kind: GroupChangeKind::NameChanged,
                            member_pubkey: None,
                            new_value: new_name,
                        })
                        .await;
                        return;
                    }

                    // All other message kinds (Text, Files, etc.)
                    _ => {
                        let kind: MessageKind = msg.kind.clone().into();
                        let content = msg.text.as_ref().map(|t| t.content.clone());
                        let payload = msg.to_json().ok();
                        let event_id = metadata.event_id.to_hex();
                        let reply_to_event_id = msg
                            .reply_to
                            .as_ref()
                            .and_then(|r| r.target_event_id.clone());
                        let group_id = msg.group_id.clone();
                        let thread_id = msg.thread_id.clone();
                        let fallback = msg.fallback.clone();
                        let sender_pubkey = sender_nostr_pubkey.to_string();

                        // ── Persist to app_* tables ──────────────────
                        let identity_pubkey = self.cached_identity_pubkey();

                        // Room ID = "peer_hex:identity_hex" for 1:1
                        // Room ID = "group_id:identity_hex" for groups
                        let room_id = if let Some(ref gid) = group_id {
                            gid.clone()
                        } else {
                            sender_pubkey.clone()
                        };
                        let full_room_id = crate::types::make_room_id(&room_id, &identity_pubkey);

                        // DB writes under sync lock (no await while lock held)
                        let saved_msgid = if !identity_pubkey.is_empty() {
                            let app_storage = self.inner.read().await.app_storage.clone();
                            {
                                let store = crate::client::lock_app_storage(&app_storage);
                                if store.is_app_message_duplicate(&event_id).unwrap_or(false) {
                                    None
                                } else {
                                    let content_str = content.as_deref().unwrap_or("");
                                    let created_at = event.created_at.as_u64() as i64;
                                    let msgid = event_id.clone();
                                    let display_content = if content_str.is_empty() {
                                        fallback.as_deref().unwrap_or("[Message]")
                                    } else {
                                        content_str
                                    };

                                    // Build relay status for received message
                                    let relay_status = relay_url.as_ref().map(|url| {
                                        format!(r#"[{{"url":"{}","status":"received"}}]"#, url)
                                    });

                                    store
                                        .transaction(|_| {
                                            store.save_app_room(
                                                &room_id,
                                                &identity_pubkey,
                                                RoomStatus::Enabled.to_i32(),
                                                if group_id.is_some() { RoomType::SignalGroup.to_i32() } else { RoomType::Dm.to_i32() },
                                                None,
                                                None,
                                                None,
                                            )?;
                                            store.save_app_message(
                                                &msgid,
                                                Some(&event_id),
                                                &full_room_id,
                                                &identity_pubkey,
                                                &sender_pubkey,
                                                content_str,
                                                false,
                                                MessageStatus::Success.to_i32(),
                                                created_at,
                                            )?;
                                            store.update_app_message(
                                                &msgid,
                                                None,
                                                None,
                                                relay_status.as_deref(),
                                                payload.as_deref(),
                                                nostr_event_json.as_deref(),
                                                reply_to_event_id.as_deref(),
                                                None,
                                            )?;

                                            // Resolve reply-to content
                                            if let Some(ref reply_eid) = reply_to_event_id {
                                                if let Ok(Some(reply_msg)) =
                                                    store.get_app_message_by_event_id(reply_eid)
                                                {
                                                    store.update_app_message(
                                                        &msgid,
                                                        None,
                                                        None,
                                                        None,
                                                        None,
                                                        None,
                                                        None,
                                                        Some(&reply_msg.content),
                                                    )?;
                                                }
                                            }

                                            store.update_app_room(
                                                &full_room_id,
                                                None,
                                                None,
                                                Some(display_content),
                                                Some(created_at),
                                            )?;
                                            store.increment_app_room_unread(&full_room_id)?;
                                            Ok(msgid)
                                        })
                                        .map_err(|e| tracing::error!("PERSIST FAILED: incoming message: {e}"))
                                        .ok()
                                }
                            }
                        } else {
                            None
                        }; // app_storage + MutexGuard dropped

                        // Emit data changes after lock released
                        if let Some(msgid) = saved_msgid {
                            self.emit_data_change(DataChange::MessageAdded {
                                room_id: full_room_id.clone(),
                                msgid,
                            })
                            .await;
                            self.emit_data_change(DataChange::RoomUpdated {
                                room_id: full_room_id.clone(),
                            })
                            .await;
                        }

                        self.emit_event(ClientEvent::MessageReceived {
                            room_id: full_room_id,
                            sender_pubkey,
                            kind,
                            content,
                            payload,
                            event_id,
                            fallback,
                            reply_to_event_id,
                            group_id,
                            thread_id,
                            nostr_event_json: nostr_event_json.clone(),
                            relay_url: relay_url.clone(),
                        })
                        .await;

                    }
                }
    }

    /// Apply a relay status update: write to DB and notify Swift.
    /// Called on every relay OK and on timeout — gives real-time status updates.
    pub(crate) async fn apply_relay_status_update(
        &self,
        update: crate::relay_tracker::RelayStatusUpdate,
    ) {
        // Determine message status
        let msg_status = if update.all_resolved {
            Some(if update.has_success { MessageStatus::Success.to_i32() } else { MessageStatus::Failed.to_i32() })
        } else {
            None // still pending — don't change message status yet
        };

        let app_storage = self.inner.read().await.app_storage.clone();
        {
            let store = crate::client::lock_app_storage(&app_storage);
            if let Err(e) = store.update_app_message(
                &update.msgid,
                None,
                msg_status,
                Some(&update.relay_status_json),
                None,
                None,
                None,
                None,
            ) {
                warn!("apply_relay_status_update: {e}");
            }
        }

        tracing::info!(
            "⬆️ RELAY_UPDATE msgid={} resolved={} success={}",
            &update.msgid[..16.min(update.msgid.len())],
            update.all_resolved,
            update.has_success,
        );

        self.emit_data_change(DataChange::MessageUpdated {
            room_id: update.room_id,
            msgid: update.msgid,
        })
        .await;

        // Clean up resolved entries from tracker memory
        if update.all_resolved {
            let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.cleanup_resolved();
        }
    }

    /// Emit a ClientEvent to the registered EventListener.
    pub(crate) async fn emit_event(&self, event: ClientEvent) {
        let inner = self.inner.read().await;
        if let Some(listener) = &inner.event_listener {
            listener.on_event(event);
        }
    }

    /// Emit a DataChange to the registered DataListener.
    pub(crate) async fn emit_data_change(&self, change: DataChange) {
        let inner = self.inner.read().await;
        if let Some(listener) = &inner.data_listener {
            listener.on_data_change(change);
        }
    }

    /// Collect pubkeys for subscription, split into identity keys and ratchet keys.
    /// Identity keys receive NIP-59 GiftWrap with ±2 day timestamp randomization,
    /// so they need `since = cursor - 2 days`. Ratchet keys are newly derived
    /// and have no historical messages, so they use `since = now()`.
    /// C-FFI1: uses .lock().await instead of try_lock() to avoid silently skipping busy sessions.
    pub(crate) async fn collect_subscribe_pubkeys(&self) -> (Vec<PublicKey>, Vec<PublicKey>) {
        // Collect session Arcs under read lock, then drop the lock before awaiting session mutexes
        let (identity_pk, session_arcs, pending_pks) = {
            let inner = self.inner.read().await;
            let identity_pk = inner
                .identity
                .as_ref()
                .and_then(|id| PublicKey::from_hex(&id.pubkey_hex()).ok());
            let session_arcs: Vec<_> = inner.sessions.values().cloned().collect();
            let pending_pks: Vec<_> = inner
                .pending_outbound
                .values()
                .filter_map(|s| PublicKey::from_hex(&s.first_inbox_keys.pubkey_hex()).ok())
                .collect();
            (identity_pk, session_arcs, pending_pks)
        }; // RwLock dropped

        // Identity keys: receive NIP-59 with randomized outer timestamps
        let mut identity_pubkeys = Vec::new();
        if let Some(pk) = identity_pk {
            identity_pubkeys.push(pk);
        }
        // Pending outbound first-inbox keys also receive NIP-59 friend request responses
        for pk in pending_pks {
            identity_pubkeys.push(pk);
        }

        // Ratchet keys: newly derived Signal addresses, no historical messages
        let mut ratchet_pubkeys = Vec::new();
        for session_mutex in &session_arcs {
            let session = session_mutex.lock().await;
            for addr_str in session.addresses.get_all_receiving_address_strings() {
                if let Ok(pk) = PublicKey::from_hex(&addr_str) {
                    ratchet_pubkeys.push(pk);
                }
            }
        }

        (identity_pubkeys, ratchet_pubkeys)
    }
}
