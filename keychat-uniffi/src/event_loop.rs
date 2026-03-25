//! Event loop: subscribes to Nostr relay notifications and dispatches
//! incoming events to Swift via the EventListener callback interface.

use std::sync::Arc;

use libkeychat::{
    receive_friend_request, receive_group_invite, receive_signal_message,
    serialize_prekey_material, AddressManager, ChatSession, DeviceId, Event, KCMessageKind, Kind,
    ProtocolAddress, PublicKey, RelayMessage, RelayPoolNotification, Timestamp,
};

use crate::client::KeychatClient;
use crate::types::*;

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
                                    let relay = relay_url.to_string();
                                    let event_json =
                                        serde_json::to_string(&event).ok();
                                    self.handle_incoming_event(
                                        &event,
                                        Some(relay),
                                        event_json,
                                    )
                                    .await;
                                }
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
    /// 1. Friend request (NIP-17 unwrap)
    /// 2. Friend approve response (pending outbound states)
    /// 3. Existing session message
    async fn handle_incoming_event(
        &self,
        event: &Event,
        relay_url: Option<String>,
        nostr_event_json: Option<String>,
    ) {
        let event_hex = event.id.to_hex();
        tracing::info!(
            "⬇️ RECV GiftWrap event_id={}",
            &event_hex[..16.min(event_hex.len())]
        );

        // Step 1: Try friend request (NIP-17 Gift Wrap → KCMessage friendRequest)
        {
            let identity = {
                let inner = self.inner.read().await;
                inner.identity.clone()
            };
            if let Some(identity) = identity {
                tracing::debug!("Step1: trying receive_friend_request...");
                match receive_friend_request(&identity, event) {
                    Ok(received) => {
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
                            "⬇️ Step1 OK: friendRequest from={} name={:?} reqId={}",
                            &sender_pubkey[..16.min(sender_pubkey.len())],
                            sender_name,
                            &request_id[..16.min(request_id.len())]
                        );

                        // Persist inbound FR to SQLCipher
                        {
                            let message_json =
                                serde_json::to_string(&received.message).unwrap_or_default();
                            let payload_json =
                                serde_json::to_string(&received.payload).unwrap_or_default();
                            let storage = self.inner.read().await.storage.clone();
                            let result =
                                (|| -> std::result::Result<(), Box<dyn std::error::Error>> {
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

                        // Emit event to Swift
                        self.emit_event(ClientEvent::FriendRequestReceived {
                            request_id,
                            sender_pubkey,
                            sender_name,
                            message,
                            created_at,
                        })
                        .await;

                        return;
                    }
                    Err(e) => {
                        tracing::debug!("Step1: not a friend request: {e}");
                    }
                }
            } else {
                tracing::warn!("Step1: no identity set, skipping friend request check");
            }
        }

        // Step 2: Try decrypt with pending outbound friend request states
        // (looking for FriendApprove responses)
        {
            // Collect shallow info from pending outbound, drop lock
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

                let remote_address =
                    ProtocolAddress::new(signal_id_hex.clone(), DeviceId::new(1).unwrap());

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
                            "⬇️ Step2 decrypt OK: kind={:?} reqId={}",
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
                            "⬇️ Step2: FriendApprove from peer={} reqId={}",
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
                            "⬇️ Step2: peer_name={:?} peer_signal_id={} peer_nostr_id={}",
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
                                let from_addr = ProtocolAddress::new(
                                    signal_id_hex.clone(),
                                    DeviceId::new(1).unwrap(),
                                );
                                let to_addr = ProtocolAddress::new(
                                    peer_signal_hex.clone(),
                                    DeviceId::new(1).unwrap(),
                                );
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
                            let new_receiving = if let Some(bob_addr) =
                                decrypt_result.bob_derived_address.as_deref()
                            {
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
                            let serialized_keys =
                                serialize_prekey_material(state.signal_participant.keys());
                            let signal_device_id =
                                u32::from(state.signal_participant.address().device_id());

                            let session =
                                ChatSession::new(state.signal_participant, addresses, identity);

                            inner.sessions.insert(
                                peer_signal_hex.clone(),
                                Arc::new(tokio::sync::Mutex::new(session)),
                            );
                            inner
                                .peer_nostr_to_signal
                                .insert(peer_nostr_id.clone(), peer_signal_hex.clone());

                            tracing::info!(
                                "⬇️ Step2: ChatSession created, peer_signal={} new_receiving={}",
                                &peer_signal_hex[..16.min(peer_signal_hex.len())],
                                new_receiving.len()
                            );

                            // Persist session state to SQLCipher
                            {
                                let store_result = inner.storage.lock();
                                if let Err(ref e) = store_result {
                                    tracing::error!("⬇️ Step2: storage lock poisoned, session NOT persisted: {e}");
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
                                    // Save signal participant keys for session restore
                                    if let Ok((
                                        id_pub,
                                        id_priv,
                                        reg_id,
                                        spk_id,
                                        spk_rec,
                                        pk_id,
                                        pk_rec,
                                        kpk_id,
                                        kpk_rec,
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
                                            *pk_id,
                                            pk_rec,
                                            *kpk_id,
                                            kpk_rec,
                                        ) {
                                            tracing::error!(
                                                "persist signal_participant failed: {e}"
                                            );
                                        }
                                    }
                                    // Save address state
                                    if let Some(session_mutex) =
                                        inner.sessions.get(&peer_signal_hex)
                                    {
                                        if let Ok(sess) = session_mutex.try_lock() {
                                            if let Some(addr_state) =
                                                sess.addresses.to_serialized(&peer_signal_hex)
                                            {
                                                if let Err(e) = store.save_peer_addresses(
                                                    &peer_signal_hex,
                                                    &addr_state,
                                                ) {
                                                    tracing::error!(
                                                        "persist peer_addresses failed: {e}"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    // Delete the pending FR (now an active session)
                                    let _ = store.delete_pending_fr(request_id);
                                    tracing::info!("⬇️ Step2: persisted session to SQLCipher");
                                }
                            }

                            // Refresh relay subscriptions: new ratchet addresses + our first_inbox
                            {
                                let mut sub_pubkeys: Vec<PublicKey> = new_receiving
                                    .iter()
                                    .filter_map(|addr| PublicKey::from_hex(addr).ok())
                                    .collect();
                                // Keep subscribing to our first_inbox so the peer can reach us
                                // before the first ratchet-derived address exchange
                                if let Ok(pk) = PublicKey::from_hex(&my_first_inbox_hex) {
                                    sub_pubkeys.push(pk);
                                }
                                if !sub_pubkeys.is_empty() {
                                    if let Some(transport) = inner.transport.as_ref() {
                                        let _ = transport
                                            .subscribe(sub_pubkeys, Some(Timestamp::now()))
                                            .await;
                                    }
                                }
                            }
                        }
                        drop(inner);

                        self.emit_event(ClientEvent::FriendRequestAccepted {
                            peer_pubkey: peer_nostr_id,
                            peer_name,
                        })
                        .await;

                        return;
                    } else if msg.kind == KCMessageKind::FriendReject {
                        tracing::info!(
                            "⬇️ Step2: FriendReject from peer={} reqId={}",
                            &peer_nostr_pubkey[..16.min(peer_nostr_pubkey.len())],
                            &request_id[..16.min(request_id.len())]
                        );
                        let peer_pubkey = peer_nostr_pubkey.clone();

                        // Remove from pending
                        let mut inner = self.inner.write().await;
                        inner.pending_outbound.remove(request_id);
                        drop(inner);

                        self.emit_event(ClientEvent::FriendRequestRejected { peer_pubkey })
                            .await;

                        return;
                    }
                }
            }
        }

        // Step 3: Try decrypt with existing ChatSessions
        {
            // Collect session Arc clones, drop RwLock
            let session_entries: Vec<(String, Arc<tokio::sync::Mutex<ChatSession>>)> = {
                let inner = self.inner.read().await;
                inner
                    .sessions
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }; // RwLock dropped

            tracing::debug!("Step3: trying {} existing sessions", session_entries.len());

            for (peer_signal_hex, session_mutex) in &session_entries {
                let remote_address =
                    ProtocolAddress::new(peer_signal_hex.clone(), DeviceId::new(1).unwrap());

                // Lock only this peer's session
                let result = {
                    let mut session = session_mutex.lock().await;
                    session.receive_message(peer_signal_hex, &remote_address, event)
                }; // session mutex dropped

                match &result {
                    Ok((msg, metadata, _)) => {
                        tracing::info!(
                            "⬇️ Step3 decrypt OK: kind={:?} eventId={} peer={}",
                            msg.kind,
                            &metadata.event_id.to_hex()[..16],
                            &peer_signal_hex[..16.min(peer_signal_hex.len())]
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Step3: decrypt failed for peer={}: {e}",
                            &peer_signal_hex[..16.min(peer_signal_hex.len())]
                        );
                    }
                }

                if let Ok((msg, metadata, addr_update)) = result {
                    // Refresh relay subscriptions if new receiving addresses were derived
                    if !addr_update.new_receiving.is_empty() {
                        let inner = self.inner.read().await;
                        if let Some(transport) = inner.transport.as_ref() {
                            let new_pubkeys: Vec<PublicKey> = addr_update
                                .new_receiving
                                .iter()
                                .filter_map(|addr| PublicKey::from_hex(addr).ok())
                                .collect();
                            if !new_pubkeys.is_empty() {
                                let _ = transport
                                    .subscribe(new_pubkeys, Some(Timestamp::now()))
                                    .await;
                            }
                        }
                    }

                    // Persist updated address state after decrypt
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
                    }

                    // Look up the nostr pubkey for this peer (room_id for 1:1)
                    let sender_nostr_pubkey = {
                        let inner = self.inner.read().await;
                        inner
                            .peer_nostr_to_signal
                            .iter()
                            .find(|(_, sig)| sig.as_str() == peer_signal_hex.as_str())
                            .map(|(nostr, _)| nostr.clone())
                            .unwrap_or_else(|| peer_signal_hex.clone())
                    };

                    // ── Group event handling ──────────────────────────────────
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
                                        "⬇️ group invite received: id={} name={} from={}",
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

                                    self.emit_event(ClientEvent::GroupInviteReceived {
                                        room_id: group_id,
                                        group_type: "signal".into(),
                                        group_name,
                                        inviter_pubkey: sender_nostr_pubkey,
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
                                "⬇️ group member removed: group={} member={:?}",
                                &group_id[..16.min(group_id.len())],
                                removed_member
                            );

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

                            self.emit_event(ClientEvent::GroupMemberChanged {
                                room_id: group_id,
                                kind: "memberRemoved".into(),
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
                                "⬇️ group member left: group={} member={:?}",
                                &group_id[..16.min(group_id.len())],
                                left_member
                            );

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

                            self.emit_event(ClientEvent::GroupMemberChanged {
                                room_id: group_id,
                                kind: "selfLeave".into(),
                                member_pubkey: left_member,
                                new_value: None,
                            })
                            .await;
                            return;
                        }

                        KCMessageKind::SignalGroupDissolve => {
                            let group_id = msg.group_id.clone().unwrap_or_default();

                            tracing::info!(
                                "⬇️ group dissolved: group={}",
                                &group_id[..16.min(group_id.len())]
                            );

                            // Remove group from manager + storage
                            {
                                let mut inner = self.inner.write().await;
                                if let Ok(store) = inner.storage.clone().lock() {
                                    let _ = inner
                                        .group_manager
                                        .remove_group_persistent(&group_id, &store);
                                } else {
                                    inner.group_manager.remove_group(&group_id);
                                }
                            }

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
                                "⬇️ group renamed: group={} newName={:?}",
                                &group_id[..16.min(group_id.len())],
                                new_name
                            );

                            // Update group name + persist
                            if let Some(ref name) = new_name {
                                let mut inner = self.inner.write().await;
                                if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
                                    g.name = name.clone();
                                }
                                if let Ok(store) = inner.storage.clone().lock() {
                                    let _ = inner.group_manager.save_group(&group_id, &store);
                                }
                            }

                            self.emit_event(ClientEvent::GroupMemberChanged {
                                room_id: group_id,
                                kind: "nameChanged".into(),
                                member_pubkey: None,
                                new_value: new_name,
                            })
                            .await;
                            return;
                        }

                        // All other message kinds (Text, Files, etc.)
                        _ => {
                            let room_id = if msg.group_id.is_some() {
                                // Group message: room_id = group_id
                                msg.group_id.clone().unwrap()
                            } else {
                                // 1:1 message: room_id = peer nostr pubkey
                                sender_nostr_pubkey.clone()
                            };

                            let kind = format!("{:?}", msg.kind);
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
                            let sender_pubkey = sender_nostr_pubkey;

                            self.emit_event(ClientEvent::MessageReceived {
                                room_id,
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

                            return;
                        }
                    }
                }
            }
        }

        // No handler matched — event not addressed to us
        tracing::debug!(
            "⬇️ UNHANDLED: no step matched event_id={}",
            &event_hex[..16.min(event_hex.len())]
        );
    }

    /// Emit a ClientEvent to the registered EventListener.
    pub(crate) async fn emit_event(&self, event: ClientEvent) {
        let inner = self.inner.read().await;
        if let Some(listener) = &inner.event_listener {
            listener.on_event(event);
        }
    }

    /// Collect all pubkeys we should subscribe to for incoming events.
    pub(crate) async fn collect_subscribe_pubkeys(&self) -> Vec<PublicKey> {
        let inner = self.inner.read().await;
        let mut pubkeys = Vec::new();

        // Our own identity pubkey (for friend requests via NIP-17)
        if let Some(ref identity) = inner.identity {
            if let Ok(pk) = PublicKey::from_hex(&identity.pubkey_hex()) {
                pubkeys.push(pk);
            }
        }

        // Receiving addresses from all sessions' AddressManagers
        for session_mutex in inner.sessions.values() {
            // We're under RwLock, so we can't await the session mutex.
            // Use try_lock — if busy, skip (will be updated on next subscribe).
            if let Ok(session) = session_mutex.try_lock() {
                for addr_str in session.addresses.get_all_receiving_address_strings() {
                    if let Ok(pk) = PublicKey::from_hex(&addr_str) {
                        pubkeys.push(pk);
                    }
                }
            }
        }

        // firstInbox keys from pending outbound friend requests
        for state in inner.pending_outbound.values() {
            if let Ok(pk) = PublicKey::from_hex(&state.first_inbox_keys.pubkey_hex()) {
                pubkeys.push(pk);
            }
        }

        pubkeys
    }
}
