//! Event loop: subscribes to Nostr relay notifications and dispatches
//! incoming events to Swift via the EventListener callback interface.

use std::sync::Arc;

use libkeychat::{
    receive_friend_request, receive_signal_message, AddressManager, ChatSession, DeviceId,
    Event, Kind, KCMessageKind, ProtocolAddress, PublicKey, RelayPoolNotification,
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
                        Ok(RelayPoolNotification::Event { event, .. }) => {
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
                                    self.handle_incoming_event(&event).await;
                                }
                            }
                        }
                        Ok(RelayPoolNotification::Shutdown) => {
                            tracing::info!("event loop: relay pool shutdown");
                            break;
                        }
                        Ok(_) => {
                            // Other notification types (Message, etc.) — ignore
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
    async fn handle_incoming_event(&self, event: &Event) {
        // Step 1: Try friend request (NIP-17 Gift Wrap → KCMessage friendRequest)
        {
            let identity = {
                let inner = self.inner.read().await;
                inner.identity.clone()
            };
            if let Some(identity) = identity {
                if let Ok(received) = receive_friend_request(&identity, event) {
                    let request_id = received
                        .message
                        .id
                        .clone()
                        .unwrap_or_else(|| format!("fr-{}", event.id.to_hex()));
                    let sender_pubkey = received.sender_pubkey_hex.clone();
                    let sender_name = received.payload.name.clone();
                    let message = received.payload.message.clone();

                    // Store in pending_inbound
                    {
                        let mut inner = self.inner.write().await;
                        inner.pending_inbound.insert(request_id.clone(), received);
                    }

                    // Emit event to Swift
                    self.emit_event(ClientEvent::FriendRequestReceived {
                        request_id,
                        sender_pubkey,
                        sender_name,
                        message,
                    })
                    .await;

                    return;
                }
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

            // Try each pending outbound state — need &mut signal_participant
            for (request_id, signal_id_hex, peer_nostr_pubkey) in &pending_keys {
                let remote_address = ProtocolAddress::new(
                    signal_id_hex.clone(),
                    DeviceId::new(1).unwrap(),
                );

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

                if let Some(Ok((msg, _decrypt_result))) = result {
                    if msg.kind == KCMessageKind::FriendApprove {
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

                        // Take the state out and create ChatSession
                        let mut inner = self.inner.write().await;
                        if let Some(state) = inner.pending_outbound.remove(request_id) {
                            let identity = match inner.identity.clone() {
                                Some(id) => id,
                                None => continue,
                            };

                            // Create AddressManager and ChatSession
                            let mut addresses = AddressManager::new();
                            let peer_signal_hex = if peer_signal_id.is_empty() {
                                peer_nostr_id.clone()
                            } else {
                                peer_signal_id
                            };

                            addresses.add_peer(
                                &peer_signal_hex,
                                None,
                                Some(peer_nostr_id.clone()),
                            );

                            let session = ChatSession::new(
                                state.signal_participant,
                                addresses,
                                identity,
                            );

                            inner.sessions.insert(
                                peer_signal_hex.clone(),
                                Arc::new(tokio::sync::Mutex::new(session)),
                            );
                            inner
                                .peer_nostr_to_signal
                                .insert(peer_nostr_id.clone(), peer_signal_hex);
                        }
                        drop(inner);

                        self.emit_event(ClientEvent::FriendRequestAccepted {
                            peer_pubkey: peer_nostr_id,
                            peer_name,
                        })
                        .await;

                        return;
                    } else if msg.kind == KCMessageKind::FriendReject {
                        let peer_pubkey = peer_nostr_pubkey.clone();

                        // Remove from pending
                        let mut inner = self.inner.write().await;
                        inner.pending_outbound.remove(request_id);
                        drop(inner);

                        self.emit_event(ClientEvent::FriendRequestRejected {
                            peer_pubkey,
                        })
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

            for (peer_signal_hex, session_mutex) in &session_entries {
                let remote_address = ProtocolAddress::new(
                    peer_signal_hex.clone(),
                    DeviceId::new(1).unwrap(),
                );

                // Lock only this peer's session
                let result = {
                    let mut session = session_mutex.lock().await;
                    session.receive_message(peer_signal_hex, &remote_address, event)
                }; // session mutex dropped

                if let Ok((msg, metadata, _addr_update)) = result {
                    // Look up the nostr pubkey for this peer (room_id)
                    let room_id = {
                        let inner = self.inner.read().await;
                        inner
                            .peer_nostr_to_signal
                            .iter()
                            .find(|(_, sig)| sig.as_str() == peer_signal_hex.as_str())
                            .map(|(nostr, _)| nostr.clone())
                            .unwrap_or_else(|| peer_signal_hex.clone())
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

                    // For 1:1, sender is the peer nostr pubkey (= room_id)
                    let sender_pubkey = room_id.clone();

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
                    })
                    .await;

                    return;
                }
            }
        }

        // No handler matched — silently drop (event not addressed to us)
        tracing::trace!(
            "event loop: unhandled event {}",
            event.id.to_hex()
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
