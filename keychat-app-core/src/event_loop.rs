//! Event loop — creates AppDelegate and starts ProtocolClient::run_event_loop.
//!
//! The protocol event processing (dedup → decrypt → routing) lives in
//! libkeychat::ProtocolClient::run_event_loop. This module provides:
//! - start_event_loop: subscribes and spawns the protocol loop with AppDelegate
//! - Relay timeout checking task
//! - apply_relay_status_update: DB persistence for relay status changes

use std::sync::Arc;

use libkeychat::ProtocolClient;

use crate::app_client::{lock_app_storage, npub_from_hex, AppClient, AppError, AppResult};
use crate::types::*;

impl AppClient {
    /// Start the event loop: subscribe + spawn protocol loop with AppDelegate.
    pub async fn start_event_loop(self: Arc<Self>) -> AppResult<()> {
        // Subscribe
        {
            let mut inner = self.inner.write().await;
            inner.protocol.refresh_subscriptions().await?;
        }

        // Create stop channel
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        {
            let mut inner = self.inner.write().await;
            inner.event_loop_stop = Some(stop_tx);
        }

        // Spawn timeout checker
        let self_timeout = Arc::clone(&self);
        let mut timeout_stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = timeout_stop.changed() => {
                        let mut t = self_timeout.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
                        t.cleanup_resolved();
                        break;
                    }
                    _ = interval.tick() => {
                        let updates = {
                            let mut t = self_timeout.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
                            t.check_timeouts(5)
                        };
                        for u in updates {
                            self_timeout.apply_relay_status_update(u).await;
                        }
                    }
                }
            }
        });

        // Spawn the event loop task
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.run_event_loop_legacy(stop_rx).await;
        });

        Ok(())
    }

    /// Legacy event loop — runs the full event processing inline.
    /// Will be replaced by ProtocolClient::run_event_loop + AppDelegate
    /// once the inner state is restructured to use Arc<RwLock<ProtocolClient>>.
    async fn run_event_loop_legacy(
        self: Arc<Self>,
        mut stop_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let nostr_client = {
            let inner = self.inner.read().await;
            match inner.protocol.transport.as_ref() {
                Some(t) => t.client().clone(),
                None => {
                    self.emit_event(ClientEvent::EventLoopError {
                        description: "transport not initialized".into(),
                    }).await;
                    return;
                }
            }
        };

        let mut notifications = nostr_client.notifications();

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    tracing::info!("event loop: stop signal received");
                    break;
                }
                result = notifications.recv() => {
                    match result {
                        Ok(libkeychat::RelayPoolNotification::Event { relay_url, event, .. }) => {
                            let eid = event.id.to_hex();

                            let deduped = {
                                let inner = self.inner.read().await;
                                match inner.protocol.transport.as_ref() {
                                    Some(t) => t.deduplicate((*event).clone()).await,
                                    None => None,
                                }
                            };

                            if let Some(event) = deduped {
                                if event.kind == libkeychat::Kind::GiftWrap {
                                    tracing::info!(
                                        "⬇️ RECV kind={} id={} from={}",
                                        event.kind.as_u16(),
                                        &eid[..16.min(eid.len())],
                                        relay_url
                                    );
                                    let relay = relay_url.to_string();
                                    let event_json = serde_json::to_string(&event).ok();

                                    // Update relay cursor
                                    let event_ts = event.created_at.as_u64();
                                    let cursor_storage = self.inner.read().await.protocol.storage.clone();
                                    if let Ok(store) = cursor_storage.lock() {
                                        let _ = store.update_relay_cursor(&relay, event_ts);
                                    }

                                    self.handle_incoming_event(&event, Some(relay), event_json).await;
                                }
                            }
                        }
                        Ok(libkeychat::RelayPoolNotification::Message { relay_url, message }) => {
                            if let libkeychat::RelayMessage::Ok { event_id, status, message: msg } = message {
                                self.handle_relay_ok(&event_id.to_hex(), &relay_url.to_string(), status, &msg).await;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!("event loop notification error: {e}");
                            self.emit_event(ClientEvent::EventLoopError {
                                description: format!("notification error: {e}"),
                            }).await;
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Handle an incoming GiftWrap event — try 4-step decryption.
    pub async fn handle_incoming_event(
        &self,
        event: &libkeychat::Event,
        relay_url: Option<String>,
        nostr_event_json: Option<String>,
    ) {
        // Step 1: Try friend request
        {
            let inner = self.inner.read().await;
            if let Some(ctx) = inner.protocol.try_decrypt_friend_request(event) {
                drop(inner);
                self.on_friend_request_app_persist(ctx, event).await;
                return;
            }
        }

        // Step 2: Try pending outbound (friend approve/reject)
        {
            let mut inner = self.inner.write().await;
            if let Some((request_id, msg)) = inner.protocol.try_decrypt_pending_outbound(event) {
                drop(inner);
                self.on_friend_approve_app_persist(&request_id, &msg, event).await;
                return;
            }
        }

        // Step 3: Try session message
        let step3 = {
            let inner = self.inner.read().await;
            inner.protocol.try_decrypt_session_message(event).await
        };
        if let Some((peer_signal_hex, msg, metadata, addr_update, session_mutex)) = step3 {
            // Update addresses
            {
                let mut inner = self.inner.write().await;
                inner.protocol.update_addresses_after_decrypt(
                    &peer_signal_hex, &session_mutex, &addr_update,
                ).await;
            }

            let sender_nostr_pubkey = {
                let inner = self.inner.read().await;
                inner.protocol.peer_signal_to_nostr.get(&peer_signal_hex)
                    .cloned().unwrap_or_else(|| peer_signal_hex.clone())
            };

            self.on_message_app_persist(
                msg, metadata, sender_nostr_pubkey, peer_signal_hex,
                event, relay_url, nostr_event_json,
            ).await;
            return;
        }

        // Step 4: Try NIP-17 DM
        {
            let inner = self.inner.read().await;
            if let Some(mut ctx) = inner.protocol.try_decrypt_nip17_dm(event) {
                ctx.nostr_event_json = nostr_event_json;
                ctx.relay_url = relay_url;
                drop(inner);
                self.on_nip17_dm_app_persist(ctx).await;
                return;
            }
        }
    }

    // ─── App persistence helpers (called after protocol decryption) ──

    async fn on_friend_request_app_persist(
        &self,
        ctx: libkeychat::FriendRequestContext,
        _event: &libkeychat::Event,
    ) {
        let identity_pubkey = self.cached_identity_pubkey();
        if identity_pubkey.is_empty() { return; }

        let fr_content = ctx.message.as_deref().unwrap_or("[Friend Request]");
        let sender_npub = npub_from_hex(ctx.sender_pubkey.clone()).unwrap_or_default();
        let msgid = format!("fr-recv-{}", &ctx.request_id);

        let saved_room_id = {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if store.is_app_message_duplicate(&ctx.event_id).unwrap_or(false) {
                None
            } else {
                let room_status = {
                    let rid = make_room_id(&ctx.sender_pubkey, &identity_pubkey);
                    let existing = store.get_app_room(&rid).ok().flatten();
                    if existing.map(|r| r.status) == Some(RoomStatus::Enabled.to_i32()) {
                        RoomStatus::Enabled.to_i32()
                    } else {
                        RoomStatus::Approving.to_i32()
                    }
                };
                store.transaction(|_| {
                    let room_id = store.save_app_room(
                        &ctx.sender_pubkey, &identity_pubkey, room_status,
                        RoomType::Dm.to_i32(), Some(&ctx.sender_name), None, None,
                    )?;
                    store.save_app_contact(
                        &ctx.sender_pubkey, &sender_npub, &identity_pubkey, Some(&ctx.sender_name),
                    )?;
                    store.save_app_message(
                        &msgid, Some(&ctx.event_id), &room_id, &identity_pubkey,
                        &ctx.sender_pubkey, fr_content, false,
                        MessageStatus::Success.to_i32(), ctx.created_at as i64,
                    )?;
                    store.update_app_room(&room_id, None, None, Some(fr_content), Some(ctx.created_at as i64))?;
                    store.increment_app_room_unread(&room_id)?;
                    Ok(room_id)
                }).ok()
            }
        };

        if let Some(room_id) = saved_room_id {
            self.emit_data_change(DataChange::RoomListChanged).await;
            self.emit_data_change(DataChange::ContactListChanged).await;
            self.emit_data_change(DataChange::MessageAdded { room_id, msgid }).await;
        }

        self.emit_event(ClientEvent::FriendRequestReceived {
            request_id: ctx.request_id,
            sender_pubkey: ctx.sender_pubkey,
            sender_name: ctx.sender_name,
            message: ctx.message,
            created_at: ctx.created_at,
        }).await;
    }

    async fn on_friend_approve_app_persist(
        &self,
        request_id: &str,
        msg: &libkeychat::KCMessage,
        event: &libkeychat::Event,
    ) {
        if msg.kind == libkeychat::KCMessageKind::FriendApprove {
            let peer_name = msg.signal_prekey_auth.as_ref()
                .map(|a| a.name.clone()).unwrap_or_default();
            let peer_signal_id = msg.signal_prekey_auth.as_ref()
                .map(|a| a.signal_id.clone()).unwrap_or_default();
            let peer_nostr_id = msg.signal_prekey_auth.as_ref()
                .map(|a| a.nostr_id.clone()).unwrap_or_default();
            let peer_signal_hex = if peer_signal_id.is_empty() { peer_nostr_id.clone() } else { peer_signal_id };

            let identity_pubkey = self.cached_identity_pubkey();
            if !identity_pubkey.is_empty() {
                let peer_npub = npub_from_hex(peer_nostr_id.clone()).unwrap_or_default();
                let msgid = format!("fr-accept-{}", request_id);
                let event_id_hex = event.id.to_hex();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

                let saved_room_id = {
                    let app_storage = self.inner.read().await.app_storage.clone();
                    let store = lock_app_storage(&app_storage);
                    if store.is_app_message_duplicate(&event_id_hex).unwrap_or(false) {
                        None
                    } else {
                        store.transaction(|_| {
                            let room_id = store.save_app_room(
                                &peer_nostr_id, &identity_pubkey,
                                RoomStatus::Enabled.to_i32(), RoomType::Dm.to_i32(),
                                Some(&peer_name), Some(&peer_signal_hex), None,
                            )?;
                            store.save_app_contact(
                                &peer_nostr_id, &peer_npub, &identity_pubkey, Some(&peer_name),
                            )?;
                            store.save_app_message(
                                &msgid, Some(&event_id_hex), &room_id, &identity_pubkey,
                                &peer_nostr_id, "[Friend Request Accepted]", false,
                                MessageStatus::Success.to_i32(), now,
                            )?;
                            store.update_app_room(
                                &room_id, Some(RoomStatus::Enabled.to_i32()), None,
                                Some("[Friend Request Accepted]"), Some(now),
                            )?;
                            store.increment_app_room_unread(&room_id)?;
                            Ok(room_id)
                        }).ok()
                    }
                };

                if let Some(room_id) = saved_room_id {
                    self.emit_data_change(DataChange::RoomUpdated { room_id: room_id.clone() }).await;
                    self.emit_data_change(DataChange::ContactListChanged).await;
                    self.emit_data_change(DataChange::MessageAdded { room_id, msgid }).await;
                }
            }

            self.emit_event(ClientEvent::FriendRequestAccepted {
                peer_pubkey: peer_nostr_id,
                peer_name,
            }).await;

        } else if msg.kind == libkeychat::KCMessageKind::FriendReject {
            let peer_pubkey = {
                let inner = self.inner.read().await;
                inner.protocol.pending_outbound.get(request_id)
                    .map(|s| s.peer_nostr_pubkey.clone()).unwrap_or_default()
            };

            let identity_pubkey = self.cached_identity_pubkey();
            if !identity_pubkey.is_empty() {
                let room_id = make_room_id(&peer_pubkey, &identity_pubkey);
                {
                    let app_storage = self.inner.read().await.app_storage.clone();
                    let store = lock_app_storage(&app_storage);
                    let _ = store.update_app_room(
                        &room_id, Some(RoomStatus::Rejected.to_i32()), None,
                        Some("[Friend Request Rejected]"), None,
                    );
                }
                self.emit_data_change(DataChange::RoomUpdated { room_id }).await;
            }

            self.emit_event(ClientEvent::FriendRequestRejected { peer_pubkey }).await;
        }
    }

    async fn on_message_app_persist(
        &self,
        msg: libkeychat::KCMessage,
        metadata: libkeychat::MessageMetadata,
        sender_nostr_pubkey: String,
        _peer_signal_hex: String,
        event: &libkeychat::Event,
        relay_url: Option<String>,
        nostr_event_json: Option<String>,
    ) {
        let identity_pubkey = self.cached_identity_pubkey();
        let kind: MessageKind = msg.kind.clone().into();
        let content = msg.text.as_ref().map(|t| t.content.clone());
        let payload_json = msg.to_json().ok();
        let event_id = metadata.event_id.to_hex();
        let group_id = msg.group_id.clone();
        let thread_id = msg.thread_id.clone();
        let fallback = msg.fallback.clone();
        let reply_to_event_id = msg.reply_to.as_ref().and_then(|r| r.target_event_id.clone());

        // Handle group-specific messages (invite, member changes, etc.)
        // For now, all messages go through the generic persistence path.
        // Group-specific handling (invite acceptance, member removal) is done
        // in the full try_handle_session_message in the legacy path.

        let room_id_base = if let Some(ref gid) = group_id {
            gid.clone()
        } else {
            sender_nostr_pubkey.clone()
        };
        let full_room_id = make_room_id(&room_id_base, &identity_pubkey);

        if !identity_pubkey.is_empty() {
            let saved_msgid = {
                let app_storage = self.inner.read().await.app_storage.clone();
                let store = lock_app_storage(&app_storage);
                if store.is_app_message_duplicate(&event_id).unwrap_or(false) {
                    None
                } else {
                    let content_str = content.as_deref().unwrap_or("");
                    let display = if content_str.is_empty() {
                        fallback.as_deref().unwrap_or("[Message]")
                    } else { content_str };
                    let created_at = event.created_at.as_u64() as i64;
                    let relay_status = relay_url.as_ref().map(|url| {
                        format!(r#"[{{"url":"{}","status":"received"}}]"#, url)
                    });
                    let room_type = if group_id.is_some() { RoomType::SignalGroup.to_i32() } else { RoomType::Dm.to_i32() };

                    store.transaction(|_| {
                        store.save_app_room(
                            &room_id_base, &identity_pubkey,
                            RoomStatus::Enabled.to_i32(), room_type, None, None, None,
                        )?;
                        store.save_app_message(
                            &event_id, Some(&event_id), &full_room_id, &identity_pubkey,
                            &sender_nostr_pubkey, content_str, false,
                            MessageStatus::Success.to_i32(), created_at,
                        )?;
                        store.update_app_message(
                            &event_id, None, None, relay_status.as_deref(),
                            payload_json.as_deref(), nostr_event_json.as_deref(),
                            reply_to_event_id.as_deref(), None,
                        )?;
                        store.update_app_room(
                            &full_room_id, None, None, Some(display), Some(created_at),
                        )?;
                        store.increment_app_room_unread(&full_room_id)?;
                        Ok(event_id.clone())
                    }).ok()
                }
            };

            if let Some(msgid) = saved_msgid {
                self.emit_data_change(DataChange::MessageAdded {
                    room_id: full_room_id.clone(), msgid,
                }).await;
                self.emit_data_change(DataChange::RoomUpdated {
                    room_id: full_room_id.clone(),
                }).await;
            }
        }

        self.emit_event(ClientEvent::MessageReceived {
            room_id: full_room_id,
            sender_pubkey: sender_nostr_pubkey,
            kind,
            content,
            payload: payload_json,
            event_id,
            fallback,
            reply_to_event_id,
            group_id,
            thread_id,
            nostr_event_json,
            relay_url,
        }).await;
    }

    async fn on_nip17_dm_app_persist(&self, ctx: libkeychat::Nip17DmContext) {
        let identity_pubkey = self.cached_identity_pubkey();
        if identity_pubkey.is_empty() { return; }

        let room_id = make_room_id(&ctx.sender_pubkey, &identity_pubkey);
        let msgid = ctx.event_id.clone();

        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_room(
                &ctx.sender_pubkey, &identity_pubkey,
                RoomStatus::Enabled.to_i32(), RoomType::Nip17Dm.to_i32(),
                None, None, None,
            );
            let _ = store.save_app_message(
                &msgid, Some(&ctx.event_id), &room_id, &identity_pubkey,
                &ctx.sender_pubkey, &ctx.content, false,
                MessageStatus::Success.to_i32(), ctx.created_at as i64,
            );
            let display = if ctx.content.len() > 50 { &ctx.content[..50] } else { &ctx.content };
            let _ = store.update_app_room(&room_id, None, None, Some(display), Some(ctx.created_at as i64));
            let _ = store.increment_app_room_unread(&room_id);
        }

        self.emit_data_change(DataChange::MessageAdded {
            room_id: room_id.clone(), msgid: msgid.clone(),
        }).await;
        self.emit_data_change(DataChange::RoomUpdated { room_id: room_id.clone() }).await;

        self.emit_event(ClientEvent::MessageReceived {
            room_id,
            sender_pubkey: ctx.sender_pubkey,
            kind: MessageKind::Text,
            content: Some(ctx.content),
            payload: None,
            event_id: ctx.event_id,
            fallback: None,
            reply_to_event_id: None,
            group_id: None,
            thread_id: None,
            nostr_event_json: ctx.nostr_event_json,
            relay_url: ctx.relay_url,
        }).await;
    }

    /// Handle relay OK response.
    pub async fn handle_relay_ok(&self, event_id: &str, relay_url: &str, status: bool, message: &str) {
        tracing::info!(
            "⬆️ RELAY_OK relay={} eventId={} ok={} msg={}",
            relay_url, &event_id[..16.min(event_id.len())], status, &message[..80.min(message.len())]
        );
        let update = {
            let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.handle_relay_ok(event_id, relay_url, status, message)
        };
        if let Some(update) = update {
            self.apply_relay_status_update(update).await;
        }
        self.emit_event(ClientEvent::RelayOk {
            event_id: event_id.to_string(),
            relay_url: relay_url.to_string(),
            success: status,
            message: message.to_string(),
        }).await;
    }

    /// Persist a relay status update to DB.
    pub async fn apply_relay_status_update(&self, update: crate::relay_tracker::RelayStatusUpdate) {
        let msg_status = if update.all_resolved {
            Some(if update.has_success { MessageStatus::Success.to_i32() } else { MessageStatus::Failed.to_i32() })
        } else {
            None
        };

        let app_storage = self.inner.read().await.app_storage.clone();
        {
            let store = lock_app_storage(&app_storage);
            if let Err(e) = store.update_app_message(
                &update.msgid, None, msg_status, Some(&update.relay_status_json),
                None, None, None, None,
            ) {
                tracing::warn!("apply_relay_status_update: {e}");
            }
        }

        self.emit_data_change(DataChange::MessageUpdated {
            room_id: update.room_id, msgid: update.msgid,
        }).await;

        if update.all_resolved {
            let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.cleanup_resolved();
        }
    }
}
