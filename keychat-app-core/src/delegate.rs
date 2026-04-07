//! AppDelegate — implements OrchestratorDelegate for app-layer persistence.
//!
//! Receives protocol events (friend requests, messages, etc.) from
//! ProtocolClient::run_event_loop and persists them to AppStorage.

use std::sync::{Arc, Mutex};

use libkeychat::{self, OrchestratorDelegate, FriendRequestContext, FriendApprovedContext, FriendRejectedContext, MessageReceivedContext, GroupInviteContext, GroupChangedContext, Nip17DmContext};

use crate::app_client::lock_app_storage;
use crate::app_client::npub_from_hex;
use crate::app_storage::AppStorage;
use crate::relay_tracker::RelaySendTracker;
use crate::types::*;

/// App-layer delegate that persists protocol events to SQLCipher.
pub struct AppDelegate {
    pub app_storage: Arc<Mutex<AppStorage>>,
    pub relay_tracker: Arc<Mutex<RelaySendTracker>>,
    pub identity_pubkey: String,
    pub event_listener: Arc<tokio::sync::RwLock<Option<Box<dyn EventListener>>>>,
    pub data_listener: Arc<tokio::sync::RwLock<Option<Box<dyn DataListener>>>>,
}

impl AppDelegate {
    async fn emit_event(&self, event: ClientEvent) {
        let guard = self.event_listener.read().await;
        if let Some(ref listener) = *guard {
            listener.on_event(event);
        }
    }

    async fn emit_data_change(&self, change: DataChange) {
        let guard = self.data_listener.read().await;
        if let Some(ref listener) = *guard {
            listener.on_data_change(change);
        }
    }
}

#[async_trait::async_trait]
impl OrchestratorDelegate for AppDelegate {
    async fn on_friend_request_received(&self, ctx: FriendRequestContext) {
        let identity_pubkey = &self.identity_pubkey;
        if identity_pubkey.is_empty() { return; }

        let fr_content = ctx.message.as_deref().unwrap_or("[Friend Request]");
        let sender_npub = npub_from_hex(ctx.sender_pubkey.clone()).unwrap_or_default();
        let msgid = format!("fr-recv-{}", &ctx.request_id);

        // DB writes
        let saved_room_id = {
            let store = lock_app_storage(&self.app_storage);
            if store.is_app_message_duplicate(&ctx.event_id).unwrap_or(false) {
                None
            } else {
                let room_status = {
                    let room_id = make_room_id(&ctx.sender_pubkey, identity_pubkey);
                    let existing = store.get_app_room(&room_id).ok().flatten();
                    if existing.map(|r| r.status) == Some(RoomStatus::Enabled.to_i32()) {
                        RoomStatus::Enabled.to_i32()
                    } else {
                        RoomStatus::Approving.to_i32()
                    }
                };
                store.transaction(|_| {
                    let room_id = store.save_app_room(
                        &ctx.sender_pubkey, identity_pubkey, room_status,
                        RoomType::Dm.to_i32(), Some(&ctx.sender_name), None, None,
                    )?;
                    store.save_app_contact(
                        &ctx.sender_pubkey, &sender_npub, identity_pubkey, Some(&ctx.sender_name),
                    )?;
                    store.save_app_message(
                        &msgid, Some(&ctx.event_id), &room_id, identity_pubkey,
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

    async fn on_friend_approved(&self, ctx: FriendApprovedContext) {
        let identity_pubkey = &self.identity_pubkey;
        if identity_pubkey.is_empty() { return; }

        let peer_npub = npub_from_hex(ctx.peer_nostr_pubkey.clone()).unwrap_or_default();
        let msgid = format!("fr-accept-{}", ctx.request_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

        let saved_room_id = {
            let store = lock_app_storage(&self.app_storage);
            if store.is_app_message_duplicate(&ctx.event_id).unwrap_or(false) {
                None
            } else {
                store.transaction(|_| {
                    let room_id = store.save_app_room(
                        &ctx.peer_nostr_pubkey, identity_pubkey,
                        RoomStatus::Enabled.to_i32(), RoomType::Dm.to_i32(),
                        Some(&ctx.peer_name), Some(&ctx.peer_signal_id_hex), None,
                    )?;
                    store.save_app_contact(
                        &ctx.peer_nostr_pubkey, &peer_npub, identity_pubkey, Some(&ctx.peer_name),
                    )?;
                    store.save_app_message(
                        &msgid, Some(&ctx.event_id), &room_id, identity_pubkey,
                        &ctx.peer_nostr_pubkey, "[Friend Request Accepted]", false,
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

        self.emit_event(ClientEvent::FriendRequestAccepted {
            peer_pubkey: ctx.peer_nostr_pubkey,
            peer_name: ctx.peer_name,
        }).await;
    }

    async fn on_friend_rejected(&self, ctx: FriendRejectedContext) {
        let identity_pubkey = &self.identity_pubkey;
        if !identity_pubkey.is_empty() {
            let room_id = make_room_id(&ctx.peer_pubkey, identity_pubkey);
            {
                let store = lock_app_storage(&self.app_storage);
                let _ = store.update_app_room(
                    &room_id, Some(RoomStatus::Rejected.to_i32()), None,
                    Some("[Friend Request Rejected]"), None,
                );
            }
            self.emit_data_change(DataChange::RoomUpdated { room_id }).await;
        }

        self.emit_event(ClientEvent::FriendRequestRejected {
            peer_pubkey: ctx.peer_pubkey,
        }).await;
    }

    async fn on_message_received(&self, ctx: MessageReceivedContext) {
        let identity_pubkey = &self.identity_pubkey;
        if identity_pubkey.is_empty() { return; }

        let room_id_base = if let Some(ref gid) = ctx.group_id {
            gid.clone()
        } else {
            ctx.sender_pubkey.clone()
        };
        let full_room_id = make_room_id(&room_id_base, identity_pubkey);

        let saved_msgid = {
            let store = lock_app_storage(&self.app_storage);
            if store.is_app_message_duplicate(&ctx.event_id).unwrap_or(false) {
                None
            } else {
                let content_str = ctx.content.as_deref().unwrap_or("");
                let display = if content_str.is_empty() {
                    ctx.fallback.as_deref().unwrap_or("[Message]")
                } else {
                    content_str
                };

                let relay_status = ctx.relay_url.as_ref().map(|url| {
                    format!(r#"[{{"url":"{}","status":"received"}}]"#, url)
                });

                store.transaction(|_| {
                    let room_type = if ctx.group_id.is_some() {
                        RoomType::SignalGroup.to_i32()
                    } else {
                        RoomType::Dm.to_i32()
                    };
                    store.save_app_room(
                        &room_id_base, identity_pubkey,
                        RoomStatus::Enabled.to_i32(), room_type,
                        None, None, None,
                    )?;
                    let msgid = ctx.event_id.clone();
                    store.save_app_message(
                        &msgid, Some(&ctx.event_id), &full_room_id, identity_pubkey,
                        &ctx.sender_pubkey, content_str, false,
                        MessageStatus::Success.to_i32(), ctx.created_at as i64,
                    )?;
                    store.update_app_message(
                        &msgid, None, None, relay_status.as_deref(),
                        ctx.payload_json.as_deref(), ctx.nostr_event_json.as_deref(),
                        ctx.reply_to_event_id.as_deref(), None,
                    )?;
                    store.update_app_room(
                        &full_room_id, None, None, Some(display), Some(ctx.created_at as i64),
                    )?;
                    store.increment_app_room_unread(&full_room_id)?;
                    Ok(msgid)
                }).ok()
            }
        };

        if let Some(msgid) = saved_msgid {
            self.emit_data_change(DataChange::MessageAdded {
                room_id: full_room_id.clone(), msgid: msgid.clone(),
            }).await;
            self.emit_data_change(DataChange::RoomUpdated {
                room_id: full_room_id.clone(),
            }).await;
        }

        self.emit_event(ClientEvent::MessageReceived {
            room_id: full_room_id,
            sender_pubkey: ctx.sender_pubkey,
            kind: ctx.kind.into(),
            content: ctx.content,
            payload: ctx.payload_json,
            event_id: ctx.event_id,
            fallback: ctx.fallback,
            reply_to_event_id: ctx.reply_to_event_id,
            group_id: ctx.group_id,
            thread_id: ctx.thread_id,
            nostr_event_json: ctx.nostr_event_json,
            relay_url: ctx.relay_url,
        }).await;
    }

    async fn on_group_invite_received(&self, ctx: GroupInviteContext) {
        let identity_pubkey = &self.identity_pubkey;
        if !identity_pubkey.is_empty() {
            {
                let store = lock_app_storage(&self.app_storage);
                let _ = store.save_app_room(
                    &ctx.group_id, identity_pubkey,
                    RoomStatus::Enabled.to_i32(), RoomType::SignalGroup.to_i32(),
                    Some(&ctx.group_name), None, None,
                );
            }
            self.emit_data_change(DataChange::RoomListChanged).await;
        }

        self.emit_event(ClientEvent::GroupInviteReceived {
            room_id: ctx.group_id,
            group_type: ctx.group_type,
            group_name: ctx.group_name,
            inviter_pubkey: ctx.inviter_pubkey,
        }).await;
    }

    async fn on_group_changed(&self, ctx: GroupChangedContext) {
        let identity_pubkey = &self.identity_pubkey;
        let full_room_id = make_room_id(&ctx.group_id, identity_pubkey);

        match &ctx.change {
            libkeychat::orchestrator::GroupChangeKind::Dissolve { .. } => {
                if !identity_pubkey.is_empty() {
                    {
                        let store = lock_app_storage(&self.app_storage);
                        let _ = store.delete_app_room(&full_room_id);
                    }
                    self.emit_data_change(DataChange::RoomDeleted { room_id: full_room_id.clone() }).await;
                }
                self.emit_event(ClientEvent::GroupDissolved { room_id: ctx.group_id }).await;
            }
            libkeychat::orchestrator::GroupChangeKind::NameChanged { new_name } => {
                if let Some(ref name) = new_name {
                    if !identity_pubkey.is_empty() {
                        let store = lock_app_storage(&self.app_storage);
                        let _ = store.update_app_room(&full_room_id, None, Some(name), None, None);
                        drop(store);
                    }
                }
                self.emit_data_change(DataChange::RoomUpdated { room_id: full_room_id }).await;
                self.emit_event(ClientEvent::GroupMemberChanged {
                    room_id: ctx.group_id,
                    kind: GroupChangeKind::NameChanged,
                    member_pubkey: None,
                    new_value: new_name.clone(),
                }).await;
            }
            libkeychat::orchestrator::GroupChangeKind::MemberRemoved { member_pubkey } => {
                self.emit_data_change(DataChange::RoomUpdated { room_id: full_room_id }).await;
                self.emit_event(ClientEvent::GroupMemberChanged {
                    room_id: ctx.group_id,
                    kind: GroupChangeKind::MemberRemoved,
                    member_pubkey: member_pubkey.clone(),
                    new_value: None,
                }).await;
            }
            libkeychat::orchestrator::GroupChangeKind::SelfLeave { .. } => {
                if !identity_pubkey.is_empty() {
                    {
                        let store = lock_app_storage(&self.app_storage);
                        let _ = store.delete_app_room(&full_room_id);
                    }
                    self.emit_data_change(DataChange::RoomDeleted { room_id: full_room_id }).await;
                }
                self.emit_event(ClientEvent::GroupMemberChanged {
                    room_id: ctx.group_id,
                    kind: GroupChangeKind::SelfLeave,
                    member_pubkey: None,
                    new_value: None,
                }).await;
            }
        }
    }

    async fn on_nip17_dm_received(&self, ctx: Nip17DmContext) {
        let identity_pubkey = &self.identity_pubkey;
        if identity_pubkey.is_empty() { return; }

        let room_id = make_room_id(&ctx.sender_pubkey, identity_pubkey);
        let msgid = ctx.event_id.clone();

        {
            let store = lock_app_storage(&self.app_storage);
            let _ = store.save_app_room(
                &ctx.sender_pubkey, identity_pubkey,
                RoomStatus::Enabled.to_i32(), RoomType::Nip17Dm.to_i32(),
                None, None, None,
            );
            let _ = store.save_app_message(
                &msgid, Some(&ctx.event_id), &room_id, identity_pubkey,
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

    async fn on_relay_ok(
        &self,
        event_id: String,
        relay_url: String,
        success: bool,
        message: String,
    ) {
        let update = {
            let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.handle_relay_ok(&event_id, &relay_url, success, &message)
        };
        if let Some(update) = update {
            let msg_status = if update.all_resolved {
                Some(if update.has_success { MessageStatus::Success.to_i32() } else { MessageStatus::Failed.to_i32() })
            } else {
                None
            };

            {
                let store = lock_app_storage(&self.app_storage);
                let _ = store.update_app_message(
                    &update.msgid, None, msg_status, Some(&update.relay_status_json),
                    None, None, None, None,
                );
            }

            self.emit_data_change(DataChange::MessageUpdated {
                room_id: update.room_id, msgid: update.msgid,
            }).await;

            if update.all_resolved {
                let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
                tracker.cleanup_resolved();
            }
        }

        self.emit_event(ClientEvent::RelayOk {
            event_id, relay_url, success, message,
        }).await;
    }

    async fn on_error(&self, description: String) {
        self.emit_event(ClientEvent::EventLoopError { description }).await;
    }
}
