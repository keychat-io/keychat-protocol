//! Signal Group — read-lock pattern matching pre-refactor behavior.
//!
//! Key insight: group operations (create, send) must NOT hold inner write lock
//! during session mutex lock + relay publish. The pre-refactor code used read lock,
//! collected session Arcs, dropped the lock, then operated on sessions.

use libkeychat::{
    build_multi_file_message, create_signal_group, encrypt_for_group_member, send_group_invite,
    KCFilePayload, KCMessage,
};

use crate::app_client::{lock_app_storage, AppClient, AppError, AppResult};
use crate::types::*;

impl AppClient {
    pub async fn create_signal_group(
        &self,
        name: String,
        members: Vec<GroupMemberInput>,
    ) -> AppResult<SignalGroupInfo> {
        // Collect under read lock, then drop — matching pre-refactor pattern
        let (my_nostr, first_session_arc, other_members, member_sessions) = {
            let inner = self.inner.read().await;
            let identity = inner
                .protocol
                .identity()
                .ok_or(AppError::NotInitialized("no identity set".into()))?;
            let my_nostr = identity.pubkey_hex();
            let first_session_arc = inner.protocol.first_session();
            let mut other_members = Vec::new();
            let mut member_sessions = Vec::new();
            for m in &members {
                let sid = inner
                    .protocol
                    .nostr_to_signal(&m.nostr_pubkey)
                    .ok_or(AppError::PeerNotFound(m.nostr_pubkey.clone()))?
                    .clone();
                let sarc = inner
                    .protocol
                    .get_session(&sid)
                    .ok_or(AppError::PeerNotFound(sid.clone()))?;
                other_members.push((sid.clone(), m.nostr_pubkey.clone(), m.name.clone()));
                member_sessions.push((sid, sarc));
            }
            (my_nostr, first_session_arc, other_members, member_sessions)
        }; // read lock dropped

        let my_signal_id = if let Some(sm) = first_session_arc {
            let s = sm.lock().await;
            s.signal.identity_public_key_hex()
        } else {
            my_nostr.clone()
        };

        let group = create_signal_group(&name, &my_signal_id, &my_nostr, "Me", other_members);
        let group_id = group.group_id.clone();
        let group_name = group.name.clone();
        let member_count = group.members.len() as u32;

        // Send invite — no inner lock held
        for (signal_id, session_arc) in &member_sessions {
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            let event = send_group_invite(&mut session.signal, &group, signal_id, &addr)
                .await
                .map_err(|e| AppError::Signal(e.to_string()))?;
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let _ = t.publish_event_async(event).await;
            }
        }

        // Store group + persist (write lock)
        {
            let mut inner = self.inner.write().await;
            let gid = group.group_id.clone();
            inner.protocol.group_manager_mut().add_group(group);
            if let Ok(store) = inner.protocol.storage().clone().lock() {
                let _ = inner.protocol.group_manager_mut().save_group(&gid, &store);
            }
        }

        // App: save room
        let identity_pubkey = self.cached_identity_pubkey();
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_room(&group_id, &identity_pubkey, 1, 1, Some(&name), None, None);
        }
        self.emit_data_change(DataChange::RoomListChanged).await;

        Ok(SignalGroupInfo {
            group_id,
            name: group_name,
            member_count,
        })
    }

    pub async fn get_signal_group_members(
        &self,
        group_id: String,
    ) -> AppResult<Vec<GroupMemberInfo>> {
        let inner = self.inner.read().await;
        let group = inner
            .protocol
            .group_manager()
            .get_group(&group_id)
            .ok_or(AppError::PeerNotFound(group_id))?;
        Ok(group
            .members
            .values()
            .map(|m| GroupMemberInfo {
                nostr_pubkey: m.nostr_pubkey.clone(),
                name: m.name.clone(),
                is_admin: group.is_admin(&m.signal_id),
                is_me: m.signal_id == group.my_signal_id,
            })
            .collect())
    }

    pub async fn send_group_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<GroupSentMessage> {
        let mut msg = KCMessage::text(&text);
        if let Some(ref rt) = reply_to {
            msg.reply_to = Some(libkeychat::ReplyTo {
                target_id: None,
                target_event_id: Some(rt.target_event_id.clone()),
                content: rt.content.clone().unwrap_or_default(),
                user_id: None,
                user_name: None,
            });
        }
        let display = if text.is_empty() { "[Message]" } else { &text };
        self.send_group_message_internal(group_id, msg, display, &reply_to)
            .await
    }

    pub async fn send_group_file(
        &self,
        group_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<GroupSentMessage> {
        if files.is_empty() {
            return Err(AppError::InvalidArgument("files empty".into()));
        }
        let kc_files: Vec<KCFilePayload> = files
            .iter()
            .map(|f| KCFilePayload {
                category: f.category.to_lib(),
                url: f.url.clone(),
                type_: f.mime_type.clone(),
                suffix: f.suffix.clone(),
                size: Some(f.size),
                key: Some(f.key.clone()),
                iv: Some(f.iv.clone()),
                hash: Some(f.hash.clone()),
                source_name: f.source_name.clone(),
                audio_duration: f.audio_duration.map(|d| d as f64),
                amplitude_samples: f.amplitude_samples.clone(),
                ecash_token: None,
            })
            .collect();
        let mut msg = build_multi_file_message(kc_files);
        if let Some(ref m) = message {
            if let Some(ref mut fs) = msg.files {
                fs.message = Some(m.clone());
            }
        }
        if let Some(ref rt) = reply_to {
            msg.reply_to = Some(libkeychat::ReplyTo {
                target_id: None,
                target_event_id: Some(rt.target_event_id.clone()),
                content: rt.content.clone().unwrap_or_default(),
                user_id: None,
                user_name: None,
            });
        }
        let display = match message.as_deref() {
            Some(m) if !m.is_empty() => m,
            _ => "[File]",
        };
        self.send_group_message_internal(group_id, msg, display, &reply_to)
            .await
    }

    pub async fn leave_signal_group(&self, group_id: String) -> AppResult<()> {
        let mut inner = self.inner.write().await;
        inner.protocol.leave_group_protocol(&group_id).await?;
        Ok(())
    }

    pub async fn dissolve_signal_group(&self, group_id: String) -> AppResult<()> {
        let mut inner = self.inner.write().await;
        inner.protocol.dissolve_group_protocol(&group_id).await?;
        Ok(())
    }

    pub async fn remove_group_member(
        &self,
        group_id: String,
        member_nostr_pubkey: String,
    ) -> AppResult<()> {
        let mut inner = self.inner.write().await;
        inner
            .protocol
            .remove_member_protocol(&group_id, &member_nostr_pubkey)
            .await?;
        Ok(())
    }

    pub async fn rename_signal_group(&self, group_id: String, new_name: String) -> AppResult<()> {
        let mut inner = self.inner.write().await;
        inner
            .protocol
            .rename_group_protocol(&group_id, &new_name)
            .await?;
        Ok(())
    }

    /// Fan-out: read lock → collect → drop → encrypt+publish (no write lock during send)
    async fn send_group_message_internal(
        &self,
        group_id: String,
        mut msg: KCMessage,
        display_text: &str,
        reply_to: &Option<ReplyToPayload>,
    ) -> AppResult<GroupSentMessage> {
        let identity_pubkey = self.cached_identity_pubkey();
        msg.group_id = Some(group_id.clone());
        let payload_json = msg.to_json().ok();

        // Collect under read lock
        let (group, member_sessions, connected_relays) = {
            let inner = self.inner.read().await;
            let group = inner
                .protocol
                .group_manager()
                .get_group(&group_id)
                .ok_or(AppError::PeerNotFound(group_id.clone()))?
                .clone();
            let transport = inner
                .protocol
                .transport()
                .ok_or(AppError::Transport("Not connected".into()))?;
            let connected = transport.connected_relays().await;
            let mut sessions = Vec::new();
            for member in group.other_members() {
                if let Some(sid) = inner.protocol.nostr_to_signal(&member.nostr_pubkey) {
                    if let Some(s) = inner.protocol.get_session(sid) {
                        sessions.push((sid.clone(), s));
                    }
                }
            }
            (group, sessions, connected)
        }; // read lock dropped

        if connected_relays.is_empty() {
            return Err(AppError::Transport("Not connected".into()));
        }

        // Encrypt + publish without inner lock
        let mut event_ids = Vec::new();
        for (signal_id, session_arc) in &member_sessions {
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            match encrypt_for_group_member(&mut session.signal, signal_id, &msg, &addr).await {
                Ok(event) => {
                    let eid = event.id.to_hex();
                    let inner = self.inner.read().await;
                    if let Some(t) = inner.protocol.transport() {
                        let _ = t.publish_event_async(event).await;
                    }
                    event_ids.push(eid);
                }
                Err(e) => tracing::error!(
                    "group send to {} failed: {e}",
                    &signal_id[..16.min(signal_id.len())]
                ),
            }
        }

        // App persistence
        let full_room_id = make_room_id(&group_id, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let msgid = format!("gsend-{}-{}", &group_id[..16.min(group_id.len())], now);

        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_message(
                &msgid,
                Some(&msgid),
                &full_room_id,
                &identity_pubkey,
                &identity_pubkey,
                display_text,
                true,
                0,
                now,
            );
            let _ = store.update_app_message(
                &msgid,
                None,
                None,
                None,
                payload_json.as_deref(),
                None,
                reply_to.as_ref().map(|r| r.target_event_id.as_str()),
                reply_to.as_ref().and_then(|r| r.content.as_deref()),
            );
            let _ = store.update_app_room(&full_room_id, None, None, Some(display_text), Some(now));
        }

        self.emit_data_change(DataChange::MessageAdded {
            room_id: full_room_id.clone(),
            msgid: msgid.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: full_room_id.clone(),
        })
        .await;

        let members_for_tracker: Vec<(String, String)> = event_ids
            .iter()
            .enumerate()
            .map(|(i, eid)| (eid.clone(), format!("member_{i}")))
            .collect();
        let initial_relay_json = {
            let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.track_group(
                msgid.clone(),
                full_room_id.clone(),
                members_for_tracker,
                connected_relays,
            )
        };
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let eid_ref = event_ids.first().map(|s| s.as_str());
            let _ = store.update_app_message(
                &msgid,
                eid_ref,
                None,
                Some(&initial_relay_json),
                None,
                None,
                None,
                None,
            );
        }

        self.emit_data_change(DataChange::MessageUpdated {
            room_id: full_room_id,
            msgid: msgid.clone(),
        })
        .await;

        Ok(GroupSentMessage {
            msgid,
            group_id,
            event_ids,
            payload_json,
            nostr_event_json: None,
            relay_status_json: Some(initial_relay_json),
        })
    }
}
