//! Signal Group (sendAll) UniFFI bindings.
//!
//! Wraps libkeychat::group functions for Swift consumption.
//! Groups use per-member 1:1 Signal encryption — each message
//! is encrypted individually for every member.

use libkeychat::{
    build_group_admin_message, create_signal_group, encrypt_for_group_member, send_group_invite,
    KCMessage, KCMessageKind, SignalGroup,
};

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

impl KeychatClient {
    /// Helper: send a list of (member_id, Event) tuples to relay (fire-and-forget).
    pub(crate) async fn broadcast_group_events(
        &self,
        events: Vec<(String, nostr::Event)>,
    ) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;

        let mut event_ids = Vec::with_capacity(events.len());
        for (_member_id, event) in events {
            event_ids.push(event.id.to_hex());
            if let Err(e) = transport.publish_event_async(event).await {
                tracing::warn!("broadcast_group_events: send failed: {e}");
            }
        }

        Ok(event_ids)
    }

    /// Encrypt a KCMessage for each group member using their individual 1:1 session,
    /// then broadcast all events to relay. Used by leave/dissolve/rename/kick.
    pub(crate) async fn send_group_admin_to_all(
        &self,
        group: &SignalGroup,
        msg: &KCMessage,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
            msg: "Not connected to any relay. Please check your network.".into(),
        })?;

        // Encrypt sequentially (needs mutable session locks), collect events
        let mut events = Vec::new();
        for member in group.other_members() {
            let signal_id = match inner.peer_nostr_to_signal.get(&member.nostr_pubkey) {
                Some(sid) => sid.clone(),
                None => { continue; }
            };
            let session_mutex = match inner.sessions.get(&signal_id) {
                Some(s) => s.clone(),
                None => { continue; }
            };

            let event = {
                let mut session = session_mutex.lock().await;
                let addr = session.addresses.clone();
                encrypt_for_group_member(
                    &mut session.signal,
                    &signal_id,
                    msg,
                    &addr,
                )
                .await
                .map_err(|e| KeychatUniError::Signal { msg: e.to_string() })?
            };

            events.push(event);
        }

        // Fire-and-forget: push to relay websocket without waiting for OK
        for event in events {
            if let Err(e) = transport.publish_event_async(event).await {
                tracing::warn!("send group admin event failed: {e}");
            }
        }

        Ok(())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Create a new Signal group.
    ///
    /// `members` is a list of (peer_nostr_pubkey, name) tuples.
    /// Each peer must already have an established 1:1 Signal session.
    /// Returns the group_id and sends invites to all members.
    pub async fn create_signal_group(
        &self,
        name: String,
        members: Vec<GroupMemberInput>,
    ) -> Result<SignalGroupInfo, KeychatUniError> {
        // I-15: Collect all data under read lock, then drop before async work
        let (my_nostr_pubkey, my_signal_id, other_members, member_sessions) = {
            let inner = self.inner.read().await;

            let identity = inner
                .identity
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "no identity set".into(),
                })?;
            let my_nostr_pubkey = identity.pubkey_hex();

            let my_signal_id = if let Some(session_mutex) = inner.sessions.values().next() {
                let session = session_mutex.lock().await;
                session.signal.identity_public_key_hex()
            } else {
                tracing::warn!(
                    "create_signal_group: no sessions available, using nostr pubkey as signal_id"
                );
                my_nostr_pubkey.clone()
            };

            let mut other_members = Vec::new();
            let mut member_sessions = Vec::new();
            for member in &members {
                let signal_id = inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .ok_or(KeychatUniError::PeerNotFound {
                        peer_id: member.nostr_pubkey.clone(),
                    })?
                    .clone();
                let session_arc = inner
                    .sessions
                    .get(&signal_id)
                    .ok_or(KeychatUniError::PeerNotFound {
                        peer_id: signal_id.clone(),
                    })?
                    .clone();
                other_members.push((
                    signal_id.clone(),
                    member.nostr_pubkey.clone(),
                    member.name.clone(),
                ));
                member_sessions.push((signal_id, session_arc));
            }

            (
                my_nostr_pubkey,
                my_signal_id,
                other_members,
                member_sessions,
            )
        }; // read lock dropped

        let group =
            create_signal_group(&name, &my_signal_id, &my_nostr_pubkey, "Me", other_members);

        let group_id = group.group_id.clone();
        let group_name = group.name.clone();
        let member_count = group.members.len() as u32;

        tracing::info!(
            "created signal group: id={}, name={}, members={}",
            &group_id[..16.min(group_id.len())],
            name,
            member_count
        );

        // Send invite to each member (no read lock held)
        let mut all_events = Vec::new();
        for (signal_id, session_arc) in &member_sessions {
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            let event = send_group_invite(&mut session.signal, &group, signal_id, &addr).await?;
            tracing::info!(
                "sent group invite to {}",
                &signal_id[..16.min(signal_id.len())]
            );
            all_events.push((signal_id.clone(), event));
        }
        let _ = self.broadcast_group_events(all_events).await;

        // Store group in manager + persist
        let mut inner = self.inner.write().await;
        let gid = group.group_id.clone();
        inner.group_manager.add_group(group);
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner.group_manager.save_group(&gid, &store);
        }

        Ok(SignalGroupInfo {
            group_id,
            name: group_name,
            member_count,
        })
    }

    /// Get the member list for a Signal group.
    pub async fn get_signal_group_members(
        &self,
        group_id: String,
    ) -> Result<Vec<GroupMemberInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let group = inner
            .group_manager
            .get_group(&group_id)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: group_id.clone(),
            })?;

        let members = group
            .members
            .values()
            .map(|m| GroupMemberInfo {
                nostr_pubkey: m.nostr_pubkey.clone(),
                name: m.name.clone(),
                is_admin: group.is_admin(&m.signal_id),
                is_me: m.signal_id == group.my_signal_id,
            })
            .collect();

        Ok(members)
    }

    /// Send a text message to a Signal group.
    /// The message is encrypted and sent individually to each member.
    pub async fn send_group_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<GroupSentMessage, KeychatUniError> {
        // 1. Gather group, identity, check connectivity under read lock
        let (group, identity_pubkey, connected_relays) = {
            let inner = self.inner.read().await;

            let group = inner
                .group_manager
                .get_group(&group_id)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: group_id.clone(),
                })?
                .clone();

            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::Transport {
                    msg: "Not connected to any relay. Please check your network.".into(),
                })?;
            let connected = transport.connected_relays().await;

            let identity_pubkey = inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default();

            (group, identity_pubkey, connected)
        }; // read lock dropped

        if connected_relays.is_empty() {
            return Err(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            });
        }

        // 2. Build KCMessage and prepare metadata
        let mut msg = KCMessage::text(&text);
        msg.group_id = Some(group_id.clone());
        if let Some(ref rt) = reply_to {
            msg.reply_to = Some(libkeychat::ReplyTo {
                target_id: None,
                target_event_id: Some(rt.target_event_id.clone()),
                content: rt.content.clone().unwrap_or_default(),
                user_id: None,
                user_name: None,
            });
        }
        let payload_json = msg.to_json().ok();

        let full_room_id = format!("{}:{}", group_id, identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let msgid = format!(
            "gsend-{}-{}",
            &group_id[..16.min(group_id.len())],
            now
        );

        // 3. Save message to DB FIRST (status=0 sending) — Swift shows it immediately
        {
            let send_storage = self.inner.read().await.app_storage.clone();
            let store = crate::client::lock_app_storage(&send_storage);
            if let Err(e) = store.save_app_message(
                &msgid,
                Some(&msgid),
                &full_room_id,
                &identity_pubkey,
                &identity_pubkey,
                &text,
                true,
                0,
                now,
            ) {
                tracing::warn!("save_app_message (group send): {e}");
            }
            // Store payload + reply_to metadata
            if let Err(e) = store.update_app_message(
                &msgid, None, None, None,
                payload_json.as_deref(), None,
                reply_to.as_ref().map(|r| r.target_event_id.as_str()),
                reply_to.as_ref().and_then(|r| r.content.as_deref()),
            ) {
                tracing::warn!("update_app_message (group send payload): {e}");
            }
            let display = if text.is_empty() { "[Message]" } else { &text };
            if let Err(e) =
                store.update_app_room(&full_room_id, None, None, Some(display), Some(now))
            {
                tracing::warn!("update_app_room (group send): {e}");
            }
        }

        // 4. Emit DataChange BEFORE relay publish — Swift shows message immediately
        self.emit_data_change(DataChange::MessageAdded {
            room_id: full_room_id.clone(),
            msgid: msgid.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: full_room_id.clone(),
        })
        .await;

        // 5. Encrypt for each member (sequential — needs mutable session locks),
        //    then send all events concurrently.
        let mut event_ids = Vec::new();
        let mut nostr_events_json = Vec::new();

        // Collect encrypted events + metadata
        struct PendingEvent {
            event: nostr::Event,
            eid: String,
            member_name: String,
        }
        let mut pending: Vec<PendingEvent> = Vec::new();

        {
            let inner = self.inner.read().await;
            for member in group.other_members() {
                // Look up session by nostr_pubkey — the only globally stable identifier
                let signal_id = match inner.peer_nostr_to_signal.get(&member.nostr_pubkey) {
                    Some(sid) => sid.clone(),
                    None => {
                        tracing::warn!(
                            "no signal_id for group member nostr={}",
                            &member.nostr_pubkey[..16.min(member.nostr_pubkey.len())],
                        );
                        continue;
                    }
                };
                let session_mutex = match inner.sessions.get(&signal_id) {
                    Some(s) => s.clone(),
                    None => {
                        tracing::warn!(
                            "no session for group member nostr={}",
                            &member.nostr_pubkey[..16.min(member.nostr_pubkey.len())],
                        );
                        continue;
                    }
                };

                let event = {
                    let mut session = session_mutex.lock().await;
                    let addr = session.addresses.clone();
                    encrypt_for_group_member(
                        &mut session.signal,
                        &signal_id,
                        &msg,
                        &addr,
                    )
                    .await
                    .map_err(|e| KeychatUniError::Signal { msg: e.to_string() })?
                };

                let eid = event.id.to_hex();
                if let Ok(json) = serde_json::to_string(&event) {
                    nostr_events_json.push(json);
                }
                event_ids.push(eid.clone());
                pending.push(PendingEvent { event, eid, member_name: member.name.clone() });
            }
        } // read lock dropped

        // Fire-and-forget: push to relay websocket without waiting for OK
        let mut relay_statuses = Vec::with_capacity(pending.len());
        {
            let inner = self.inner.read().await;
            let transport = inner.transport.as_ref().ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
            for p in pending {
                match transport.publish_event_async(p.event).await {
                    Ok(_) => {
                        relay_statuses.push(format!(
                            r#"{{"event_id":"{}","member":"{}","status":"success"}}"#,
                            p.eid, p.member_name
                        ));
                    }
                    Err(e) => {
                        relay_statuses.push(format!(
                            r#"{{"event_id":"{}","member":"{}","status":"failed","error":"{}"}}"#,
                            p.eid, p.member_name, e
                        ));
                    }
                }
            }
        }

        // 6. Update message with final status, event data, and relay tracking
        let all_success = relay_statuses.iter().all(|s| s.contains("\"success\""));
        let status = if event_ids.is_empty() { 2 } else if all_success { 1 } else { 1 }; // 1=success, 2=failed
        let relay_status_json = format!("[{}]", relay_statuses.join(","));
        // Store all Nostr events as a JSON array
        let nostr_event_json = format!("[{}]", nostr_events_json.join(","));

        {
            let send_storage = self.inner.read().await.app_storage.clone();
            let store = crate::client::lock_app_storage(&send_storage);
            let event_id_ref = event_ids.first().map(|s| s.as_str());
            if let Err(e) = store.update_app_message(
                &msgid,
                event_id_ref,                   // event_id (first one as primary)
                Some(status),                   // status
                Some(&relay_status_json),        // relay_status_json
                None,                           // payload already saved
                Some(&nostr_event_json),         // all nostr events
                None, None,
            ) {
                tracing::warn!("update_app_message (group send finalize): {e}");
            }
        }

        // 7. Emit MessageUpdated so Swift refreshes the status
        self.emit_data_change(DataChange::MessageUpdated {
            room_id: full_room_id,
            msgid: msgid.clone(),
        })
        .await;

        tracing::info!(
            "sent group text to {} members, group={}",
            event_ids.len(),
            &group_id[..16.min(group_id.len())]
        );

        Ok(GroupSentMessage {
            group_id,
            event_ids,
        })
    }

    /// Leave a Signal group. Notifies all members.
    pub async fn leave_signal_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        let group = {
            let inner = self.inner.read().await;
            inner.group_manager.get_group(&group_id)
                .ok_or(KeychatUniError::PeerNotFound { peer_id: group_id.clone() })?
                .clone()
        };

        let payload = serde_json::json!({ "action": "selfLeave", "memberId": group.my_signal_id });
        let msg = build_group_admin_message(KCMessageKind::SignalGroupSelfLeave, &group, payload);
        self.send_group_admin_to_all(&group, &msg).await?;

        // Remove group from manager + storage
        let mut inner = self.inner.write().await;
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner.group_manager.remove_group_persistent(&group_id, &store);
        } else {
            inner.group_manager.remove_group(&group_id);
        }

        tracing::info!("left signal group {}", &group_id[..16.min(group_id.len())]);
        Ok(())
    }

    /// Dissolve a Signal group (admin only). Notifies all members.
    pub async fn dissolve_signal_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        let group = {
            let inner = self.inner.read().await;
            inner.group_manager.get_group(&group_id)
                .ok_or(KeychatUniError::PeerNotFound { peer_id: group_id.clone() })?
                .clone()
        };

        let payload = serde_json::json!({ "action": "dissolve" });
        let msg = build_group_admin_message(KCMessageKind::SignalGroupDissolve, &group, payload);
        self.send_group_admin_to_all(&group, &msg).await?;

        let mut inner = self.inner.write().await;
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner.group_manager.remove_group_persistent(&group_id, &store);
        } else {
            inner.group_manager.remove_group(&group_id);
        }

        tracing::info!("dissolved signal group {}", &group_id[..16.min(group_id.len())]);
        Ok(())
    }

    /// Remove a member from a Signal group (admin only).
    pub async fn remove_group_member(
        &self,
        group_id: String,
        member_nostr_pubkey: String,
    ) -> Result<(), KeychatUniError> {
        let (group, removed_signal_id) = {
            let inner = self.inner.read().await;
            let group = inner.group_manager.get_group(&group_id)
                .ok_or(KeychatUniError::PeerNotFound { peer_id: group_id.clone() })?
                .clone();
            let removed_signal_id = inner.peer_nostr_to_signal
                .get(&member_nostr_pubkey)
                .ok_or(KeychatUniError::PeerNotFound { peer_id: member_nostr_pubkey.clone() })?
                .clone();
            (group, removed_signal_id)
        };

        let payload = serde_json::json!({ "action": "memberRemoved", "memberId": removed_signal_id });
        let msg = build_group_admin_message(KCMessageKind::SignalGroupMemberRemoved, &group, payload);
        self.send_group_admin_to_all(&group, &msg).await?;

        // Update group state + persist
        let mut inner = self.inner.write().await;
        if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
            g.remove_member(&removed_signal_id);
        }
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner.group_manager.save_group(&group_id, &store);
        }

        tracing::info!(
            "removed member {} from group {}",
            &member_nostr_pubkey[..16.min(member_nostr_pubkey.len())],
            &group_id[..16.min(group_id.len())]
        );
        Ok(())
    }

    /// Rename a Signal group (admin only).
    pub async fn rename_signal_group(
        &self,
        group_id: String,
        new_name: String,
    ) -> Result<(), KeychatUniError> {
        let group = {
            let inner = self.inner.read().await;
            inner.group_manager.get_group(&group_id)
                .ok_or(KeychatUniError::PeerNotFound { peer_id: group_id.clone() })?
                .clone()
        };

        let payload = serde_json::json!({ "action": "nameChanged", "newName": new_name });
        let msg = build_group_admin_message(KCMessageKind::SignalGroupNameChanged, &group, payload);
        self.send_group_admin_to_all(&group, &msg).await?;

        let mut inner = self.inner.write().await;
        if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
            g.name = new_name.clone();
        }

        tracing::info!(
            "renamed group {} to {}",
            &group_id[..16.min(group_id.len())],
            new_name
        );
        Ok(())
    }
}
