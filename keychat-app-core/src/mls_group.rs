//! MLS Group — app-layer MLS group operations.
//!
//! Implements create, send, leave, add/remove members, and rebuild for MLS groups.
//! Follows the same read-lock-then-drop pattern as group.rs for Signal groups.

use std::sync::Arc;

use libkeychat::{
    build_multi_file_message, encrypt_for_group_member, KCFilePayload, KCMessage, KCMessageKind,
    MlsGroupInvitePayload,
};

use crate::app_client::{lock_app_storage, AppClient, AppError, AppResult};
use crate::types::*;

impl AppClient {
    /// Get or lazily initialize the MLS participant.
    ///
    /// Uses a file-backed MLS provider at `mls_db_path` so group state
    /// survives app restarts.  The signer public key is persisted to
    /// app_settings ("mls_signer_pk") so the same signing identity is
    /// restored on subsequent launches.
    fn mls_participant_guard(
        &self,
    ) -> AppResult<std::sync::MutexGuard<'_, Option<libkeychat::MlsParticipant>>> {
        let mut guard = self
            .mls_participant
            .lock()
            .map_err(|e| AppError::Mls(format!("mls_participant lock: {e}")))?;
        if guard.is_none() {
            let identity_pubkey = self.cached_identity_pubkey();
            if identity_pubkey.is_empty() {
                return Err(AppError::NotInitialized("no identity set".into()));
            }

            // Open file-backed MLS provider (state persists across restarts)
            let provider = libkeychat::MlsProvider::open(&self.mls_db_path)?;

            // Try to restore the saved signer public key from the in-memory cache
            // (avoids try_read() race when a write lock is held on self.inner)
            let saved_signer_pk: Option<Vec<u8>> = self
                .mls_signer_pk
                .lock()
                .ok()
                .and_then(|cached| cached.clone())
                .and_then(|hex_str| hex::decode(&hex_str).ok());

            let participant = libkeychat::MlsParticipant::with_provider_and_signer(
                &identity_pubkey,
                provider,
                saved_signer_pk.as_deref(),
            )?;

            // Update the in-memory cache with the actual signer public key
            let signer_pk_hex = hex::encode(participant.signer_public_key());
            if let Ok(mut cached) = self.mls_signer_pk.lock() {
                *cached = Some(signer_pk_hex.clone());
            }
            // Best-effort persist to app_settings for cross-restart durability
            if let Ok(inner) = self.inner.try_read() {
                let store = lock_app_storage(&inner.app_storage);
                let _ = store.set_setting("mls_signer_pk", &signer_pk_hex);
            }

            *guard = Some(participant);
        }
        Ok(guard)
    }

    // ─── Create ─────────────────────────────────────────────

    pub async fn create_mls_group(
        &self,
        name: String,
        members: Vec<GroupMemberInput>,
    ) -> AppResult<MlsGroupCreatedInfo> {
        let identity_pubkey = self.cached_identity_pubkey();
        if identity_pubkey.is_empty() {
            return Err(AppError::NotInitialized("no identity set".into()));
        }

        // Generate a random group_id (64-char hex)
        let group_id = nostr::Keys::generate().public_key().to_hex();

        // Create MLS group (sync, holding mls_participant lock)
        {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            participant.create_group(&group_id, &name)?;
        }

        let member_count = 1 + members.len() as u32; // creator + invited
        let room_id = make_room_id(&group_id, &identity_pubkey);

        // Persist room and members before sending invites so a crash after
        // invite delivery cannot leave a group with no local record.
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_room(
                &group_id,
                &identity_pubkey,
                RoomStatus::Enabled.to_i32(),
                RoomType::MlsGroup.to_i32(),
                Some(&name),
                None,
                None,
            );
            let _ = store.save_room_member(
                &room_id,
                &identity_pubkey,
                Some("Me"),
                true,
                MemberStatus::Invited.to_i32(),
            );
            for m in &members {
                let _ = store.save_room_member(
                    &room_id,
                    &m.nostr_pubkey,
                    Some(&m.name),
                    false,
                    MemberStatus::Inviting.to_i32(),
                );
            }
        }

        // Register temp_inbox → group_id in the routing map
        self.register_mls_inbox(&group_id)?;

        // Fetch KeyPackages, add members, broadcast commit, send Welcome
        self.mls_fetch_add_and_invite(&group_id, &name, &identity_pubkey, &members)
            .await?;

        self.emit_data_change(DataChange::RoomListChanged).await;

        Ok(MlsGroupCreatedInfo {
            room_id,
            group_id,
            name,
            member_count,
        })
    }

    // ─── Send Text ──────────────────────────────────────────

    pub async fn send_mls_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<MlsSentMessage> {
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
        let display = if text.is_empty() { "[Message]" } else { &text };
        self.send_mls_message_internal(group_id, msg, display, &reply_to)
            .await
    }

    // ─── Send File ──────────────────────────────────────────

    pub async fn send_mls_file(
        &self,
        group_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<MlsSentMessage> {
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
        msg.group_id = Some(group_id.clone());
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
        self.send_mls_message_internal(group_id, msg, display, &reply_to)
            .await
    }

    // ─── Leave ──────────────────────────────────────────────

    pub async fn leave_mls_group(&self, group_id: String) -> AppResult<()> {
        let identity_pubkey = self.cached_identity_pubkey();

        // Generate a self-remove Commit (not a Proposal) so the removal
        // takes effect immediately without relying on an admin to commit it.
        let event = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            let self_leaf_index =
                participant.find_member_index(&group_id, &identity_pubkey)?;
            let commit_bytes =
                participant.remove_members(&group_id, &[self_leaf_index])?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            libkeychat::broadcast_commit(&commit_bytes, &mls_temp_inbox)?
        };

        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let _ = t.publish_event_async(event).await;
            }
        }

        // Remove from mls_inbox_map
        {
            let mut map = self
                .mls_inbox_map
                .lock()
                .map_err(|e| AppError::Mls(format!("mls_inbox_map lock: {e}")))?;
            map.retain(|_, gid| gid != &group_id);
        }

        // Archive room locally
        let room_id = make_room_id(&group_id, &identity_pubkey);
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.update_app_room(
                &room_id,
                Some(RoomStatus::Archived.to_i32()),
                None,
                None,
                None,
            );
        }

        self.emit_data_change(DataChange::RoomUpdated { room_id }).await;
        Ok(())
    }

    // ─── Add Members ────────────────────────────────────────

    pub async fn add_mls_members(
        &self,
        group_id: String,
        members: Vec<GroupMemberInput>,
    ) -> AppResult<()> {
        let identity_pubkey = self.cached_identity_pubkey();

        // Read group name for the invite payload
        let group_name = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            let ext = participant.group_extension(&group_id)?;
            ext.name()
        };

        // Fetch KeyPackages, add members, broadcast commit, send Welcome
        self.mls_fetch_add_and_invite(&group_id, &group_name, &identity_pubkey, &members)
            .await?;

        // Save members to app_storage with Inviting status
        let room_id = make_room_id(&group_id, &identity_pubkey);
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            for m in &members {
                let _ = store.save_room_member(
                    &room_id,
                    &m.nostr_pubkey,
                    Some(&m.name),
                    false,
                    MemberStatus::Inviting.to_i32(),
                );
            }
        }

        self.emit_data_change(DataChange::RoomUpdated { room_id }).await;
        Ok(())
    }

    // ─── Remove Members ─────────────────────────────────────

    pub async fn remove_mls_members(
        &self,
        group_id: String,
        member_pubkeys: Vec<String>,
    ) -> AppResult<()> {
        let identity_pubkey = self.cached_identity_pubkey();

        // Find leaf indices and remove via MLS commit
        let event = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            let mut indices = Vec::new();
            for pk in &member_pubkeys {
                indices.push(participant.find_member_index(&group_id, pk)?);
            }
            let commit_bytes = participant.remove_members(&group_id, &indices)?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            libkeychat::broadcast_commit(&commit_bytes, &mls_temp_inbox)?
        };

        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let _ = t.publish_event_async(event).await;
            }
        }

        // Mark members as removed in app_storage
        let room_id = make_room_id(&group_id, &identity_pubkey);
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            for pk in &member_pubkeys {
                let _ = store.update_room_member(
                    &room_id,
                    pk,
                    None,
                    None,
                    Some(MemberStatus::Removed.to_i32()),
                );
            }
        }

        self.emit_data_change(DataChange::RoomUpdated { room_id }).await;
        Ok(())
    }

    // ─── Rebuild ────────────────────────────────────────────

    pub async fn rebuild_mls_group(
        &self,
        archived_room_id: String,
    ) -> AppResult<MlsGroupCreatedInfo> {
        let identity_pubkey = self.cached_identity_pubkey();

        // Read old room's members and name
        let (old_name, members) = {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);

            let room = store
                .get_app_room(&archived_room_id)
                .map_err(|e| AppError::Storage(format!("get archived room: {e}")))?
                .ok_or_else(|| {
                    AppError::InvalidArgument(format!("room not found: {archived_room_id}"))
                })?;
            let old_name = room.name.unwrap_or_else(|| "Rebuilt Group".to_string());

            let member_rows = store
                .get_room_members(&archived_room_id)
                .map_err(|e| AppError::Storage(format!("get room members: {e}")))?;

            let members: Vec<GroupMemberInput> = member_rows
                .into_iter()
                .filter(|m| {
                    m.pubkey != identity_pubkey
                        && m.status != MemberStatus::Removed.to_i32()
                })
                .map(|m| GroupMemberInput {
                    nostr_pubkey: m.pubkey,
                    name: m.name.unwrap_or_default(),
                })
                .collect();

            (old_name, members)
        };

        // Create new group with same members
        let info = self.create_mls_group(old_name, members).await?;

        // Archive old room and point it to the new room
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.update_app_room(
                &archived_room_id,
                Some(RoomStatus::Archived.to_i32()),
                None,
                None,
                None,
            );
            let _ = store.set_app_room_parent(&info.room_id, &archived_room_id);
            // 新群.parent_room_id = 老群.room_id (predecessor / 前身群)
        }

        self.emit_data_change(DataChange::RoomUpdated {
            room_id: archived_room_id,
        })
        .await;

        Ok(info)
    }

    // ─── MLS Inbox Routing ────────────────────────────────────

    /// Register a mapping from the MLS group's current temp_inbox to its group_id.
    /// Returns the temp_inbox address.
    pub(crate) fn register_mls_inbox(&self, group_id: &str) -> AppResult<String> {
        let temp_inbox = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            participant.derive_temp_inbox(group_id)?
        };
        {
            let mut map = self
                .mls_inbox_map
                .lock()
                .map_err(|e| AppError::Mls(format!("mls_inbox_map lock: {e}")))?;
            map.insert(temp_inbox.clone(), group_id.to_string());
        }
        tracing::debug!(
            "[MLS] registered inbox {} → group {}",
            &temp_inbox[..16.min(temp_inbox.len())],
            &group_id[..16.min(group_id.len())]
        );
        Ok(temp_inbox)
    }

    /// O(1) lookup: resolve a temp_inbox address to a group_id.
    pub(crate) fn resolve_mls_group(&self, temp_inbox: &str) -> Option<String> {
        self.mls_inbox_map
            .lock()
            .ok()
            .and_then(|map| map.get(temp_inbox).cloned())
    }

    /// After an epoch change (Commit), rotate the inbox mapping:
    /// remove old temp_inbox, derive and register the new one.
    /// Returns (old_inbox, new_inbox).
    pub(crate) fn rotate_mls_inbox(
        &self,
        group_id: &str,
    ) -> AppResult<(String, String)> {
        // Remove old entry for this group_id
        let old_inbox = {
            let mut map = self
                .mls_inbox_map
                .lock()
                .map_err(|e| AppError::Mls(format!("mls_inbox_map lock: {e}")))?;
            let old = map
                .iter()
                .find(|(_, gid)| gid.as_str() == group_id)
                .map(|(inbox, _)| inbox.clone());
            if let Some(ref old_key) = old {
                map.remove(old_key);
            }
            old.unwrap_or_default()
        };

        // Derive and register new temp_inbox
        let new_inbox = self.register_mls_inbox(group_id)?;

        tracing::info!(
            "[MLS] rotated inbox for group {}: {} → {}",
            &group_id[..16.min(group_id.len())],
            if old_inbox.is_empty() {
                "(none)"
            } else {
                &old_inbox[..16.min(old_inbox.len())]
            },
            &new_inbox[..16.min(new_inbox.len())]
        );
        Ok((old_inbox, new_inbox))
    }

    /// Restore the mls_inbox_map from all active MLS groups in app_storage.
    /// Returns the list of temp_inbox addresses (for subscribing on startup).
    pub async fn restore_mls_inbox_map(&self) -> AppResult<Vec<String>> {
        let group_ids: Vec<String> = {
            let inner = self.inner.read().await;
            let store = lock_app_storage(&inner.app_storage);
            store.get_active_mls_group_ids().unwrap_or_default()
        };

        let mut inboxes = Vec::with_capacity(group_ids.len());
        for gid in &group_ids {
            match self.register_mls_inbox(gid) {
                Ok(inbox) => inboxes.push(inbox),
                Err(e) => {
                    tracing::warn!(
                        "[MLS] restore_mls_inbox_map: skip group {}: {e}",
                        &gid[..16.min(gid.len())]
                    );
                }
            }
        }

        tracing::info!(
            "[MLS] restored inbox map: {} groups, {} inboxes",
            group_ids.len(),
            inboxes.len()
        );
        Ok(inboxes)
    }

    // ─── MLS Receive ─────────────────────────────────────────

    /// Try to decrypt an incoming event as an MLS group message.
    ///
    /// Uses the mls_inbox_map for O(1) p-tag routing: extracts the first
    /// p-tag from the event, resolves it to a group_id, then decrypts only
    /// with that group. Returns `true` if the event was handled.
    pub async fn handle_mls_event(
        &self,
        event: &libkeychat::Event,
        nostr_event_json: Option<String>,
        relay_url: Option<String>,
    ) -> bool {
        let identity_pubkey = self.cached_identity_pubkey();
        if identity_pubkey.is_empty() {
            return false;
        }

        // O(1) routing: extract p-tag → resolve to group_id
        let p_tags = libkeychat::extract_p_tags(event);
        let first_p = match p_tags.first() {
            Some(p) => p,
            None => return false,
        };

        let group_id = match self.resolve_mls_group(first_p) {
            Some(gid) => gid,
            None => return false,
        };

        // Decrypt with the matched group_id only
        let decrypt_result = {
            let guard = match self.mls_participant_guard() {
                Ok(g) => g,
                Err(_) => return false,
            };
            let participant = match guard.as_ref() {
                Some(p) => p,
                None => return false,
            };
            libkeychat::receive_mls_message(participant, &group_id, event).ok()
            // guard (mls_participant lock) dropped here
        };

        let (msg, metadata) = match decrypt_result {
            Some(r) => r,
            None => return false,
        };

        let event_id = event.id.to_hex();
        let room_id = make_room_id(&group_id, &identity_pubkey);

        // Commit — epoch changed, rotate temp_inbox and refresh members
        if metadata.is_commit {
            tracing::info!(
                "[MLS] commit processed: group={} sender={}",
                &group_id[..16.min(group_id.len())],
                metadata.sender_id
            );

            // Rotate inbox mapping (old temp_inbox → new temp_inbox)
            match self.rotate_mls_inbox(&group_id) {
                Ok((_old_inbox, new_inbox)) => {
                    // Subscribe to the new temp_inbox
                    // (old inbox will be ignored on next resubscribe cycle)
                    let inner = self.inner.read().await;
                    if let Some(t) = inner.protocol.transport() {
                        if let Ok(new_pk) = nostr::PublicKey::from_hex(&new_inbox) {
                            let _ = t.subscribe(vec![new_pk], None).await;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "[MLS] rotate_mls_inbox failed for group {}: {e}",
                        &group_id[..16.min(group_id.len())]
                    );
                }
            }

            // Refresh room members from MLS group state
            let member_update = {
                let guard = match self.mls_participant_guard() {
                    Ok(g) => g,
                    Err(_) => return true,
                };
                let participant = match guard.as_ref() {
                    Some(p) => p,
                    None => return true,
                };
                participant.group_members(&group_id).ok()
            };
            if let Some(members) = member_update {
                let app_storage = self.inner.read().await.app_storage.clone();
                let store = lock_app_storage(&app_storage);
                let existing = store.get_room_members(&room_id).unwrap_or_default();
                let existing_pks: std::collections::HashSet<String> =
                    existing.iter().map(|m| m.pubkey.clone()).collect();
                let current_pks: std::collections::HashSet<String> =
                    members.iter().cloned().collect();

                // Add new members
                for pk in current_pks.difference(&existing_pks) {
                    let _ = store.save_room_member(
                        &room_id,
                        pk,
                        None,
                        false,
                        MemberStatus::Invited.to_i32(),
                    );
                }
                // Mark removed members
                for pk in existing_pks.difference(&current_pks) {
                    let _ = store.update_room_member(
                        &room_id,
                        pk,
                        None,
                        None,
                        Some(MemberStatus::Removed.to_i32()),
                    );
                }
            }

            self.emit_data_change(DataChange::RoomUpdated {
                room_id,
            })
            .await;

            return true;
        }

        // Proposal (empty-text non-commit) — just log
        let content = msg.text.as_ref().map(|t| t.content.clone());
        let content_str = content.as_deref().unwrap_or("");
        if content_str.is_empty() && msg.files.is_none() {
            tracing::info!(
                "[MLS] proposal received: group={} sender={}",
                &group_id[..16.min(group_id.len())],
                metadata.sender_id
            );
            return true;
        }

        // Application message — persist to app storage
        let display = if content_str.is_empty() {
            "[File]"
        } else {
            content_str
        };
        let payload_json = msg.to_json().ok();
        let created_at = event.created_at.as_u64() as i64;
        let reply_to_event_id = msg
            .reply_to
            .as_ref()
            .and_then(|r| r.target_event_id.clone());

        let saved = {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if store.is_app_message_duplicate(&event_id).unwrap_or(false) {
                return true;
            }
            let relay_status = relay_url
                .as_ref()
                .map(|url| format!(r#"[{{"url":"{}","status":"received"}}]"#, url));

            store
                .transaction(|_| {
                    store.save_app_room(
                        &group_id,
                        &identity_pubkey,
                        RoomStatus::Enabled.to_i32(),
                        RoomType::MlsGroup.to_i32(),
                        None,
                        None,
                        None,
                    )?;
                    store.save_app_message(
                        &event_id,
                        Some(&event_id),
                        &room_id,
                        &identity_pubkey,
                        &metadata.sender_id,
                        content_str,
                        false,
                        MessageStatus::Success.to_i32(),
                        created_at,
                    )?;
                    store.update_app_message(
                        &event_id,
                        None,
                        None,
                        relay_status.as_deref(),
                        payload_json.as_deref(),
                        nostr_event_json.as_deref(),
                        reply_to_event_id.as_deref(),
                        None,
                    )?;
                    store.update_app_room(&room_id, None, None, Some(display), Some(created_at))?;
                    store.increment_app_room_unread(&room_id)?;
                    Ok(())
                })
                .is_ok()
        };

        if saved {
            self.emit_data_change(DataChange::MessageAdded {
                room_id: room_id.clone(),
                msgid: event_id.clone(),
            })
            .await;
            self.emit_data_change(DataChange::RoomUpdated {
                room_id: room_id.clone(),
            })
            .await;
        }

        self.emit_event(ClientEvent::MessageReceived {
            room_id,
            sender_pubkey: metadata.sender_id,
            kind: MessageKind::Text,
            content,
            payload: payload_json,
            event_id,
            fallback: None,
            reply_to_event_id,
            group_id: Some(group_id),
            thread_id: msg.thread_id.clone(),
            nostr_event_json,
            relay_url,
        })
        .await;

        true
    }

    // ─── Internal: MLS encrypt + publish + persist ──────────

    async fn send_mls_message_internal(
        &self,
        group_id: String,
        msg: KCMessage,
        display_text: &str,
        reply_to: &Option<ReplyToPayload>,
    ) -> AppResult<MlsSentMessage> {
        let identity_pubkey = self.cached_identity_pubkey();
        let payload_json = msg.to_json().ok();

        // MLS encrypt + wrap as kind:1059 (sync, holding mls_participant lock)
        let event = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            libkeychat::send_mls_message(participant, &group_id, &msg, &mls_temp_inbox)?
        };

        let event_id = event.id.to_hex();

        // Publish (async, no mls lock held)
        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let _ = t.publish_event_async(event).await;
            }
        }

        // App persistence
        let room_id = make_room_id(&group_id, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let msgid = format!(
            "mls-{}-{}-{:08x}",
            &group_id[..16.min(group_id.len())],
            now,
            nanos
        );

        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_message(
                &msgid,
                Some(&event_id),
                &room_id,
                &identity_pubkey,
                &identity_pubkey,
                display_text,
                true,
                MessageStatus::Sending.to_i32(),
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
            let _ = store.update_app_room(&room_id, None, None, Some(display_text), Some(now));
        }

        self.emit_data_change(DataChange::MessageAdded {
            room_id: room_id.clone(),
            msgid: msgid.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated { room_id })
            .await;

        Ok(MlsSentMessage {
            msgid,
            group_id,
            event_id: Some(event_id),
        })
    }

    // ─── Internal: Fetch KeyPackages + add members + invite ─

    /// Complete flow shared by create_mls_group and add_mls_members:
    /// 1. Fetch KeyPackages (kind 10443) from Nostr relays
    /// 2. participant.add_members → (commit, welcome)
    /// 3. Broadcast commit to temp_inbox
    /// 4. Send MlsGroupInvite to each member via Signal session
    /// 5. Subscribe temp_inbox
    async fn mls_fetch_add_and_invite(
        &self,
        group_id: &str,
        group_name: &str,
        identity_pubkey: &str,
        members: &[GroupMemberInput],
    ) -> AppResult<()> {
        // Step 1: Fetch KeyPackages from relays
        // We collect raw nostr Events and parse them together with the MLS
        // participant lock to avoid exposing openmls types in our signature.
        let mut kp_events: Vec<(GroupMemberInput, libkeychat::Event)> = Vec::new();
        {
            let inner = self.inner.read().await;
            let transport = inner
                .protocol
                .transport()
                .ok_or(AppError::Transport("Not connected".into()))?;
            let client = transport.client();

            for m in members {
                let pk = nostr::PublicKey::from_hex(&m.nostr_pubkey).map_err(|e| {
                    AppError::Crypto(format!("invalid member pubkey {}: {e}", &m.nostr_pubkey))
                })?;
                let filter = nostr::Filter::new()
                    .kind(nostr::Kind::from(libkeychat::KIND_MLS_KEY_PACKAGE))
                    .author(pk)
                    .limit(1);
                match client
                    .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
                    .await
                {
                    Ok(events) => {
                        if let Some(event) = events.first() {
                            kp_events.push((m.clone(), event.clone()));
                        } else {
                            tracing::warn!(
                                "no MLS key package for member {} (not upgraded?)",
                                &m.nostr_pubkey[..16.min(m.nostr_pubkey.len())]
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "fetch key package for {} failed: {e}",
                            &m.nostr_pubkey[..16.min(m.nostr_pubkey.len())]
                        );
                    }
                }
            }
        } // read lock dropped

        if kp_events.is_empty() {
            tracing::warn!(
                "mls_fetch_add_and_invite: no valid KeyPackages found for {} members",
                members.len()
            );
            return Ok(());
        }

        // Step 2: Parse KeyPackages + add_members (sync, holding mls_participant lock)
        let mut members_with_kp = Vec::new();
        let (commit_bytes, welcome_bytes, mls_temp_inbox) = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();

            let mut key_packages = Vec::new();
            for (member, event) in &kp_events {
                match libkeychat::parse_key_package(event) {
                    Ok(kp) => {
                        key_packages.push(kp);
                        members_with_kp.push(member.clone());
                    }
                    Err(e) => {
                        tracing::warn!(
                            "parse_key_package for {}: {e}",
                            &member.nostr_pubkey[..16.min(member.nostr_pubkey.len())]
                        );
                    }
                }
            }

            if key_packages.is_empty() {
                return Ok(());
            }

            let (commit_bytes, welcome_bytes) =
                participant.add_members(group_id, key_packages)?;
            let mls_temp_inbox = participant.derive_temp_inbox(group_id)?;
            (commit_bytes, welcome_bytes, mls_temp_inbox)
        }; // mls_participant lock dropped

        // Step 3: Broadcast commit to temp_inbox
        let commit_event =
            libkeychat::broadcast_commit(&commit_bytes, &mls_temp_inbox)?;
        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let _ = t.publish_event_async(commit_event).await;
            }
        }

        // Step 4: Send MlsGroupInvite to each member via Signal session
        let invite_payload = MlsGroupInvitePayload::new(
            group_id.to_string(),
            group_name.to_string(),
            &welcome_bytes,
            vec![identity_pubkey.to_string()],
        );
        let mut invite_msg = KCMessage {
            v: 2,
            id: Some(format!("mls-invite-{}", &group_id[..16.min(group_id.len())])),
            kind: KCMessageKind::MlsGroupInvite,
            group_id: Some(group_id.to_string()),
            ..KCMessage::empty()
        };
        invite_msg
            .extra
            .insert("mlsGroupInvite".to_string(), serde_json::to_value(&invite_payload).unwrap());

        // Collect Signal session arcs under read lock, then drop
        let member_sessions: Vec<(
            String,
            Arc<tokio::sync::Mutex<libkeychat::ChatSession>>,
        )> = {
            let inner = self.inner.read().await;
            let mut sessions = Vec::new();
            for m in &members_with_kp {
                if let Some(sid) = inner.protocol.nostr_to_signal(&m.nostr_pubkey) {
                    if let Some(sarc) = inner.protocol.get_session(sid) {
                        sessions.push((sid.clone(), sarc));
                    } else {
                        tracing::warn!(
                            "no Signal session for member {} — invite not sent",
                            &m.nostr_pubkey[..16.min(m.nostr_pubkey.len())]
                        );
                    }
                } else {
                    tracing::warn!(
                        "no Signal mapping for member {} — invite not sent",
                        &m.nostr_pubkey[..16.min(m.nostr_pubkey.len())]
                    );
                }
            }
            sessions
        }; // read lock dropped

        for (signal_id, session_arc) in &member_sessions {
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            match encrypt_for_group_member(
                &mut session.signal,
                signal_id,
                &invite_msg,
                &addr,
            )
            .await
            {
                Ok(event) => {
                    let inner = self.inner.read().await;
                    if let Some(t) = inner.protocol.transport() {
                        let _ = t.publish_event_async(event).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "send MLS invite to {} failed: {e}",
                        &signal_id[..16.min(signal_id.len())]
                    );
                }
            }
        }

        // Step 5: Subscribe to the MLS temp_inbox so we receive group messages
        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let inbox_pk =
                    nostr::PublicKey::from_hex(&mls_temp_inbox).map_err(|e| {
                        AppError::Crypto(format!("invalid mls temp inbox pubkey: {e}"))
                    })?;
                let _ = t.subscribe(vec![inbox_pk], None).await;
            }
        }

        Ok(())
    }

    // ─── Join MLS Group (invited by another user) ───────────

    /// Join an MLS group from a received invite payload.
    /// Called when we receive a KCMessage with kind MlsGroupInvite.
    pub async fn join_mls_group(
        &self,
        invite_payload: MlsGroupInvitePayload,
    ) -> AppResult<String> {
        let identity_pubkey = self.cached_identity_pubkey();
        if identity_pubkey.is_empty() {
            return Err(AppError::NotInitialized("no identity set".into()));
        }

        let welcome_bytes = invite_payload
            .welcome_bytes()
            .map_err(|e| AppError::Mls(format!("decode welcome: {e}")))?;

        // Join group + read extension data (sync, holding mls_participant lock)
        let (group_id, group_name, admin_pubkeys, member_ids, mls_temp_inbox) = {
            let guard = self.mls_participant_guard()?;
            let participant = guard.as_ref().unwrap();
            let group_id = participant.join_group(&welcome_bytes)?;
            let ext = participant.group_extension(&group_id)?;
            let members = participant.group_members(&group_id)?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            (
                group_id,
                ext.name(),
                ext.admin_pubkeys(),
                members,
                mls_temp_inbox,
            )
        };

        let room_id = make_room_id(&group_id, &identity_pubkey);

        // Persist room and members
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_room(
                &group_id,
                &identity_pubkey,
                RoomStatus::Enabled.to_i32(),
                RoomType::MlsGroup.to_i32(),
                Some(&group_name),
                None,
                None,
            );
            // Save self as member
            let _ = store.save_room_member(
                &room_id,
                &identity_pubkey,
                Some("Me"),
                false,
                MemberStatus::Invited.to_i32(),
            );
            // Save other members from MLS group state
            for member_id in &member_ids {
                if member_id == &identity_pubkey {
                    continue;
                }
                let is_admin = admin_pubkeys.contains(member_id);
                let _ = store.save_room_member(
                    &room_id,
                    member_id,
                    None,
                    is_admin,
                    MemberStatus::Invited.to_i32(),
                );
            }
        }

        // Register temp_inbox → group_id in the routing map
        self.register_mls_inbox(&group_id)?;

        // Subscribe to the MLS temp_inbox
        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                if let Ok(inbox_pk) = nostr::PublicKey::from_hex(&mls_temp_inbox) {
                    let _ = t.subscribe(vec![inbox_pk], None).await;
                }
            }
        }

        self.emit_data_change(DataChange::RoomListChanged).await;

        tracing::info!(
            "[MLS] joined group: id={} name={}",
            &group_id[..16.min(group_id.len())],
            group_name
        );

        Ok(room_id)
    }
}
