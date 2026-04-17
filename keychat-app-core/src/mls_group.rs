//! MLS Group — app-core business logic for MLS (RFC 9420) large groups.
//!
//! Follows the same read-lock → collect → drop → operate pattern as group.rs
//! (Signal groups). MLS differs from Signal in that messages are broadcast to
//! a single shared `mlsTempInbox` address rather than fan-out to each member.
//!
//! `MlsParticipant` lives in `AppClient::mls_participant` (a `std::sync::Mutex`)
//! rather than inside `AppClientInner`, because the OpenMLS provider contains
//! non-Send `RefCell` types that would break `tokio::spawn` requirements.

use libkeychat::{
    broadcast_commit, send_mls_message, KCMessage, KCMessageKind, MlsGroupInvitePayload,
    MlsParticipant,
};

use crate::app_client::{lock_app_storage, AppClient, AppError, AppResult};
use crate::types::*;

impl AppClient {
    /// Lock the MLS participant mutex, returning an error if not initialized.
    fn lock_mls(&self) -> AppResult<std::sync::MutexGuard<'_, Option<MlsParticipant>>> {
        let guard = self
            .mls_participant
            .lock()
            .map_err(|e| AppError::Mls(format!("mls_participant lock: {e}")))?;
        if guard.is_none() {
            return Err(AppError::NotInitialized("MLS not initialized".into()));
        }
        Ok(guard)
    }

    // ─── Group Lifecycle ─────────────────────────────────────────

    /// Create a new MLS group and invite members.
    ///
    /// `member_key_packages_bytes` is a list of `(nostr_pubkey, serialized_key_package)`.
    /// The caller is responsible for fetching KeyPackages (kind:10443 events) beforehand.
    /// The Welcome message is sent to each member through their existing
    /// Signal 1:1 session as an `MlsGroupInvite` KCMessage.
    pub async fn create_mls_group(
        &self,
        name: String,
        member_key_packages_bytes: Vec<(String, Vec<u8>)>,
    ) -> AppResult<MlsGroupInfo> {
        if member_key_packages_bytes.is_empty() {
            return Err(AppError::InvalidArgument("no members provided".into()));
        }

        // Generate a unique group ID: timestamp + identity hash to avoid collision
        let group_id = {
            let identity_pubkey = self.cached_identity_pubkey();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            // Mix identity into the hash to prevent collision across devices
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            identity_pubkey.hash(&mut h);
            now.hash(&mut h);
            format!("mls-{:016x}", h.finish())
        };

        // Phase 1: Read-lock — collect identity + member sessions
        let (my_nostr, member_sessions) = {
            let inner = self.inner.read().await;
            let identity = inner
                .protocol
                .identity()
                .ok_or(AppError::NotInitialized("no identity set".into()))?;
            let my_nostr = identity.pubkey_hex();

            let mut sessions = Vec::new();
            for (pubkey, _) in &member_key_packages_bytes {
                if let Some(sid) = inner.protocol.nostr_to_signal(pubkey) {
                    if let Some(s) = inner.protocol.get_session(sid) {
                        sessions.push((sid.clone(), pubkey.clone(), s));
                    }
                }
            }
            (my_nostr, sessions)
        }; // read lock dropped

        // Phase 2: Parse KeyPackages
        let key_packages: Vec<_> = member_key_packages_bytes
            .iter()
            .filter_map(
                |(pubkey, kp_bytes)| match libkeychat::parse_key_package_bytes(kp_bytes) {
                    Ok(kp) => Some(kp),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse KeyPackage for {}: {e}",
                            &pubkey[..16.min(pubkey.len())]
                        );
                        None
                    }
                },
            )
            .collect();
        if key_packages.is_empty() {
            return Err(AppError::Mls("no valid KeyPackages".into()));
        }

        // Phase 3: Create group + add members (MLS mutex, no inner lock)
        let (welcome_bytes, mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();

            participant.create_group(&group_id, &name)?;
            let (_commit_bytes, welcome_bytes) =
                participant.add_members(&group_id, key_packages)?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            (welcome_bytes, mls_temp_inbox)
        }; // MLS mutex dropped

        // Save group ID for re-subscription on restart
        {
            let inner = self.inner.read().await;
            if let Ok(store) = inner.protocol.storage().clone().lock() {
                if let Err(e) = store.save_mls_group_id(&group_id) {
                    tracing::error!("save_mls_group_id failed: {e}");
                }
            }
        }

        // Phase 4: Send invite to each member via their 1:1 Signal session
        let invite_payload = MlsGroupInvitePayload::new(
            group_id.clone(),
            name.clone(),
            &welcome_bytes,
            vec![my_nostr.clone()],
        );
        let invite_json = serde_json::to_string(&invite_payload)
            .map_err(|e| AppError::Mls(format!("serialize invite: {e}")))?;

        let invite_msg = KCMessage {
            v: 2,
            kind: KCMessageKind::MlsGroupInvite,
            text: Some(libkeychat::KCTextPayload {
                content: invite_json,
                format: None,
            }),
            group_id: Some(group_id.clone()),
            ..KCMessage::empty()
        };

        for (_signal_id, nostr_pubkey, _) in &member_sessions {
            let mut inner = self.inner.write().await;
            match inner
                .protocol
                .send_message_core(nostr_pubkey, &invite_msg)
                .await
            {
                Ok(_) => {}
                Err(e) => tracing::error!(
                    "MLS invite send to {} failed: {e}",
                    &nostr_pubkey[..16.min(nostr_pubkey.len())]
                ),
            }
        }

        let member_count = (member_key_packages_bytes.len() + 1) as u32;

        // Phase 5: App persistence
        let identity_pubkey = self.cached_identity_pubkey();
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if let Err(e) = store.save_app_room(
                &group_id,
                &identity_pubkey,
                1, // Enabled
                2, // MlsGroup
                Some(&name),
                None,
                None,
            ) {
                tracing::error!("save_app_room failed: {e}");
            }
        }
        self.emit_data_change(DataChange::RoomListChanged).await;

        // Subscribe to the new group's mlsTempInbox
        self.refresh_mls_subscriptions().await;

        Ok(MlsGroupInfo {
            group_id,
            name,
            member_count,
            mls_temp_inbox,
        })
    }

    /// Join an MLS group via a received Welcome message.
    pub async fn join_mls_group(
        &self,
        welcome_bytes: Vec<u8>,
        name: String,
        _admin_pubkeys: Vec<String>,
    ) -> AppResult<MlsGroupInfo> {
        let (group_id, mls_temp_inbox, member_count) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();

            let group_id = participant.join_group(&welcome_bytes)?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            let member_count = participant.group_members(&group_id)?.len() as u32;
            (group_id, mls_temp_inbox, member_count)
        };

        // Save group ID for re-subscription on restart
        {
            let inner = self.inner.read().await;
            if let Ok(store) = inner.protocol.storage().clone().lock() {
                if let Err(e) = store.save_mls_group_id(&group_id) {
                    tracing::error!("save_mls_group_id failed: {e}");
                }
            }
        }

        // App persistence
        let identity_pubkey = self.cached_identity_pubkey();
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if let Err(e) = store.save_app_room(
                &group_id,
                &identity_pubkey,
                1, // Enabled
                2, // MlsGroup
                Some(&name),
                None,
                None,
            ) {
                tracing::error!("save_app_room failed: {e}");
            }
        }
        self.emit_data_change(DataChange::RoomListChanged).await;

        // Subscribe to the new group's mlsTempInbox
        self.refresh_mls_subscriptions().await;

        Ok(MlsGroupInfo {
            group_id,
            name,
            member_count,
            mls_temp_inbox,
        })
    }

    // ─── Messaging ───────────────────────────────────────────────

    /// Send a text message to an MLS group.
    pub async fn send_mls_text(
        &self,
        group_id: String,
        text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<MlsGroupSentMessage> {
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

    /// Send a file message to an MLS group.
    pub async fn send_mls_file(
        &self,
        group_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<MlsGroupSentMessage> {
        if files.is_empty() {
            return Err(AppError::InvalidArgument("files empty".into()));
        }
        let kc_files: Vec<libkeychat::KCFilePayload> = files
            .iter()
            .map(|f| libkeychat::KCFilePayload {
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
        let mut msg = libkeychat::build_multi_file_message(kc_files);
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

    /// Internal: encrypt + broadcast MLS message to mlsTempInbox.
    async fn send_mls_message_internal(
        &self,
        group_id: String,
        msg: KCMessage,
        display_text: &str,
        reply_to: &Option<ReplyToPayload>,
    ) -> AppResult<MlsGroupSentMessage> {
        let identity_pubkey = self.cached_identity_pubkey();
        let payload_json = msg.to_json().ok();

        // MLS encrypt (MLS mutex, no inner lock)
        let (event, mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            let event = send_mls_message(participant, &group_id, &msg, &mls_temp_inbox)?;
            (event, mls_temp_inbox)
        }; // MLS mutex dropped

        // Publish (read lock)
        let event_id = event.id.to_hex();
        {
            let inner = self.inner.read().await;
            let transport = inner
                .protocol
                .transport()
                .ok_or(AppError::Transport("Not connected".into()))?;
            let _ = transport.publish_event_async(event).await;
        }

        // App persistence
        let full_room_id = make_room_id(&group_id, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Use event_id suffix for uniqueness (guaranteed unique per Nostr event)
        let msgid = format!(
            "mlssend-{}-{}",
            &group_id[..16.min(group_id.len())],
            &event_id[..16.min(event_id.len())]
        );

        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if let Err(e) = store.save_app_message(
                &msgid,
                Some(&event_id),
                &full_room_id,
                &identity_pubkey,
                &identity_pubkey,
                display_text,
                true,
                0,
                now,
            ) {
                tracing::error!("save_app_message failed: {e}");
            }
            if let Err(e) = store.update_app_message(
                &msgid,
                None,
                None,
                None,
                payload_json.as_deref(),
                None,
                reply_to.as_ref().map(|r| r.target_event_id.as_str()),
                reply_to.as_ref().and_then(|r| r.content.as_deref()),
            ) {
                tracing::error!("update_app_message failed: {e}");
            }
            if let Err(e) =
                store.update_app_room(&full_room_id, None, None, Some(display_text), Some(now))
            {
                tracing::error!("update_app_room failed: {e}");
            }
        }

        self.emit_data_change(DataChange::MessageAdded {
            room_id: full_room_id.clone(),
            msgid: msgid.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: full_room_id,
        })
        .await;

        Ok(MlsGroupSentMessage {
            msgid,
            group_id,
            event_id,
            payload_json,
            relay_status_json: None,
        })
    }

    // ─── Group Management ────────────────────────────────────────

    /// Get the list of members in an MLS group.
    pub async fn get_mls_group_members(
        &self,
        group_id: String,
    ) -> AppResult<Vec<MlsGroupMemberInfo>> {
        let my_nostr = {
            let inner = self.inner.read().await;
            inner
                .protocol
                .identity()
                .map(|i| i.pubkey_hex())
                .unwrap_or_default()
        };

        // MLS operations in sync block — guard dropped before any .await
        let (members, admin_pubkeys) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let members = participant.group_members(&group_id)?;
            let ext = participant.group_extension(&group_id)?;
            let admin_pubkeys = ext.admin_pubkeys();
            (members, admin_pubkeys)
        };

        Ok(members
            .iter()
            .map(|m| MlsGroupMemberInfo {
                nostr_pubkey: m.clone(),
                is_admin: admin_pubkeys.contains(m),
                is_me: *m == my_nostr,
            })
            .collect())
    }

    /// Remove a member from an MLS group. Admin only.
    ///
    /// Two-phase commit: broadcast Commit to the **current** mlsTempInbox
    /// (so members on the old epoch can receive it), then merge locally
    /// and re-subscribe to the new-epoch mlsTempInbox.
    pub async fn remove_mls_member(
        &self,
        group_id: String,
        member_nostr_pubkey: String,
    ) -> AppResult<()> {
        // Phase 1: create Commit + derive CURRENT inbox (before merge)
        let (commit_bytes, old_mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let leaf_index = participant.find_member_index(&group_id, &member_nostr_pubkey)?;
            let old_inbox = participant.derive_temp_inbox(&group_id)?;
            let commit_bytes = participant.remove_members(&group_id, &[leaf_index])?;
            (commit_bytes, old_inbox)
        };

        // Phase 2: broadcast to OLD inbox (members are still on old epoch)
        let event = broadcast_commit(&commit_bytes, &old_mls_temp_inbox)?;
        let inner = self.inner.read().await;
        if let Some(t) = inner.protocol.transport() {
            let _ = t.publish_event_async(event).await;
        }
        drop(inner);

        // Phase 3: merge locally → advance to new epoch
        {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            participant.self_commit(&group_id)?;
        }

        // Phase 4: re-subscribe to new-epoch mlsTempInbox (spec §11.3)
        self.refresh_mls_subscriptions().await;

        Ok(())
    }

    /// MLS self-update (key rotation). Broadcasts a Commit to the current
    /// mlsTempInbox, then merges locally and re-subscribes.
    pub async fn mls_self_update(&self, group_id: String) -> AppResult<()> {
        // Phase 1: create Commit + derive CURRENT inbox (before merge)
        let (commit_bytes, old_mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let old_inbox = participant.derive_temp_inbox(&group_id)?;
            let commit_bytes = participant.self_update(&group_id)?;
            (commit_bytes, old_inbox)
        };

        // Phase 2: broadcast to OLD inbox
        let event = broadcast_commit(&commit_bytes, &old_mls_temp_inbox)?;
        let inner = self.inner.read().await;
        if let Some(t) = inner.protocol.transport() {
            let _ = t.publish_event_async(event).await;
        }
        drop(inner);

        // Phase 3: merge locally
        {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            participant.self_commit(&group_id)?;
        }

        // Phase 4: re-subscribe
        self.refresh_mls_subscriptions().await;

        Ok(())
    }

    /// Leave an MLS group.
    pub async fn leave_mls_group(&self, group_id: String) -> AppResult<()> {
        let (proposal_bytes, mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            let proposal_bytes = participant.leave_group(&group_id)?;
            (proposal_bytes, mls_temp_inbox)
        };

        let event = broadcast_commit(&proposal_bytes, &mls_temp_inbox)?;
        let inner = self.inner.read().await;
        if let Some(t) = inner.protocol.transport() {
            let _ = t.publish_event_async(event).await;
        }

        // Clean up storage
        if let Ok(store) = inner.protocol.storage().clone().lock() {
            if let Err(e) = store.delete_mls_group_id(&group_id) {
                tracing::error!("delete_mls_group_id failed: {e}");
            }
        }

        Ok(())
    }

    /// Dissolve an MLS group. Admin only.
    pub async fn dissolve_mls_group(&self, group_id: String) -> AppResult<()> {
        let (commit_bytes, mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let commit_bytes = participant.update_group_context_extensions(
                &group_id,
                None,
                Some("dissolved"),
                None,
            )?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            (commit_bytes, mls_temp_inbox)
        };

        let event = broadcast_commit(&commit_bytes, &mls_temp_inbox)?;
        let inner = self.inner.read().await;
        if let Some(t) = inner.protocol.transport() {
            let _ = t.publish_event_async(event).await;
        }

        Ok(())
    }

    /// Rename an MLS group. Admin only.
    pub async fn rename_mls_group(&self, group_id: String, new_name: String) -> AppResult<()> {
        let (commit_bytes, mls_temp_inbox) = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            let commit_bytes = participant.update_group_context_extensions(
                &group_id,
                Some(&new_name),
                None,
                None,
            )?;
            let mls_temp_inbox = participant.derive_temp_inbox(&group_id)?;
            (commit_bytes, mls_temp_inbox)
        };

        let event = broadcast_commit(&commit_bytes, &mls_temp_inbox)?;
        {
            let inner = self.inner.read().await;
            if let Some(t) = inner.protocol.transport() {
                let _ = t.publish_event_async(event).await;
            }
        }

        // Update app room name
        let identity_pubkey = self.cached_identity_pubkey();
        let full_room_id = make_room_id(&group_id, &identity_pubkey);
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if let Err(e) = store.update_app_room(&full_room_id, None, Some(&new_name), None, None)
            {
                tracing::error!("update_app_room failed: {e}");
            }
        }
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: full_room_id,
        })
        .await;

        Ok(())
    }

    /// Get the current MLS temp inbox address for a group.
    pub async fn get_mls_temp_inbox(&self, group_id: &str) -> AppResult<String> {
        let result = {
            let guard = self.lock_mls()?;
            let participant = guard.as_ref().unwrap();
            participant.derive_temp_inbox(group_id)
        };
        result.map_err(|e| AppError::Mls(e.to_string()))
    }

    /// Generate a KeyPackage for this identity (serialized as TLS bytes).
    /// Other users need this to invite us to an MLS group.
    pub async fn generate_mls_key_package(&self) -> AppResult<Vec<u8>> {
        let guard = self.lock_mls()?;
        let participant = guard.as_ref().unwrap();
        participant
            .generate_key_package_bytes()
            .map_err(|e| AppError::Mls(e.to_string()))
    }

    /// List all tracked MLS group IDs (for re-subscription on restart).
    pub async fn list_mls_group_ids(&self) -> AppResult<Vec<String>> {
        let inner = self.inner.read().await;
        if let Ok(store) = inner.protocol.storage().clone().lock() {
            store
                .list_mls_group_ids()
                .map_err(|e| AppError::Storage(e.to_string()))
        } else {
            Ok(vec![])
        }
    }

    /// Collect MLS temp inbox pubkeys for all joined groups (for relay subscription).
    /// Returns (pubkeys, group_id→temp_inbox map for routing incoming events).
    pub(crate) fn collect_mls_temp_inbox_pubkeys(
        &self,
    ) -> (
        Vec<nostr::PublicKey>,
        std::collections::HashMap<String, String>,
    ) {
        let mut pubkeys = Vec::new();
        let mut inbox_to_group = std::collections::HashMap::new();

        let guard = match self.mls_participant.lock() {
            Ok(g) => g,
            Err(_) => return (pubkeys, inbox_to_group),
        };
        let participant = match guard.as_ref() {
            Some(p) => p,
            None => return (pubkeys, inbox_to_group),
        };

        // Get group IDs from SecureStorage
        let group_ids = {
            // We need inner for storage, but we can't hold async lock here (sync fn).
            // Use try_read to avoid blocking.
            // If inner is locked, return empty — subscriptions will be refreshed later.
            let inner_guard = match self.inner.try_read() {
                Ok(g) => g,
                Err(_) => return (pubkeys, inbox_to_group),
            };
            if let Ok(store) = inner_guard.protocol.storage().clone().lock() {
                store.list_mls_group_ids().unwrap_or_default()
            } else {
                vec![]
            }
        };

        for group_id in &group_ids {
            if let Ok(inbox) = participant.derive_temp_inbox(group_id) {
                if let Ok(pk) = nostr::PublicKey::from_hex(&inbox) {
                    pubkeys.push(pk);
                    inbox_to_group.insert(inbox, group_id.clone());
                }
            }
        }

        (pubkeys, inbox_to_group)
    }

    /// Try to decrypt an incoming event as an MLS group message.
    /// Returns (group_id, KCMessage, MlsMessageMetadata) if successful.
    pub(crate) fn try_decrypt_mls_event(
        &self,
        event: &nostr::Event,
        inbox_to_group: &std::collections::HashMap<String, String>,
    ) -> Option<(
        String,
        libkeychat::KCMessage,
        libkeychat::MlsMessageMetadata,
    )> {
        // Check if any #p tag matches a known MLS temp inbox
        let p_tags: Vec<String> = event
            .tags
            .iter()
            .filter_map(|t| {
                if t.as_slice().first().map(|s| s.as_str()) == Some("p") {
                    t.as_slice().get(1).map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();

        for p_tag in &p_tags {
            if let Some(group_id) = inbox_to_group.get(p_tag) {
                let guard = self.mls_participant.lock().ok()?;
                let participant = guard.as_ref()?;
                match libkeychat::receive_mls_message(participant, group_id, event) {
                    Ok((msg, metadata)) => return Some((group_id.clone(), msg, metadata)),
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("own messages") {
                            // Normal: sender receives their own broadcast — skip silently
                            tracing::debug!(
                                "[mls] skipped own message for group {}",
                                &group_id[..16.min(group_id.len())]
                            );
                        } else {
                            tracing::warn!(
                                "[mls] decrypt failed for group {}: {e}",
                                &group_id[..16.min(group_id.len())]
                            );
                        }
                    }
                }
            }
        }
        None
    }
}
