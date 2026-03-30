use libkeychat::{KCFilePayload, KCMessage, ProtocolAddress};

use crate::client::{default_device_id, KeychatClient};
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn send_text(
        &self,
        room_id: String,
        text: String,
        _format: Option<String>,
        reply_to: Option<ReplyToPayload>,
        _thread_id: Option<String>,
    ) -> Result<SentMessage, KeychatUniError> {
        // 1. Check relay connection FIRST — before any expensive work
        let connected = {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::Transport {
                    msg: "Not connected to any relay. Please check your network.".into(),
                })?;
            transport.connected_relays().await
        };

        if connected.is_empty() {
            return Err(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            });
        }

        // 2. Get session and peer info
        let (session_mutex, peer_signal_hex, identity_pubkey) = {
            let inner = self.inner.read().await;
            let peer_pubkey = room_id.split(':').next().unwrap_or(&room_id);
            let signal_hex = inner
                .peer_nostr_to_signal
                .get(peer_pubkey)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: peer_pubkey.to_string(),
                })?
                .clone();
            let session = inner
                .sessions
                .get(&signal_hex)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: signal_hex.clone(),
                })?
                .clone();
            let pubkey_hex = inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default();
            (session, signal_hex, pubkey_hex)
        }; // RwLock dropped here

        // 3. Lock only the specific peer session and encrypt
        let remote_addr = ProtocolAddress::new(peer_signal_hex.clone(), default_device_id());
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
        let payload_json = msg.to_json().ok();

        let (event, addr_update) = {
            let mut session = session_mutex.lock().await;
            session
                .send_message(&peer_signal_hex, &remote_addr, &msg)
                .await?
        };

        // 4. Serialize event before publishing (for resend support)
        let nostr_event_json = serde_json::to_string(&event).ok();
        let event_id = event.id.to_hex();

        // 5. Write message to DB (status=0 sending) before publishing
        // room_id is already "peer_hex:identity_hex" from Swift — use as-is
        let full_room_id = room_id.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let my_pubkey = {
            let inner = self.inner.read().await;
            inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default()
        };

        let send_storage = self.inner.read().await.app_storage.clone();
        {
            let store = crate::client::lock_app_storage(&send_storage);
            if let Err(e) = store.save_app_message(
                &event_id, Some(&event_id), &full_room_id, &identity_pubkey,
                &my_pubkey, &text, true, 0, now,
            ) {
                tracing::warn!("save_app_message (send): {e}");
            }
            if let Err(e) = store.update_app_message(
                &event_id, None, None, None,
                payload_json.as_deref(), nostr_event_json.as_deref(),
                reply_to.as_ref().map(|r| r.target_event_id.as_str()),
                reply_to.as_ref().and_then(|r| r.content.as_deref()),
            ) {
                tracing::warn!("update_app_message (send metadata): {e}");
            }
            let display = if text.is_empty() { "[Message]" } else { &text };
            if let Err(e) = store.update_app_room(&full_room_id, None, None, Some(display), Some(now)) {
                tracing::warn!("update_app_room (send): {e}");
            }
        }
        drop(send_storage);

        // Emit DataChange before publishing so Swift can show the message immediately
        self.emit_data_change(DataChange::MessageAdded {
            room_id: full_room_id.clone(),
            msgid: event_id.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: full_room_id.clone(),
        })
        .await;

        // 6. Publish to relays — relay OK responses come via event loop
        {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::Transport {
                    msg: "Not connected to any relay. Please check your network.".into(),
                })?;
            transport.publish_event_async(event).await?;
        }

        tracing::info!(
            "⬆️ SENT eventId={} to {} relays (async OK)",
            &event_id[..16.min(event_id.len())],
            connected.len()
        );

        // 7. Register with relay tracker — initial JSON written to DB immediately
        let initial_relay_json = {
            let mut tracker = self
                .relay_tracker
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            tracker.track(
                event_id.clone(),
                event_id.clone(), // msgid = event_id for sent messages
                full_room_id.clone(),
                connected.clone(),
            )
        };
        // Persist initial relay status (all "pending")
        {
            let store_arc = self.inner.read().await.app_storage.clone();
            let store = crate::client::lock_app_storage(&store_arc);
            let _ = store.update_app_message(
                &event_id, None, None, Some(&initial_relay_json),
                None, None, None, None,
            );
        }
        // Emit MessageUpdated so Swift sees initial relay status
        self.emit_data_change(DataChange::MessageUpdated {
            room_id: full_room_id,
            msgid: event_id.clone(),
        })
        .await;

        Ok(SentMessage {
            event_id,
            payload_json,
            nostr_event_json,
            connected_relays: connected,
            new_receiving_addresses: addr_update.new_receiving,
            dropped_receiving_addresses: addr_update.dropped_receiving,
            new_sending_address: addr_update.new_sending,
        })
    }

    /// Send file(s) to a DM peer.
    ///
    /// Swift is responsible for:
    /// 1. Encrypting files via `encrypt_file_data()`
    /// 2. Uploading ciphertext to file server (Blossom / Ecash-Presigned)
    /// 3. Passing the resulting FilePayload list here with URLs + encryption metadata
    pub async fn send_file(
        &self,
        room_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<SentMessage, KeychatUniError> {
        if files.is_empty() {
            return Err(KeychatUniError::InvalidArgument {
                msg: "files list cannot be empty".into(),
            });
        }

        // 1. Check relay connection
        let connected = {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::Transport {
                    msg: "Not connected to any relay. Please check your network.".into(),
                })?;
            transport.connected_relays().await
        };
        if connected.is_empty() {
            return Err(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            });
        }

        // 2. Get session and peer info
        let (session_mutex, peer_signal_hex, identity_pubkey) = {
            let inner = self.inner.read().await;
            let peer_pubkey = room_id.split(':').next().unwrap_or(&room_id);
            let signal_hex = inner
                .peer_nostr_to_signal
                .get(peer_pubkey)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: peer_pubkey.to_string(),
                })?
                .clone();
            let session = inner
                .sessions
                .get(&signal_hex)
                .ok_or(KeychatUniError::PeerNotFound {
                    peer_id: signal_hex.clone(),
                })?
                .clone();
            let pubkey_hex = inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default();
            (session, signal_hex, pubkey_hex)
        };

        // 3. Build KCMessage with Files kind
        let kc_files: Vec<KCFilePayload> = files
            .iter()
            .map(|f| KCFilePayload {
                category: crate::media::file_category_to_lib(&f.category),
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
        // Attach optional text message
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
        let payload_json = msg.to_json().ok();

        // 4. Encrypt and send via Signal session
        let remote_addr = ProtocolAddress::new(peer_signal_hex.clone(), default_device_id());
        let (event, addr_update) = {
            let mut session = session_mutex.lock().await;
            session
                .send_message(&peer_signal_hex, &remote_addr, &msg)
                .await?
        };

        let nostr_event_json = serde_json::to_string(&event).ok();
        let event_id = event.id.to_hex();

        // 5. Write to DB
        let full_room_id = room_id.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let my_pubkey = {
            let inner = self.inner.read().await;
            inner
                .identity
                .as_ref()
                .map(|id| id.pubkey_hex())
                .unwrap_or_default()
        };

        let display_text = if let Some(ref m) = message {
            if m.is_empty() { "[File]" } else { m }
        } else {
            "[File]"
        };

        let send_storage = self.inner.read().await.app_storage.clone();
        {
            let store = crate::client::lock_app_storage(&send_storage);
            if let Err(e) = store.save_app_message(
                &event_id, Some(&event_id), &full_room_id, &identity_pubkey,
                &my_pubkey, display_text, true, 0, now,
            ) {
                tracing::warn!("save_app_message (send_file): {e}");
            }
            if let Err(e) = store.update_app_message(
                &event_id, None, None, None,
                payload_json.as_deref(), nostr_event_json.as_deref(),
                reply_to.as_ref().map(|r| r.target_event_id.as_str()),
                reply_to.as_ref().and_then(|r| r.content.as_deref()),
            ) {
                tracing::warn!("update_app_message (send_file metadata): {e}");
            }
            if let Err(e) = store.update_app_room(
                &full_room_id, None, None, Some(display_text), Some(now),
            ) {
                tracing::warn!("update_app_room (send_file): {e}");
            }
        }
        drop(send_storage);

        // 6. Emit DataChange
        self.emit_data_change(DataChange::MessageAdded {
            room_id: full_room_id.clone(),
            msgid: event_id.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: full_room_id.clone(),
        })
        .await;

        // 7. Publish to relays
        {
            let inner = self.inner.read().await;
            let transport = inner
                .transport
                .as_ref()
                .ok_or(KeychatUniError::Transport {
                    msg: "Not connected to any relay. Please check your network.".into(),
                })?;
            transport.publish_event_async(event).await?;
        }

        tracing::info!(
            "⬆️ SENT FILE eventId={} ({} files) to {} relays",
            &event_id[..16.min(event_id.len())],
            files.len(),
            connected.len()
        );

        // 8. Relay tracker
        let initial_relay_json = {
            let mut tracker = self
                .relay_tracker
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            tracker.track(
                event_id.clone(),
                event_id.clone(),
                full_room_id.clone(),
                connected.clone(),
            )
        };
        {
            let store_arc = self.inner.read().await.app_storage.clone();
            let store = crate::client::lock_app_storage(&store_arc);
            let _ = store.update_app_message(
                &event_id, None, None, Some(&initial_relay_json),
                None, None, None, None,
            );
        }
        self.emit_data_change(DataChange::MessageUpdated {
            room_id: full_room_id,
            msgid: event_id.clone(),
        })
        .await;

        Ok(SentMessage {
            event_id,
            payload_json,
            nostr_event_json,
            connected_relays: connected,
            new_receiving_addresses: addr_update.new_receiving,
            dropped_receiving_addresses: addr_update.dropped_receiving,
            new_sending_address: addr_update.new_sending,
        })
    }

    /// Retry all failed outgoing messages by rebroadcasting to relays.
    /// Called after reconnect to recover messages that failed due to network issues.
    pub async fn retry_failed_messages(&self) -> Result<u32, KeychatUniError> {
        // 1. Query failed messages from DB
        let failed_messages = {
            let storage = self.inner.read().await.app_storage.clone();
            let store = crate::client::lock_app_storage_result(&storage)?;
            store
                .get_app_failed_messages()
                .map_err(|e| KeychatUniError::Storage {
                    msg: format!("get_app_failed_messages: {e}"),
                })?
        };

        if failed_messages.is_empty() {
            return Ok(0);
        }

        tracing::info!(
            "retry_failed_messages: {} messages to retry",
            failed_messages.len()
        );

        let mut retried = 0u32;
        for msg in &failed_messages {
            let event_json = match &msg.nostr_event_json {
                Some(json) => json.clone(),
                None => {
                    tracing::warn!(
                        "retry: message {} has no nostr_event_json, skipping",
                        &msg.msgid[..16.min(msg.msgid.len())]
                    );
                    continue;
                }
            };

            // Mark as sending (status=0)
            let retry_s1 = self.inner.read().await.app_storage.clone();
            {
                let store = crate::client::lock_app_storage(&retry_s1);
                if let Err(e) = store.update_app_message(
                    &msg.msgid, None, Some(0), None, None, None, None, None,
                ) {
                    tracing::warn!("retry update_app_message (sending): {e}");
                }
            }
            drop(retry_s1);

            // Rebroadcast
            match self.rebroadcast_event(event_json).await {
                Ok(result) => {
                    let success = !result.success_relays.is_empty();
                    let status = if success { 1 } else { 2 };

                    // Build relay status JSON
                    let mut relays = Vec::new();
                    for url in &result.success_relays {
                        relays.push(serde_json::json!({"url": url, "status": "ok"}));
                    }
                    for f in &result.failed_relays {
                        relays.push(
                            serde_json::json!({"url": f.url, "status": "failed", "error": f.error}),
                        );
                    }
                    let relay_json = serde_json::to_string(&relays).unwrap_or_default();

                    let retry_s2 = self.inner.read().await.app_storage.clone();
                    {
                        let store = crate::client::lock_app_storage(&retry_s2);
                        if let Err(e) = store.update_app_message(
                            &msg.msgid, None, Some(status), Some(&relay_json),
                            None, None, None, None,
                        ) {
                            tracing::warn!("retry update_app_message (result): {e}");
                        }
                    }
                    drop(retry_s2);

                    self.emit_data_change(DataChange::MessageUpdated {
                        room_id: msg.room_id.clone(),
                        msgid: msg.msgid.clone(),
                    })
                    .await;

                    if success {
                        retried += 1;
                    }
                    tracing::info!(
                        "retry: {} → {}",
                        &msg.msgid[..16.min(msg.msgid.len())],
                        if success { "success" } else { "failed" }
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "retry: {} rebroadcast failed: {e}",
                        &msg.msgid[..16.min(msg.msgid.len())]
                    );
                    // Mark as failed again
                    let retry_s3 = self.inner.read().await.app_storage.clone();
                    {
                        let store = crate::client::lock_app_storage(&retry_s3);
                        if let Err(e) = store.update_app_message(
                            &msg.msgid, None, Some(2), None, None, None, None, None,
                        ) {
                            tracing::warn!("retry update_app_message (mark failed): {e}");
                        }
                    }
                    drop(retry_s3);
                }
            }
        }

        tracing::info!("retry_failed_messages: {retried}/{} retried", failed_messages.len());
        Ok(retried)
    }
}
