//! Message sending (DM, file, NIP-17, retry).

use libkeychat::{KCFilePayload, KCMessage};

use crate::app_client::{lock_app_storage, AppClient, AppError, AppResult};
use crate::types::*;

impl AppClient {
    pub async fn send_text(
        &self,
        room_id: String,
        text: String,
        _format: Option<String>,
        reply_to: Option<ReplyToPayload>,
        _thread_id: Option<String>,
    ) -> AppResult<SentMessage> {
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
        let display_text = if text.is_empty() {
            "[Message]".to_string()
        } else {
            text
        };
        self.send_message_internal(room_id, msg, display_text, reply_to)
            .await
    }

    pub async fn send_file(
        &self,
        room_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<SentMessage> {
        if files.is_empty() {
            return Err(AppError::InvalidArgument(
                "files list cannot be empty".into(),
            ));
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

        let mut msg = libkeychat::build_multi_file_message(kc_files);
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
        let display_text = if let Some(ref m) = message {
            if m.is_empty() {
                "[File]".to_string()
            } else {
                m.clone()
            }
        } else {
            "[File]".to_string()
        };
        self.send_message_internal(room_id, msg, display_text, reply_to)
            .await
    }

    /// Shared send implementation: protocol send via ProtocolClient + app persistence.
    async fn send_message_internal(
        &self,
        room_id: String,
        msg: KCMessage,
        display_text: String,
        reply_to: Option<ReplyToPayload>,
    ) -> AppResult<SentMessage> {
        let peer_pubkey = room_id.split(':').next().unwrap_or(&room_id).to_string();
        let identity_pubkey = self.cached_identity_pubkey();
        let payload_json = msg.to_json().ok();

        // 1. Protocol: encrypt + publish + address update
        let result = {
            let mut inner = self.inner.write().await;
            let r = inner.protocol.send_message_core(&peer_pubkey, &msg).await?;
            // §9.2: "After encrypt: new_receiving_addr is YOUR new address. Subscribe to it."
            if !r.addr_update.new_receiving.is_empty() {
                if let Err(e) = inner.protocol.refresh_subscriptions().await {
                    tracing::warn!("refresh_subscriptions after send: {e}");
                }
            }
            r
        };

        // 2. App: persist message to DB
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            if let Err(e) = store.save_app_message(
                &result.event_id,
                Some(&result.event_id),
                &room_id,
                &identity_pubkey,
                &identity_pubkey,
                &display_text,
                true,
                MessageStatus::Sending.to_i32(),
                now,
            ) {
                tracing::error!("PERSIST FAILED: save_app_message (send): {e}");
            }
            if let Err(e) = store.update_app_message(
                &result.event_id,
                None,
                None,
                None,
                result.payload_json.as_deref(),
                result.nostr_event_json.as_deref(),
                reply_to.as_ref().map(|r| r.target_event_id.as_str()),
                reply_to.as_ref().and_then(|r| r.content.as_deref()),
            ) {
                tracing::error!("PERSIST FAILED: update_app_message metadata: {e}");
            }
            if let Err(e) =
                store.update_app_room(&room_id, None, None, Some(&display_text), Some(now))
            {
                tracing::error!("PERSIST FAILED: update_app_room: {e}");
            }
        }

        // 3. App: emit DataChange
        self.emit_data_change(DataChange::MessageAdded {
            room_id: room_id.clone(),
            msgid: result.event_id.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated {
            room_id: room_id.clone(),
        })
        .await;

        // 4. App: relay tracker
        let initial_relay_json = {
            let mut tracker = self.relay_tracker.lock().unwrap_or_else(|e| e.into_inner());
            tracker.track(
                result.event_id.clone(),
                result.event_id.clone(),
                room_id.clone(),
                result.connected_relays.clone(),
            )
        };
        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.update_app_message(
                &result.event_id,
                None,
                None,
                Some(&initial_relay_json),
                None,
                None,
                None,
                None,
            );
        }
        self.emit_data_change(DataChange::MessageUpdated {
            room_id,
            msgid: result.event_id.clone(),
        })
        .await;

        Ok(SentMessage {
            event_id: result.event_id,
            payload_json: result.payload_json,
            nostr_event_json: result.nostr_event_json,
            connected_relays: result.connected_relays,
            new_receiving_addresses: result.addr_update.new_receiving,
            dropped_receiving_addresses: result.addr_update.dropped_receiving,
            new_sending_address: result.addr_update.new_sending,
        })
    }

    /// Send a standard NIP-17 DM (no Signal encryption, NIP-44 only).
    pub async fn send_nip17_dm(&self, peer_pubkey: String, text: String) -> AppResult<SentMessage> {
        let connected = {
            let inner = self.inner.read().await;
            let transport = inner
                .protocol
                .transport()
                .ok_or(AppError::Transport("Not connected to any relay.".into()))?;
            transport.connected_relays().await
        };
        if connected.is_empty() {
            return Err(AppError::Transport("Not connected to any relay.".into()));
        }

        let identity = {
            let inner = self.inner.read().await;
            inner
                .protocol
                .identity()
                .cloned()
                .ok_or(AppError::NotInitialized("no identity set".into()))?
        };
        let identity_pubkey = identity.pubkey_hex();

        let receiver_pk = libkeychat::PublicKey::from_hex(&peer_pubkey)
            .map_err(|e| AppError::Transport(format!("invalid pubkey: {e}")))?;
        let gift_wrap =
            libkeychat::giftwrap::create_gift_wrap(identity.keys(), &receiver_pk, &text)
                .await
                .map_err(|e| AppError::Transport(format!("create gift wrap: {e}")))?;

        let event_id = gift_wrap.id.to_hex();
        let nostr_event_json = serde_json::to_string(&gift_wrap).ok();
        let room_id = make_room_id(&peer_pubkey, &identity_pubkey);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = lock_app_storage(&app_storage);
            let _ = store.save_app_message(
                &event_id,
                Some(&event_id),
                &room_id,
                &identity_pubkey,
                &identity_pubkey,
                &text,
                true,
                0,
                now,
            );
            let display = if text.len() > 50 { &text[..50] } else { &text };
            let _ = store.update_app_room(&room_id, None, None, Some(display), Some(now));
        }

        self.emit_data_change(DataChange::MessageAdded {
            room_id: room_id.clone(),
            msgid: event_id.clone(),
        })
        .await;
        self.emit_data_change(DataChange::RoomUpdated { room_id })
            .await;

        {
            let inner = self.inner.read().await;
            let transport = inner
                .protocol
                .transport()
                .ok_or(AppError::Transport("Not connected to any relay.".into()))?;
            transport.publish_event_async(gift_wrap).await?;
        }

        Ok(SentMessage {
            event_id,
            payload_json: None,
            nostr_event_json,
            connected_relays: connected.iter().map(|u| u.to_string()).collect(),
            new_receiving_addresses: vec![],
            dropped_receiving_addresses: vec![],
            new_sending_address: None,
        })
    }

    pub async fn retry_failed_messages(&self) -> AppResult<u32> {
        let failed = {
            let app_storage = self.inner.read().await.app_storage.clone();
            let store = crate::app_client::lock_app_storage_result(&app_storage)?;
            store
                .get_app_failed_messages()
                .map_err(|e| AppError::Storage(format!("{e}")))?
        };
        if failed.is_empty() {
            return Ok(0);
        }

        let mut retried = 0u32;
        for msg in &failed {
            let Some(ref event_json) = msg.nostr_event_json else {
                continue;
            };

            {
                let app_storage = self.inner.read().await.app_storage.clone();
                let store = lock_app_storage(&app_storage);
                let _ = store.update_app_message(
                    &msg.msgid,
                    None,
                    Some(MessageStatus::Sending.to_i32()),
                    None,
                    None,
                    None,
                    None,
                    None,
                );
            }

            match self.rebroadcast_event_internal(event_json).await {
                Ok((success, failed_relays)) => {
                    let ok = !success.is_empty();
                    let status = if ok {
                        MessageStatus::Success.to_i32()
                    } else {
                        MessageStatus::Failed.to_i32()
                    };
                    let mut relays = Vec::new();
                    for url in &success {
                        relays.push(serde_json::json!({"url": url, "status": "ok"}));
                    }
                    for (url, err) in &failed_relays {
                        relays.push(
                            serde_json::json!({"url": url, "status": "failed", "error": err}),
                        );
                    }
                    let relay_json = serde_json::to_string(&relays).unwrap_or_default();

                    {
                        let app_storage = self.inner.read().await.app_storage.clone();
                        let store = lock_app_storage(&app_storage);
                        let _ = store.update_app_message(
                            &msg.msgid,
                            None,
                            Some(status),
                            Some(&relay_json),
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                    self.emit_data_change(DataChange::MessageUpdated {
                        room_id: msg.room_id.clone(),
                        msgid: msg.msgid.clone(),
                    })
                    .await;
                    if ok {
                        retried += 1;
                    }
                }
                Err(_) => {
                    let app_storage = self.inner.read().await.app_storage.clone();
                    let store = lock_app_storage(&app_storage);
                    let _ = store.update_app_message(
                        &msg.msgid,
                        None,
                        Some(MessageStatus::Failed.to_i32()),
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                }
            }
        }
        Ok(retried)
    }
}
