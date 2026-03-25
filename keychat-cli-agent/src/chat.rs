//! 1:1 chat — friend requests + Signal encrypted messaging.
//!
//! Core protocol logic with proper address management (§9).
//! Both REPL (app.rs) and daemon (daemon.rs) use these functions.

use anyhow::{Context, Result};
use libkeychat::{
    accept_friend_request, accept_friend_request_persistent, receive_friend_request,
    send_friend_request_persistent, serialize_prekey_material, AddressManager, AddressUpdate,
    KCMessage,
};
use libkeychat::{DeviceId, PreKeySignalMessage, ProtocolAddress};
use nostr::prelude::*;
use nostr_sdk::RelayPoolNotification;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Normalize a Nostr public key: accept both npub1... (bech32) and hex formats.
fn normalize_pubkey(input: &str) -> Result<String> {
    libkeychat::normalize_pubkey(input).map_err(|e| anyhow::anyhow!("{}", e))
}
use tokio::sync::broadcast;

use crate::state::{AppState, ChatTarget, OutboundFriendRequest, Peer, PendingFriendRequest};
use crate::ui;

// ─── Event types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub sender: String,
    pub sender_name: String,
    pub message: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IncomingEvent {
    #[serde(rename = "message")]
    Message(IncomingMessage),
    #[serde(rename = "friend_request")]
    FriendRequest {
        sender: String,
        sender_name: String,
        auto_accepted: bool,
    },
}

// ─── Send ───────────────────────────────────────────────────────────────────

/// Persist address state to DB after address updates.
fn save_address_state(state: &AppState, peer_signal_id: &str, addr_mgr: &AddressManager) {
    if let Some(addr_state) = addr_mgr.to_serialized(peer_signal_id) {
        let _ = state.db().save_peer_addresses(peer_signal_id, &addr_state);
    }
}

/// Send a text message to a specific peer (by nostr pubkey).
pub async fn send_text_to(state: &AppState, peer_npub: &str, text: &str) -> Result<()> {
    let mut peers = state.peers.write().await;
    let peer = peers
        .get_mut(peer_npub)
        .ok_or_else(|| anyhow::anyhow!("Peer not found: {}", peer_npub))?;

    let msg = KCMessage::text(text);
    let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());

    // Encrypt with metadata to get ratchet address info
    let json = msg.to_json()?;
    let ct = peer.signal.encrypt(&addr, json.as_bytes())?;

    // Resolve correct sending address (ratchet → firstInbox → npub fallback)
    let to_address = peer
        .address_manager
        .resolve_send_address(&peer.signal_id)
        .unwrap_or_else(|_| peer.nostr_pubkey.clone());

    // Update address state after encrypt
    let update = peer
        .address_manager
        .on_encrypt(&peer.signal_id, ct.sender_address.as_deref())
        .unwrap_or_default();

    // Build and send Mode 1 event
    let event = build_mode1_event(&ct.bytes, &to_address).await?;
    state.client.send_event(event).await?;

    // Subscribe to any new receiving addresses
    subscribe_addresses(state, &update).await;

    Ok(())
}

/// Send a text message to the active peer (REPL mode).
pub async fn send_text(state: &AppState, text: &str) -> Result<()> {
    let active = state.active_chat.read().await;
    let peer_npub = match active.as_ref() {
        Some(ChatTarget::Peer(p)) => p.clone(),
        _ => anyhow::bail!("Active chat is not a 1:1 peer"),
    };
    drop(active);
    send_text_to(state, &peer_npub, text).await?;
    ui::sent(text);
    Ok(())
}

/// Send a friend request.
pub async fn add_friend(state: &AppState, peer_npub: &str) -> Result<()> {
    // Accept both npub (bech32) and hex formats
    let peer_hex = normalize_pubkey(peer_npub)?;
    let keys = libkeychat::signal_session::generate_prekey_material()?;
    let (event, fr_state) = send_friend_request_persistent(
        &state.identity,
        &peer_hex,
        &state.name,
        "keychat-cli",
        keys,
        state.storage_arc(),
        1,
    )
    .await?;
    state.client.send_event(event).await?;

    // Subscribe to firstInbox for the acceptance reply
    let first_inbox_hex = fr_state.first_inbox_keys.pubkey_hex();
    subscribe_to_address(state, &first_inbox_hex).await;

    // Store pending state
    state.pending_outbound_frs.write().await.insert(
        first_inbox_hex.clone(),
        OutboundFriendRequest {
            signal: fr_state.signal_participant,
            first_inbox_pubkey: first_inbox_hex.clone(),
            first_inbox_secret: fr_state.first_inbox_keys.secret_key().to_secret_hex(),
        },
    );

    state.db().save_peer_mapping(
        peer_npub,
        "pending",
        &format!("{}...", &peer_npub[..8.min(peer_npub.len())]),
    )?;

    ui::sys(&format!(
        "📨 Friend request sent to {}...",
        &peer_npub[..16.min(peer_npub.len())]
    ));
    Ok(())
}

/// Send a file message to active peer.
pub async fn send_file(state: &AppState, path: &str) -> Result<()> {
    let active = state.active_chat.read().await;
    let peer_npub = match active.as_ref() {
        Some(ChatTarget::Peer(p)) => p.clone(),
        _ => anyhow::bail!("Active chat is not a 1:1 peer"),
    };
    drop(active);

    let file_data = std::fs::read(path)?;
    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let mime = mime_from_ext(path);
    let category = category_from_mime(&mime);

    let encrypted = libkeychat::media::encrypt_file(&file_data);
    let file_msg = libkeychat::media::build_file_message(
        &format!("local://{}", file_name),
        category,
        Some(&mime),
        file_data.len() as u64,
        &encrypted,
    );

    let mut peers = state.peers.write().await;
    let peer = peers
        .get_mut(&peer_npub)
        .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;
    let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());

    let json = file_msg.to_json()?;
    let ct = peer.signal.encrypt(&addr, json.as_bytes())?;
    let to_address = peer
        .address_manager
        .resolve_send_address(&peer.signal_id)
        .unwrap_or_else(|_| peer.nostr_pubkey.clone());
    let update = peer
        .address_manager
        .on_encrypt(&peer.signal_id, ct.sender_address.as_deref())
        .unwrap_or_default();
    save_address_state(state, &peer.signal_id, &peer.address_manager);

    let event = build_mode1_event(&ct.bytes, &to_address).await?;
    state.client.send_event(event).await?;
    subscribe_addresses(state, &update).await;

    ui::sys(&format!(
        "📁 Sent file: {} ({} bytes)",
        file_name,
        file_data.len()
    ));
    Ok(())
}

/// Send a voice message to active peer.
pub async fn send_voice(state: &AppState, path: &str) -> Result<()> {
    let active = state.active_chat.read().await;
    let peer_npub = match active.as_ref() {
        Some(ChatTarget::Peer(p)) => p.clone(),
        _ => anyhow::bail!("Active chat is not a 1:1 peer"),
    };
    drop(active);

    let data = std::fs::read(path)?;
    let encrypted = libkeychat::media::encrypt_file(&data);
    let voice_msg = libkeychat::media::build_voice_message(
        "local://voice",
        data.len() as u64,
        0.0,
        vec![],
        &encrypted,
    );

    let mut peers = state.peers.write().await;
    let peer = peers
        .get_mut(&peer_npub)
        .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;
    let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());

    let json = voice_msg.to_json()?;
    let ct = peer.signal.encrypt(&addr, json.as_bytes())?;
    let to_address = peer
        .address_manager
        .resolve_send_address(&peer.signal_id)
        .unwrap_or_else(|_| peer.nostr_pubkey.clone());
    let update = peer
        .address_manager
        .on_encrypt(&peer.signal_id, ct.sender_address.as_deref())
        .unwrap_or_default();
    save_address_state(state, &peer.signal_id, &peer.address_manager);

    let event = build_mode1_event(&ct.bytes, &to_address).await?;
    state.client.send_event(event).await?;
    subscribe_addresses(state, &update).await;

    ui::sys(&format!("🎤 Sent voice: {} bytes", data.len()));
    Ok(())
}

// ─── Listener ───────────────────────────────────────────────────────────────

/// Background listener — decrypts events and dispatches to event_tx + REPL UI.
pub async fn start_listener(state: Arc<AppState>, event_tx: broadcast::Sender<IncomingEvent>) {
    // Subscribe to our npub (for friend requests via Gift Wrap)
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(state.keys.public_key())
        .since(Timestamp::now() - 300);
    let _ = state.client.subscribe(vec![filter], None).await;

    // Also subscribe to kind:1059 sent to any p-tag matching our npub
    // (Mode 1 events use p-tag targeting)
    let filter2 = Filter::new()
        .kind(Kind::GiftWrap)
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            [state.keys.public_key().to_hex()],
        )
        .since(Timestamp::now() - 300);
    let _ = state.client.subscribe(vec![filter2], None).await;

    // Re-subscribe to all persisted receiving addresses from restored peers
    {
        let peers = state.peers.read().await;
        for peer in peers.values() {
            for addr in peer.address_manager.get_all_receiving_address_strings() {
                subscribe_to_address(&state, &addr).await;
            }
        }
        let count: usize = peers
            .values()
            .map(|p| p.address_manager.get_all_receiving_address_strings().len())
            .sum();
        if count > 0 {
            eprintln!("[listener] re-subscribed to {} receiving addresses", count);
        }
    }

    // Re-subscribe to MLS group temp inboxes
    {
        let mls_group_ids = state.db().list_mls_group_ids().unwrap_or_default();
        let mls_inboxes: Vec<String> = {
            let mls = state.mls.lock().unwrap();
            if let Some(participant) = mls.as_ref() {
                mls_group_ids
                    .iter()
                    .filter_map(|gid| participant.derive_temp_inbox(gid).ok())
                    .collect()
            } else {
                Vec::new()
            }
        };
        for inbox in &mls_inboxes {
            subscribe_to_address(&state, inbox).await;
        }
        if !mls_inboxes.is_empty() {
            eprintln!(
                "[listener] re-subscribed to {} MLS group inboxes",
                mls_inboxes.len()
            );
        }
    }

    let mut notifications = state.client.notifications();
    loop {
        match notifications.recv().await {
            Ok(RelayPoolNotification::Event { event, .. }) => {
                if event.kind == Kind::GiftWrap {
                    let _ = handle_event(&state, &event, &event_tx).await;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

// ─── Friend request approval ────────────────────────────────────────────────

/// Approve a pending inbound friend request (owner action).
pub async fn approve_friend(
    state: &AppState,
    sender_npub: &str,
    event_tx: &broadcast::Sender<IncomingEvent>,
) -> Result<()> {
    let mut pending = state.pending_friend_requests.write().await;
    let idx = pending
        .iter()
        .position(|p| p.sender_npub == sender_npub)
        .ok_or_else(|| anyhow::anyhow!("No pending request from {}", sender_npub))?;
    let pfr = pending.remove(idx);
    drop(pending);

    // Re-parse the payload and re-receive to get FriendRequestReceived
    let payload: libkeychat::KCFriendRequestPayload = serde_json::from_str(&pfr.payload_json)?;

    // Build a synthetic FriendRequestReceived
    let sender_pubkey = PublicKey::from_hex(&pfr.sender_npub)?;
    let fr = libkeychat::FriendRequestReceived {
        sender_pubkey,
        sender_pubkey_hex: pfr.sender_npub.clone(),
        payload,
        message: KCMessage::text(""), // placeholder, not used in accept
        created_at: 0, // Restored from DB, original rumor timestamp not preserved
    };

    do_accept_friend(state, &fr, event_tx).await?;
    ui::sys(&format!("✅ Approved {}", pfr.sender_name));
    Ok(())
}

/// Reject a pending inbound friend request.
pub async fn reject_friend(state: &AppState, sender_npub: &str) -> Result<()> {
    let mut pending = state.pending_friend_requests.write().await;
    let idx = pending
        .iter()
        .position(|p| p.sender_npub == sender_npub)
        .ok_or_else(|| anyhow::anyhow!("No pending request from {}", sender_npub))?;
    let pfr = pending.remove(idx);
    ui::sys(&format!("❌ Rejected {}", pfr.sender_name));
    Ok(())
}

/// List pending friend requests.
pub async fn list_pending_friends(state: &AppState) -> Vec<PendingFriendRequest> {
    state.pending_friend_requests.read().await.clone()
}

// ─── Event handling ─────────────────────────────────────────────────────────

/// Process a single event.
pub async fn handle_event(
    state: &AppState,
    event: &Event,
    event_tx: &broadcast::Sender<IncomingEvent>,
) -> Result<()> {
    let eid = event.id.to_hex();
    {
        let db = state.db();
        if db.is_event_processed(&eid)? {
            return Ok(());
        }
        db.mark_event_processed(&eid)?;
    }

    // 1) Try friend request (NIP-17 Gift Wrap → Seal → Rumor)
    if let Ok(fr) = receive_friend_request(&state.identity, event) {
        return handle_friend_request(state, &fr, event_tx).await;
    }

    // 2) Try decrypt from known peers (Mode 1: base64 Signal ciphertext in content)
    if try_decrypt_from_peers(state, event, event_tx).await? {
        return Ok(());
    }

    // 3) Try pending friend request responses
    if try_pending_fr_response(state, event, event_tx).await? {
        return Ok(());
    }

    Ok(())
}

async fn handle_friend_request(
    state: &AppState,
    fr: &libkeychat::FriendRequestReceived,
    event_tx: &broadcast::Sender<IncomingEvent>,
) -> Result<()> {
    let sender_hex = fr.sender_pubkey.to_hex();

    // Determine whether to auto-accept based on dm_policy:
    //   - No owner yet → auto-accept, sender becomes owner
    //   - Sender IS owner → auto-accept
    //   - Otherwise → require owner approval (queue as pending)
    let should_accept = if state.config.auto_accept_friends {
        let owner = state.owner.read().await;
        match owner.as_deref() {
            None => true,                       // No owner yet — first peer becomes owner
            Some(o) if o == sender_hex => true, // Owner is adding us (e.g., re-add after reset)
            Some(_) => false,                   // Someone else — needs owner approval
        }
    } else {
        false
    };

    if should_accept {
        do_accept_friend(state, fr, event_tx).await?;

        // If no owner yet, this sender becomes owner
        let mut owner = state.owner.write().await;
        if owner.is_none() {
            *owner = Some(sender_hex.clone());
            // Persist to config
            let mut config = state.config.clone();
            config.owner = Some(sender_hex.clone());
            let _ = config.save(std::path::Path::new(&state.data_dir));
            ui::sys(&format!("👑 {} is now owner", fr.payload.name));
        }
    } else {
        // Queue for owner approval
        let pending = PendingFriendRequest {
            sender_npub: sender_hex.clone(),
            sender_name: fr.payload.name.clone(),
            signal_identity_key: fr.payload.signal_identity_key.clone(),
            first_inbox: fr.payload.first_inbox.clone(),
            payload_json: serde_json::to_string(&fr.payload).unwrap_or_default(),
        };
        state.pending_friend_requests.write().await.push(pending);

        let _ = event_tx.send(IncomingEvent::FriendRequest {
            sender: sender_hex.clone(),
            sender_name: fr.payload.name.clone(),
            auto_accepted: false,
        });
        ui::sys(&format!(
            "📨 Friend request from {} (needs owner approval)",
            fr.payload.name
        ));
    }
    Ok(())
}

/// Accept a friend request and register the peer.
async fn do_accept_friend(
    state: &AppState,
    fr: &libkeychat::FriendRequestReceived,
    event_tx: &broadcast::Sender<IncomingEvent>,
) -> Result<()> {
    let sender_hex = fr.sender_pubkey.to_hex();
    let peer_signal_id = fr.payload.signal_identity_key.clone();

    // Generate keys and create persistent participant (sessions auto-saved to DB)
    let keys = libkeychat::signal_session::generate_prekey_material()?;
    let device_id = 1u32;

    // Save key material to DB
    if let Ok((id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec)) =
        serialize_prekey_material(&keys)
    {
        let _ = state.db().save_signal_participant(
            &peer_signal_id,
            device_id,
            &id_pub,
            &id_priv,
            reg_id,
            spk_id,
            &spk_rec,
            pk_id,
            &pk_rec,
            kpk_id,
            &kpk_rec,
        );
    }

    let accepted = accept_friend_request_persistent(
        &state.identity,
        fr,
        &state.name,
        keys,
        state.storage_arc(),
        device_id,
    )
    .await?;
    state.client.send_event(accepted.event).await?;

    let mut addr_mgr = AddressManager::new();
    addr_mgr.add_peer(
        &peer_signal_id,
        Some(fr.payload.first_inbox.clone()),
        Some(sender_hex.clone()),
    );

    let update = addr_mgr
        .on_encrypt(&peer_signal_id, accepted.sender_address.as_deref())
        .unwrap_or_default();
    if let Some(addr_state) = addr_mgr.to_serialized(&peer_signal_id) {
        let _ = state.db().save_peer_addresses(&peer_signal_id, &addr_state);
    }
    subscribe_addresses(state, &update).await;

    let peer = Peer {
        nostr_pubkey: sender_hex.clone(),
        signal_id: peer_signal_id.clone(),
        name: fr.payload.name.clone(),
        signal: accepted.signal_participant,
        address_manager: addr_mgr,
    };
    state
        .db()
        .save_peer_mapping(&sender_hex, &peer_signal_id, &fr.payload.name)?;
    state.peers.write().await.insert(sender_hex.clone(), peer);

    let _ = event_tx.send(IncomingEvent::FriendRequest {
        sender: sender_hex.clone(),
        sender_name: fr.payload.name.clone(),
        auto_accepted: true,
    });
    ui::sys(&format!("✅ Auto-accepted {}", fr.payload.name));
    Ok(())
}

async fn try_decrypt_from_peers(
    state: &AppState,
    event: &Event,
    event_tx: &broadcast::Sender<IncomingEvent>,
) -> Result<bool> {
    // Mode 1: content is base64(Signal ciphertext), p-tag is receiving address
    let ciphertext =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.content) {
            Ok(ct) => ct,
            Err(_) => return Ok(false),
        };

    let peer_keys: Vec<String> = state.peers.read().await.keys().cloned().collect();
    for npub in &peer_keys {
        let mut peers = state.peers.write().await;
        if let Some(peer) = peers.get_mut(npub) {
            let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());
            if let Ok(result) = peer.signal.decrypt(&addr, &ciphertext) {
                // Update address state after decrypt
                let update = peer
                    .address_manager
                    .on_decrypt(
                        &peer.signal_id,
                        result.bob_derived_address.as_deref(),
                        result.alice_addrs.as_deref(),
                    )
                    .unwrap_or_default();
                save_address_state(state, &peer.signal_id, &peer.address_manager);

                // Subscribe to new receiving addresses
                drop(peers);
                subscribe_addresses(state, &update).await;

                // Parse message
                let text = String::from_utf8_lossy(&result.plaintext);
                if let Some(msg) = KCMessage::try_parse(&text) {
                    let group_info = if let Some(gid) = &msg.group_id {
                        let gm = state.signal_groups.read().await;
                        let gname = gm
                            .get_group(gid)
                            .map(|g| g.name.clone())
                            .unwrap_or_else(|| gid[..8].to_string());
                        Some((gid.clone(), gname))
                    } else {
                        None
                    };

                    let incoming = kcmessage_to_incoming(
                        &msg,
                        npub,
                        &{
                            state
                                .peers
                                .read()
                                .await
                                .get(npub)
                                .map(|p| p.name.clone())
                                .unwrap_or_default()
                        },
                        group_info.as_ref(),
                    );

                    if let Some((_, ref gname)) = group_info {
                        display_message(&msg, &incoming.sender_name, Some(gname));
                    } else {
                        display_message(&msg, &incoming.sender_name, None);
                    }
                    let _ = event_tx.send(IncomingEvent::Message(incoming));
                }
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn try_pending_fr_response(
    state: &AppState,
    event: &Event,
    event_tx: &broadcast::Sender<IncomingEvent>,
) -> Result<bool> {
    let ciphertext =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.content) {
            Ok(ct) => ct,
            Err(_) => return Ok(false),
        };

    if !libkeychat::SignalParticipant::is_prekey_message(&ciphertext) {
        return Ok(false);
    }

    let prekey_msg = match PreKeySignalMessage::try_from(ciphertext.as_slice()) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };

    let sender_identity = hex::encode(prekey_msg.identity_key().serialize());
    let remote_addr = ProtocolAddress::new(sender_identity.clone(), DeviceId::new(1).unwrap());

    let pending_keys: Vec<String> = state
        .pending_outbound_frs
        .read()
        .await
        .keys()
        .cloned()
        .collect();
    for first_inbox in &pending_keys {
        let mut pending = state.pending_outbound_frs.write().await;
        if let Some(pfr) = pending.get_mut(first_inbox) {
            if let Ok(result) = pfr.signal.decrypt(&remote_addr, &ciphertext) {
                let text = String::from_utf8_lossy(&result.plaintext);
                if let Some(msg) = KCMessage::try_parse(&text) {
                    if let Some(ref auth) = msg.signal_prekey_auth {
                        let peer_signal_id = auth.signal_id.clone();
                        let peer_nostr_id = auth.nostr_id.clone();
                        let peer_name = auth.name.clone();

                        // Take signal participant from pending
                        let fi = first_inbox.clone();
                        let mut signal = std::mem::replace(
                            &mut pfr.signal,
                            libkeychat::SignalParticipant::new("_placeholder", 1).unwrap(),
                        );
                        pending.remove(&fi);
                        drop(pending);

                        // Initialize address manager with proper addresses
                        let mut addr_mgr = AddressManager::new();
                        addr_mgr.add_peer(
                            &peer_signal_id,
                            None,                        // we don't know their firstInbox
                            Some(peer_nostr_id.clone()), // peer's nostr pubkey
                        );

                        // Process decrypt address updates
                        let update = addr_mgr
                            .on_decrypt(
                                &peer_signal_id,
                                result.bob_derived_address.as_deref(),
                                result.alice_addrs.as_deref(),
                            )
                            .unwrap_or_default();
                        if let Some(addr_state) = addr_mgr.to_serialized(&peer_signal_id) {
                            let _ = state.db().save_peer_addresses(&peer_signal_id, &addr_state);
                        }

                        subscribe_addresses(state, &update).await;

                        // Persist Signal key material
                        let device_id = u32::from(signal.address().device_id());
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
                        )) = serialize_prekey_material(signal.keys())
                        {
                            let _ = state.db().save_signal_participant(
                                &peer_signal_id,
                                device_id,
                                &id_pub,
                                &id_priv,
                                reg_id,
                                spk_id,
                                &spk_rec,
                                pk_id,
                                &pk_rec,
                                kpk_id,
                                &kpk_rec,
                            );
                        }

                        let peer = Peer {
                            nostr_pubkey: peer_nostr_id.clone(),
                            signal_id: peer_signal_id.clone(),
                            name: peer_name.clone(),
                            signal,
                            address_manager: addr_mgr,
                        };
                        state.db().save_peer_mapping(
                            &peer_nostr_id,
                            &peer_signal_id,
                            &peer_name,
                        )?;
                        state
                            .peers
                            .write()
                            .await
                            .insert(peer_nostr_id.clone(), peer);

                        let _ = event_tx.send(IncomingEvent::FriendRequest {
                            sender: peer_nostr_id.clone(),
                            sender_name: peer_name.clone(),
                            auto_accepted: true,
                        });
                        ui::sys(&format!("🤝 {} accepted our friend request", peer_name));
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

// ─── Address management ─────────────────────────────────────────────────────

/// Subscribe to a single address (kind:1059 p-tag filter).
async fn subscribe_to_address(state: &AppState, address: &str) {
    if let Ok(pk) = PublicKey::from_hex(address) {
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::P), [pk.to_hex()])
            .since(Timestamp::now() - 60);
        let _ = state.client.subscribe(vec![filter], None).await;
    }
}

/// Subscribe to new receiving addresses from an AddressUpdate.
async fn subscribe_addresses(state: &AppState, update: &AddressUpdate) {
    for addr in &update.new_receiving {
        subscribe_to_address(state, addr).await;
    }
}

/// Build a Mode 1 event (kind:1059, base64 ciphertext, p-tag to receiver).
async fn build_mode1_event(ciphertext: &[u8], to_address: &str) -> Result<Event> {
    let sender = libkeychat::EphemeralKeypair::generate();
    let content = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext);
    let to_pubkey =
        PublicKey::from_hex(to_address).map_err(|e| anyhow::anyhow!("invalid to_address: {e}"))?;

    let event = EventBuilder::new(Kind::GiftWrap, &content)
        .tag(Tag::public_key(to_pubkey))
        .sign(sender.keys())
        .await
        .map_err(|e| anyhow::anyhow!("sign failed: {e}"))?;
    Ok(event)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn kcmessage_to_incoming(
    msg: &KCMessage,
    sender_npub: &str,
    sender_name: &str,
    group_info: Option<&(String, String)>,
) -> IncomingMessage {
    let (content, kind) = if let Some(t) = &msg.text {
        (t.content.clone(), "text".to_string())
    } else if let Some(files) = &msg.files {
        let descs: Vec<String> = files
            .items
            .iter()
            .map(|f| match f.category {
                libkeychat::FileCategory::Voice => {
                    format!("🎤 Voice ({:.1}s)", f.audio_duration.unwrap_or(0.0))
                }
                _ => format!("📁 {} ({})", f.url, f.size.unwrap_or(0)),
            })
            .collect();
        (descs.join("; "), "file".to_string())
    } else if let Some(c) = &msg.cashu {
        (
            format!("💰 {} sats from {}", c.amount, c.mint),
            "cashu".to_string(),
        )
    } else if let Some(l) = &msg.lightning {
        (format!("⚡ {} sats", l.amount), "lightning".to_string())
    } else {
        (format!("[{:?}]", msg.kind), format!("{:?}", msg.kind))
    };

    IncomingMessage {
        sender: sender_npub.to_string(),
        sender_name: sender_name.to_string(),
        message: content,
        kind,
        group_id: group_info.map(|(gid, _)| gid.clone()),
        group_name: group_info.map(|(_, gname)| gname.clone()),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }
}

fn display_message(msg: &KCMessage, sender: &str, group: Option<&str>) {
    // Show reply reference if present
    if let Some(ref reply) = msg.reply_to {
        let preview = if reply.content.len() > 40 {
            format!("{}...", &reply.content[..40])
        } else {
            reply.content.clone()
        };
        let who = reply.user_name.as_deref().unwrap_or("?");
        ui::sys(&format!("  ↩ {} \"{}\"", who, preview));
    }

    match &msg.text {
        Some(t) => {
            if let Some(g) = group {
                ui::group_msg(g, sender, &t.content);
            } else {
                ui::received(sender, &t.content);
            }
        }
        None => {
            if let Some(files) = &msg.files {
                for f in &files.items {
                    let desc = match f.category {
                        libkeychat::FileCategory::Voice => {
                            format!("🎤 Voice ({:.1}s)", f.audio_duration.unwrap_or(0.0))
                        }
                        _ => format!("📁 {} ({})", f.url, f.size.unwrap_or(0)),
                    };
                    if let Some(g) = group {
                        ui::group_msg(g, sender, &desc);
                    } else {
                        ui::received(sender, &desc);
                    }
                }
            } else if let Some(c) = &msg.cashu {
                ui::received(sender, &format!("💰 Cashu: {} sats", c.amount));
            } else if let Some(l) = &msg.lightning {
                ui::received(sender, &format!("⚡ Invoice: {} sats", l.amount));
            } else {
                ui::received(sender, &format!("[{:?}]", msg.kind));
            }
        }
    }
}

pub fn mime_from_ext(path: &str) -> String {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext.to_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "aac" => "audio/aac",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

pub fn category_from_mime(mime: &str) -> libkeychat::FileCategory {
    if mime.starts_with("image/") {
        libkeychat::FileCategory::Image
    } else if mime.starts_with("video/") {
        libkeychat::FileCategory::Video
    } else if mime.starts_with("audio/") {
        libkeychat::FileCategory::Voice
    } else {
        libkeychat::FileCategory::Other
    }
}
