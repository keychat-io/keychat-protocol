//! Protocol orchestration layer.
//!
//! Provides `ProtocolClient` for multi-session management and event routing,
//! plus the `OrchestratorDelegate` trait for notifying upper layers (app persistence, UI)
//! without depending on them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::address::AddressManager;
use crate::error::{KeychatError, Result};
use crate::friend_request::FriendRequestState;
use crate::group::GroupManager;
use crate::identity::Identity;
use crate::message::KCMessageKind;
use crate::session::ChatSession;
use crate::storage::SecureStorage;
use crate::transport::Transport;

// ─── Delegate Trait ─────────────────────────────────────────────

/// Callback interface for the protocol orchestrator.
///
/// The orchestrator calls these methods after protocol-level processing is complete
/// (decryption, session creation, address rotation, SecureStorage persistence).
/// Implementations handle app-layer concerns: UI persistence, notifications, etc.
///
/// **Lock contract**: The orchestrator drops its own `RwLock` before calling any
/// delegate method, so implementations may freely acquire their own locks.
#[async_trait::async_trait]
pub trait OrchestratorDelegate: Send + Sync {
    /// An inbound friend request was received and protocol-persisted.
    /// App should: create room (status=Approving), save contact, save message, notify UI.
    async fn on_friend_request_received(&self, ctx: FriendRequestContext);

    /// A pending outbound friend request was approved by the peer.
    /// Session is created and protocol-persisted.
    /// App should: update room (status=Enabled), save contact, save message, notify UI.
    async fn on_friend_approved(&self, ctx: FriendApprovedContext);

    /// A pending outbound friend request was rejected by the peer.
    /// App should: update room (status=Rejected), notify UI.
    async fn on_friend_rejected(&self, ctx: FriendRejectedContext);

    /// A decrypted session message was received (Text, Files, Cashu, etc.).
    /// App should: create/update room, save message, increment unread, notify UI.
    async fn on_message_received(&self, ctx: MessageReceivedContext);

    /// A Signal group invite was received and stored in GroupManager.
    /// App should: create group room, notify UI.
    async fn on_group_invite_received(&self, ctx: GroupInviteContext);

    /// A group change event occurred (member removed, self-leave, dissolve, rename).
    /// App should: update/delete room, notify UI.
    async fn on_group_changed(&self, ctx: GroupChangedContext);

    /// A NIP-17 DM (non-keychat) was received.
    /// App should: create/update room (type=Nip17Dm), save message, notify UI.
    async fn on_nip17_dm_received(&self, ctx: Nip17DmContext);

    /// A relay responded OK to one of our published events (NIP-01).
    /// App should: update relay status tracking, update message status.
    async fn on_relay_ok(
        &self,
        event_id: String,
        relay_url: String,
        success: bool,
        message: String,
    );

    /// The event loop encountered an error.
    async fn on_error(&self, description: String);
}

// ─── Context Structs ────────────────────────────────────────────
// Pure data — no app_storage, no UI types, no UniFFI annotations.

/// Context for an inbound friend request.
#[derive(Debug, Clone)]
pub struct FriendRequestContext {
    /// Unique ID of the friend request.
    pub request_id: String,
    /// Sender's Nostr pubkey (hex).
    pub sender_pubkey: String,
    /// Sender's display name.
    pub sender_name: String,
    /// Optional message from the sender.
    pub message: Option<String>,
    /// Rumor created_at timestamp (seconds since epoch).
    pub created_at: u64,
    /// Nostr event ID (hex) of the GiftWrap event.
    pub event_id: String,
    /// Serialized KCMessage JSON.
    pub message_json: Option<String>,
    /// Serialized KCFriendRequestPayload JSON.
    pub payload_json: Option<String>,
}

/// Context for a friend request that was approved.
#[derive(Debug, Clone)]
pub struct FriendApprovedContext {
    /// The original request ID.
    pub request_id: String,
    /// Peer's Nostr pubkey (hex).
    pub peer_nostr_pubkey: String,
    /// Peer's display name.
    pub peer_name: String,
    /// Peer's Signal identity key (hex) — used for room association.
    pub peer_signal_id_hex: String,
    /// Nostr event ID (hex) of the GiftWrap event.
    pub event_id: String,
}

/// Context for a friend request that was rejected.
#[derive(Debug, Clone)]
pub struct FriendRejectedContext {
    /// The original request ID.
    pub request_id: String,
    /// Peer's Nostr pubkey (hex).
    pub peer_pubkey: String,
}

/// Context for a decrypted incoming message.
#[derive(Debug, Clone)]
pub struct MessageReceivedContext {
    /// Nostr event ID (hex).
    pub event_id: String,
    /// Sender's Nostr pubkey (hex).
    pub sender_pubkey: String,
    /// KCMessage kind.
    pub kind: KCMessageKind,
    /// Text content (if text message).
    pub content: Option<String>,
    /// Serialized full KCMessage payload (JSON).
    pub payload_json: Option<String>,
    /// Serialized Nostr event JSON (for resend support).
    pub nostr_event_json: Option<String>,
    /// Fallback text for unknown kinds.
    pub fallback: Option<String>,
    /// Event ID of the message being replied to.
    pub reply_to_event_id: Option<String>,
    /// Group ID if this is a group message.
    pub group_id: Option<String>,
    /// Thread ID for threaded conversations.
    pub thread_id: Option<String>,
    /// Relay URL that delivered this event.
    pub relay_url: Option<String>,
    /// Event created_at timestamp.
    pub created_at: u64,
}

/// Context for a group invite.
#[derive(Debug, Clone)]
pub struct GroupInviteContext {
    /// The group ID (Nostr pubkey of the group).
    pub group_id: String,
    /// Group name.
    pub group_name: String,
    /// Group type identifier (e.g. "signal").
    pub group_type: String,
    /// Pubkey of the member who sent the invite.
    pub inviter_pubkey: String,
}

/// The kind of group change event.
#[derive(Debug, Clone)]
pub enum GroupChangeKind {
    MemberRemoved { member_pubkey: Option<String> },
    SelfLeave { group_id: String },
    Dissolve { group_id: String },
    NameChanged { new_name: Option<String> },
}

/// Context for a group change event.
#[derive(Debug, Clone)]
pub struct GroupChangedContext {
    /// The group ID.
    pub group_id: String,
    /// What changed.
    pub change: GroupChangeKind,
    /// Nostr event ID (hex) of the event.
    pub event_id: String,
}

/// Context for a NIP-17 DM.
#[derive(Debug, Clone)]
pub struct Nip17DmContext {
    /// Nostr event ID (hex).
    pub event_id: String,
    /// Sender's Nostr pubkey (hex).
    pub sender_pubkey: String,
    /// Message content.
    pub content: String,
    /// Event created_at timestamp.
    pub created_at: u64,
    /// Serialized Nostr event JSON.
    pub nostr_event_json: Option<String>,
    /// Relay URL that delivered this event.
    pub relay_url: Option<String>,
}

/// Result of a successful `send_message` call.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// Nostr event ID of the published event (hex).
    pub event_id: String,
    /// Serialized Nostr event JSON (for resend support).
    pub nostr_event_json: Option<String>,
    /// Serialized KCMessage payload JSON.
    pub payload_json: Option<String>,
    /// List of relay URLs that the event was published to.
    pub connected_relays: Vec<String>,
    /// Address rotation update from the encrypt step.
    pub addr_update: crate::address::AddressUpdate,
}

// ─── ProtocolClient ─────────────────────────────────────────────

/// Multi-session protocol client.
///
/// Manages Signal sessions, peer mappings, relay transport, and subscription addresses.
/// All protocol state (sessions, peer indexes, pending friend requests) lives here.
/// App-layer state (rooms, messages, contacts, settings) is NOT part of this struct.
pub struct ProtocolClient {
    /// The user's Nostr identity.
    pub identity: Option<Identity>,
    /// Nostr relay transport.
    pub transport: Option<Transport>,
    /// Protocol-level encrypted storage (Signal sessions, peers, addresses, dedup).
    pub storage: Arc<Mutex<SecureStorage>>,
    /// Per-peer Signal chat sessions, keyed by peer's signal identity hex.
    pub sessions: HashMap<String, Arc<tokio::sync::Mutex<ChatSession>>>,
    /// Nostr pubkey → Signal identity mapping.
    pub peer_nostr_to_signal: HashMap<String, String>,
    /// Reverse: Signal identity → Nostr pubkey.
    pub peer_signal_to_nostr: HashMap<String, String>,
    /// Receiving ratchet address → peer signal ID for O(1) message routing.
    pub receiving_addr_to_peer: HashMap<String, String>,
    /// Pending outbound friend requests, keyed by request ID.
    pub pending_outbound: HashMap<String, FriendRequestState>,
    /// Signal group manager.
    pub group_manager: GroupManager,
    /// Next available Signal device ID.
    pub next_signal_device_id: u32,
    /// Active relay subscription IDs.
    pub subscription_ids: Vec<String>,
    /// Last known relay URLs.
    pub last_relay_urls: Vec<String>,
}

impl ProtocolClient {
    /// Create a new ProtocolClient with the given SecureStorage.
    pub fn new(storage: Arc<Mutex<SecureStorage>>) -> Self {
        Self {
            identity: None,
            transport: None,
            storage,
            sessions: HashMap::new(),
            peer_nostr_to_signal: HashMap::new(),
            peer_signal_to_nostr: HashMap::new(),
            receiving_addr_to_peer: HashMap::new(),
            pending_outbound: HashMap::new(),
            group_manager: GroupManager::new(),
            next_signal_device_id: 1,
            subscription_ids: Vec::new(),
            last_relay_urls: Vec::new(),
        }
    }

    /// Restore all sessions, peer mappings, pending FRs, and groups from storage.
    ///
    /// Returns the number of active sessions restored.
    pub fn restore_sessions(&mut self) -> Result<u32> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("call import_identity first".into()))?;
        let storage = self.storage.clone();

        let store = storage
            .lock()
            .map_err(|e| KeychatError::Storage(format!("storage lock: {e}")))?;

        let mut restored_count: u32 = 0;
        let mut max_device_id: u32 = 0;

        // ── Phase 1: Read all data from DB while holding the lock ──

        type ParticipantRow = (String, u32, Vec<u8>, Vec<u8>, u32);
        let mut participant_rows: Vec<ParticipantRow> = Vec::new();

        type FrRow = (
            String,
            u32,
            Vec<u8>,
            Vec<u8>,
            u32,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            u32,
            Vec<u8>,
            String,
            String,
        );
        let mut fr_rows: Vec<FrRow> = Vec::new();

        let peers = store
            .list_peers()
            .map_err(|e| KeychatError::Storage(format!("list_peers: {e}")))?;
        let peer_ids = store
            .list_signal_participants()
            .map_err(|e| KeychatError::Storage(format!("list_signal_participants: {e}")))?;
        let all_addresses = store
            .load_all_peer_addresses()
            .map_err(|e| KeychatError::Storage(format!("load_all_peer_addresses: {e}")))?;
        let fr_ids = store
            .list_pending_frs()
            .map_err(|e| KeychatError::Storage(format!("list_pending_frs: {e}")))?;

        tracing::info!(
            "RESTORE: peers={} participants={} addresses={} frs={}",
            peers.len(),
            peer_ids.len(),
            all_addresses.len(),
            fr_ids.len()
        );

        for peer_signal_id in &peer_ids {
            match store.load_signal_participant(peer_signal_id) {
                Ok(Some((device_id, id_pub, id_priv, reg_id, _spk_id, _spk_rec))) => {
                    participant_rows.push((
                        peer_signal_id.clone(),
                        device_id,
                        id_pub,
                        id_priv,
                        reg_id,
                    ));
                }
                Ok(None) => {
                    tracing::warn!(
                        "restore: no data for participant {}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                }
                Err(e) => {
                    tracing::error!(
                        "restore: load participant {} failed: {e}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                }
            }
        }

        for fr_id in &fr_ids {
            match store.load_pending_fr(fr_id) {
                Ok(Some((
                    device_id,
                    id_pub,
                    id_priv,
                    reg_id,
                    spk_id,
                    spk_rec,
                    pk_id,
                    pk_rec,
                    kpk_id,
                    kpk_rec,
                    first_inbox_secret,
                    peer_nostr_pubkey,
                ))) => {
                    fr_rows.push((
                        fr_id.clone(),
                        device_id,
                        id_pub,
                        id_priv,
                        reg_id,
                        spk_id,
                        spk_rec,
                        pk_id,
                        pk_rec,
                        kpk_id,
                        kpk_rec,
                        first_inbox_secret,
                        peer_nostr_pubkey,
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(
                        "restore pending FR {} failed: {e}",
                        &fr_id[..16.min(fr_id.len())]
                    );
                }
            }
        }

        // Drop the Mutex guard so restore_persistent can lock it
        drop(store);

        // ── Phase 2: Reconstruct objects (may lock storage internally) ──

        // 1. Restore peer mappings
        for peer in &peers {
            self.peer_nostr_to_signal
                .insert(peer.nostr_pubkey.clone(), peer.signal_id.clone());
            self.peer_signal_to_nostr
                .insert(peer.signal_id.clone(), peer.nostr_pubkey.clone());
        }
        if !peers.is_empty() {
            tracing::info!("restored {} peer mappings", peers.len());
        }

        // 2. Restore active sessions with per-peer identity
        let addr_map: HashMap<String, _> = all_addresses.into_iter().collect();

        for (peer_signal_id, device_id, id_pub, id_priv, reg_id) in participant_rows {
            if device_id > max_device_id {
                max_device_id = device_id;
            }

            let identity_key = match crate::IdentityKey::decode(&id_pub) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(
                        "restore session {}: decode identity: {e}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                    continue;
                }
            };
            let private_key = match crate::SignalPrivateKey::deserialize(&id_priv) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(
                        "restore session {}: decode private key: {e}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                    continue;
                }
            };
            let identity_key_pair = crate::IdentityKeyPair::new(identity_key, private_key);

            let signal = match crate::SignalParticipant::restore_persistent(
                identity.pubkey_hex(),
                device_id,
                identity_key_pair,
                reg_id,
                storage.clone(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "restore session {}: create participant failed: {e}",
                        &peer_signal_id[..16.min(peer_signal_id.len())]
                    );
                    continue;
                }
            };

            let addresses = if let Some(addr_state) = addr_map.get(&peer_signal_id) {
                AddressManager::from_serialized(&peer_signal_id, addr_state.clone())
            } else {
                AddressManager::new()
            };

            // Build reverse index: receiving_address → peer_signal_id
            for addr in addresses.get_all_receiving_address_strings() {
                self.receiving_addr_to_peer
                    .insert(addr, peer_signal_id.clone());
            }

            let session = ChatSession::new(signal, addresses, identity.clone());
            self.sessions.insert(
                peer_signal_id.clone(),
                Arc::new(tokio::sync::Mutex::new(session)),
            );
            restored_count += 1;
        }

        // 3. Restore pending outbound friend requests (per-peer identity)
        for (
            fr_id,
            device_id,
            id_pub,
            id_priv,
            reg_id,
            spk_id,
            spk_rec,
            pk_id,
            pk_rec,
            kpk_id,
            kpk_rec,
            first_inbox_secret,
            peer_nostr_pubkey,
        ) in fr_rows
        {
            if device_id > max_device_id {
                max_device_id = device_id;
            }

            let keys = match crate::reconstruct_prekey_material(
                &id_pub, &id_priv, reg_id, spk_id, &spk_rec, pk_id, &pk_rec, kpk_id, &kpk_rec,
            ) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(
                        "restore pending FR {}: reconstruct keys failed: {e}",
                        &fr_id[..16.min(fr_id.len())]
                    );
                    continue;
                }
            };

            let signal = match crate::SignalParticipant::persistent(
                identity.pubkey_hex(),
                device_id,
                keys,
                storage.clone(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "restore pending FR {}: create participant failed: {e}",
                        &fr_id[..16.min(fr_id.len())]
                    );
                    continue;
                }
            };

            let first_inbox_keys =
                match crate::EphemeralKeypair::from_secret_hex(&first_inbox_secret) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!(
                            "restore pending FR {}: reconstruct first_inbox failed: {e}",
                            &fr_id[..16.min(fr_id.len())]
                        );
                        continue;
                    }
                };

            self.pending_outbound.insert(
                fr_id.clone(),
                FriendRequestState {
                    signal_participant: signal,
                    first_inbox_keys,
                    request_id: fr_id.clone(),
                    peer_nostr_pubkey,
                },
            );
        }
        if !fr_ids.is_empty() {
            tracing::info!("restored {} pending friend requests", fr_ids.len());
        }

        // 4. Restore signal groups
        {
            let store = storage
                .lock()
                .map_err(|e| KeychatError::Storage(format!("storage lock: {e}")))?;
            self.group_manager.load_all(&store).map_err(|e| {
                tracing::error!("restore: load_all groups failed: {e}");
                KeychatError::Storage(format!("load_all groups: {e}"))
            })?;
            if self.group_manager.group_count() > 0 {
                tracing::info!(
                    "restored {} signal groups",
                    self.group_manager.group_count()
                );
            }
        }

        // Update device_id counter to avoid collisions
        if max_device_id >= self.next_signal_device_id {
            self.next_signal_device_id = max_device_id + 1;
        }

        tracing::info!(
            "restore complete: {} sessions, {} pending FRs, {} groups, next_device_id={}",
            restored_count,
            self.pending_outbound.len(),
            self.group_manager.group_count(),
            self.next_signal_device_id
        );

        Ok(restored_count)
    }

    /// Connect to Nostr relays.
    ///
    /// If `relay_urls` is empty, loads from DB or falls back to defaults.
    pub async fn connect(&mut self, relay_urls: Vec<String>) -> Result<()> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("call import_identity first".into()))?;

        // Resolve relay URLs: parameter → DB → defaults
        let urls = if !relay_urls.is_empty() {
            relay_urls
        } else {
            let storage = self.storage.clone();
            let db_relays = storage
                .lock()
                .ok()
                .and_then(|s| s.list_relays().ok())
                .unwrap_or_default();
            if !db_relays.is_empty() {
                db_relays
            } else {
                crate::transport::DEFAULT_RELAYS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            }
        };

        tracing::info!("connecting to {} relays: {:?}", urls.len(), urls);

        // Create transport, inject storage for persistent dedup, add relays, connect
        let mut transport = Transport::new(identity.keys()).await?;
        transport.set_storage(self.storage.clone());
        // Prune old dedup records on connect
        if let Ok(store) = self.storage.lock() {
            let _ = store.prune_processed_events(86400 * 7); // 7 days
        }
        for url in &urls {
            transport.add_relay(url).await.map_err(|e| {
                tracing::error!("add_relay({url}) failed: {e}");
                e
            })?;
        }
        transport.connect().await;
        tracing::info!("relay transport connected");

        // Persist the relay list to DB
        if let Ok(store) = self.storage.lock() {
            for url in &urls {
                let _ = store.save_relay(url);
            }
        }

        self.transport = Some(transport);
        self.last_relay_urls = urls;
        self.subscription_ids.clear();
        Ok(())
    }

    /// Disconnect from all relays and stop background tasks.
    ///
    /// Note: event_loop_stop and reconnect_stop channels are managed by the caller
    /// (e.g. the FFI layer), since they relate to tasks the caller spawns.
    pub async fn disconnect(&mut self) -> Result<()> {
        tracing::info!("disconnecting from relays");
        self.subscription_ids.clear();
        if let Some(t) = self.transport.take() {
            t.disconnect().await.map_err(|e| {
                tracing::error!("disconnect failed: {e}");
                e
            })?;
        }
        tracing::info!("disconnected");
        Ok(())
    }

    /// Add a relay at runtime, connect to it, and persist to DB.
    pub async fn add_relay(&self, url: &str) -> Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        transport.add_relay_and_connect(url).await?;

        if let Ok(store) = self.storage.lock() {
            let _ = store.save_relay(url);
        }
        tracing::info!("added relay: {url}");
        Ok(())
    }

    /// Remove a relay at runtime and delete from DB.
    pub async fn remove_relay(&self, url: &str) -> Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        transport.remove_relay(url).await?;

        if let Ok(store) = self.storage.lock() {
            let _ = store.delete_relay(url);
        }
        tracing::info!("removed relay: {url}");
        Ok(())
    }

    /// Get the current relay URL list.
    pub async fn get_relays(&self) -> Result<Vec<String>> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        Ok(transport.get_relays().await)
    }

    /// Get only the currently connected relay URLs.
    pub async fn connected_relays(&self) -> Result<Vec<String>> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        Ok(transport.connected_relays().await)
    }

    /// Get relay URLs with their connection status.
    pub async fn get_relay_statuses(&self) -> Result<Vec<(String, String)>> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        Ok(transport.get_relay_statuses().await)
    }

    /// Reconnect to all relays (re-enables disabled ones).
    pub async fn reconnect_relays(&self) -> Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        transport.reconnect().await?;
        tracing::info!("reconnected to all relays");
        Ok(())
    }

    /// Collect pubkeys for subscription, split into identity keys and ratchet keys.
    ///
    /// Identity keys receive NIP-59 GiftWrap with ±2 day timestamp randomization,
    /// so they need `since = cursor - 2 days`. Ratchet keys are newly derived
    /// and have no historical messages, so they use `since = now()`.
    pub async fn collect_subscribe_pubkeys(
        &self,
    ) -> (Vec<nostr::PublicKey>, Vec<nostr::PublicKey>) {
        let identity_pk = self
            .identity
            .as_ref()
            .and_then(|id| nostr::PublicKey::from_hex(&id.pubkey_hex()).ok());

        // Identity keys: receive NIP-59 with randomized outer timestamps
        let mut identity_pubkeys = Vec::new();
        if let Some(pk) = identity_pk {
            identity_pubkeys.push(pk);
        }
        // Pending outbound first-inbox keys also receive NIP-59 friend request responses
        for state in self.pending_outbound.values() {
            if let Ok(pk) = nostr::PublicKey::from_hex(&state.first_inbox_keys.pubkey_hex()) {
                identity_pubkeys.push(pk);
            }
        }

        // Ratchet keys: newly derived Signal addresses, no historical messages
        let mut ratchet_pubkeys = Vec::new();
        for session_mutex in self.sessions.values() {
            let session = session_mutex.lock().await;
            for addr_str in session.addresses.get_all_receiving_address_strings() {
                if let Ok(pk) = nostr::PublicKey::from_hex(&addr_str) {
                    ratchet_pubkeys.push(pk);
                }
            }
        }

        (identity_pubkeys, ratchet_pubkeys)
    }

    /// Refresh relay subscriptions with current identity + ratchet addresses.
    pub async fn refresh_subscriptions(&mut self) -> Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected.".into()))?;

        let relay_cursor = self
            .storage
            .lock()
            .ok()
            .and_then(|s| s.get_min_relay_cursor().ok())
            .unwrap_or(0);

        let (identity_pubkeys, ratchet_pubkeys) = self.collect_subscribe_pubkeys().await;

        // Subscribe identity keys with cursor-based since (±2 day randomization)
        let identity_since = if relay_cursor > 0 {
            Some(nostr::Timestamp::from(
                relay_cursor.saturating_sub(3 * 86400),
            ))
        } else {
            None
        };
        // Use resubscribe() for atomic unsub+sub (matches main branch behavior)
        let old_ids = std::mem::take(&mut self.subscription_ids);
        let mut old_iter = old_ids.into_iter().map(|s| crate::SubscriptionId::new(s));

        let mut new_sub_ids = Vec::new();
        if !identity_pubkeys.is_empty() {
            let id = transport
                .resubscribe(old_iter.next(), identity_pubkeys, identity_since)
                .await?;
            new_sub_ids.push(id.to_string());
        }

        if !ratchet_pubkeys.is_empty() {
            // Use cursor - 60s instead of now() to avoid race condition:
            // events sent in the same second as the subscription would be filtered out.
            let ratchet_since = if relay_cursor > 0 {
                Some(nostr::Timestamp::from(relay_cursor.saturating_sub(60)))
            } else {
                None
            };
            let id = transport
                .resubscribe(old_iter.next(), ratchet_pubkeys, ratchet_since)
                .await?;
            new_sub_ids.push(id.to_string());
        }

        // Unsubscribe any remaining stale IDs
        for leftover in old_iter {
            transport.unsubscribe(leftover).await;
        }

        self.subscription_ids = new_sub_ids;

        Ok(())
    }

    /// Get all receiving addresses across all sessions (for debugging).
    pub async fn get_all_receiving_addresses(&self) -> Vec<String> {
        let mut all = Vec::new();
        for session_mutex in self.sessions.values() {
            let session = session_mutex.lock().await;
            all.extend(session.addresses.get_all_receiving_address_strings());
        }
        all
    }

    /// Update address state, reverse index, and relay subscriptions after a successful decrypt.
    pub async fn update_addresses_after_decrypt(
        &mut self,
        peer_signal_hex: &str,
        session_mutex: &Arc<tokio::sync::Mutex<ChatSession>>,
        addr_update: &crate::address::AddressUpdate,
    ) {
        // Note: relay re-subscription is done by the caller AFTER dropping write lock,
        // so that relay WebSocket messages can actually be sent.

        if !addr_update.new_receiving.is_empty() || addr_update.new_sending.is_some() {
            // Persist address state
            let addr_state_opt = {
                let session = session_mutex.lock().await;
                session.addresses.to_serialized(peer_signal_hex)
            };
            if let Some(addr_state) = addr_state_opt {
                if let Ok(store) = self.storage.lock() {
                    if let Err(e) = store.save_peer_addresses(peer_signal_hex, &addr_state) {
                        tracing::error!("persist address state failed: {e}");
                    }
                }
            }

            // Update reverse index
            for addr in &addr_update.new_receiving {
                self.receiving_addr_to_peer
                    .insert(addr.clone(), peer_signal_hex.to_string());
            }
            for addr in &addr_update.dropped_receiving {
                self.receiving_addr_to_peer.remove(addr);
            }
        }
    }

    // ─── Protocol-level send/receive ────────────────────────────

    /// Send an encrypted message to a peer via Signal session.
    ///
    /// Pure protocol: session lookup → encrypt → publish → address index update.
    /// Does NOT write to app_storage, emit DataChange, or track relay status.
    /// Returns `SendResult` for the caller to handle persistence.
    pub async fn send_message_core(
        &mut self,
        peer_pubkey: &str,
        msg: &crate::KCMessage,
    ) -> Result<SendResult> {
        // 1. Check relay connection
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        let connected = transport.connected_relays().await;
        if connected.is_empty() {
            return Err(KeychatError::Transport(
                "Not connected to any relay.".into(),
            ));
        }

        // 2. Resolve peer → signal session
        let signal_hex = self
            .peer_nostr_to_signal
            .get(peer_pubkey)
            .ok_or_else(|| {
                KeychatError::SignalSession(format!(
                    "peer not found: {}",
                    &peer_pubkey[..16.min(peer_pubkey.len())]
                ))
            })?
            .clone();
        let session_mutex = self
            .sessions
            .get(&signal_hex)
            .ok_or_else(|| {
                KeychatError::SignalSession(format!(
                    "no session for signal id: {}",
                    &signal_hex[..16.min(signal_hex.len())]
                ))
            })?
            .clone();

        // 3. Encrypt via Signal session
        let device_id = crate::DeviceId::new(1).expect("device_id 1 is valid");
        let remote_addr = crate::ProtocolAddress::new(signal_hex.clone(), device_id);
        let payload_json = msg.to_json().ok();
        let (event, addr_update) = {
            let mut session = session_mutex.lock().await;
            session.send_message(&signal_hex, &remote_addr, msg).await?
        };

        // 4. Serialize for resend support
        let nostr_event_json = serde_json::to_string(&event).ok();
        let event_id = event.id.to_hex();

        // 5. Publish to relays
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("transport lost".into()))?;
        transport.publish_event_async(event).await?;

        tracing::info!(
            "⬆️ SENT eventId={} to {} relays",
            &event_id[..16.min(event_id.len())],
            connected.len()
        );

        // 6. Update address reverse index
        for addr in &addr_update.new_receiving {
            self.receiving_addr_to_peer
                .insert(addr.clone(), signal_hex.clone());
        }
        for addr in &addr_update.dropped_receiving {
            self.receiving_addr_to_peer.remove(addr);
        }

        Ok(SendResult {
            event_id,
            nostr_event_json,
            payload_json,
            connected_relays: connected,
            addr_update,
        })
    }

    /// Try to decrypt an incoming event as a friend request (Step 1).
    ///
    /// Returns `Some(FriendRequestContext)` if successful, `None` if not a friend request.
    /// Pure protocol: unwraps gift wrap, verifies globalSign, persists to SecureStorage.
    /// Does NOT write to app_storage.
    pub fn try_decrypt_friend_request(&self, event: &crate::Event) -> Option<FriendRequestContext> {
        let identity = self.identity.as_ref()?;

        let received = match crate::receive_friend_request(identity, event) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let request_id = received
            .message
            .id
            .clone()
            .unwrap_or_else(|| format!("fr-{}", event.id.to_hex()));
        let sender_pubkey = received.sender_pubkey_hex.clone();
        let sender_name = received.payload.name.clone();
        let message = received.payload.message.clone();
        let created_at = received.created_at;

        tracing::info!(
            "[Step1] OK: friendRequest from={} name={:?}",
            &sender_pubkey[..16.min(sender_pubkey.len())],
            sender_name
        );

        // Persist inbound FR to SecureStorage
        let message_json = serde_json::to_string(&received.message).ok();
        let payload_json = serde_json::to_string(&received.payload).ok();
        if let (Some(ref mj), Some(ref pj)) = (&message_json, &payload_json) {
            if let Ok(store) = self.storage.lock() {
                let _ = store.save_inbound_fr(&request_id, &sender_pubkey, mj, pj);
            }
        }

        Some(FriendRequestContext {
            request_id,
            sender_pubkey,
            sender_name,
            message,
            created_at,
            event_id: event.id.to_hex(),
            message_json,
            payload_json,
        })
    }

    // ─── Complex decrypt methods (TODO: move full logic from app-core) ──

    /// Try to decrypt an incoming event with pending outbound FR states (Step 2).
    ///
    /// Currently a simplified version that only decrypts. The full session creation
    /// logic (relocate_session, AddressManager setup, persist) remains in keychat-app-core.
    /// TODO: Move the complete try_handle_friend_approve logic here.
    pub fn try_decrypt_pending_outbound(
        &mut self,
        event: &crate::Event,
    ) -> Option<(String, crate::KCMessage, crate::SignalDecryptResult)> {
        let pending_keys: Vec<(String, String)> = self
            .pending_outbound
            .iter()
            .map(|(k, v)| (k.clone(), v.signal_participant.identity_public_key_hex()))
            .collect();

        let device_id = crate::DeviceId::new(1).expect("valid");

        for (request_id, signal_id_hex) in &pending_keys {
            let remote_address = crate::ProtocolAddress::new(signal_id_hex.clone(), device_id);

            let result = if let Some(state) = self.pending_outbound.get_mut(request_id) {
                crate::receive_signal_message(&mut state.signal_participant, &remote_address, event)
            } else {
                continue;
            };

            if let Ok((msg, decrypt_result)) = result {
                return Some((request_id.clone(), msg, decrypt_result));
            }
        }
        None
    }

    /// Try to decrypt an incoming event with existing sessions (Step 3).
    ///
    /// Uses O(1) p-tag routing via receiving_addr_to_peer.
    /// Returns (peer_signal_hex, KCMessage, MessageMetadata, AddressUpdate, session_mutex).
    pub async fn try_decrypt_session_message(
        &self,
        event: &crate::Event,
    ) -> Option<(
        String,
        crate::KCMessage,
        crate::MessageMetadata,
        crate::address::AddressUpdate,
        Arc<tokio::sync::Mutex<crate::ChatSession>>,
    )> {
        let p_tags = crate::extract_p_tags(event);
        let first_p = match p_tags.first() {
            Some(p) => p,
            None => {
                tracing::warn!("Step3: event {} has no p-tag", &event.id.to_hex()[..16]);
                return None;
            }
        };

        let (peer_id, session_arc) = match self.receiving_addr_to_peer.get(first_p) {
            Some(peer_id) => {
                let peer_id = peer_id.clone();
                match self.sessions.get(&peer_id) {
                    Some(session) => (peer_id, session.clone()),
                    None => {
                        tracing::warn!(
                            "Step3: peer {} in index but no session",
                            &peer_id[..16.min(peer_id.len())]
                        );
                        return None;
                    }
                }
            }
            None => {
                tracing::debug!(
                    "Step3: p-tag {} not in receiving_addr_to_peer (have {} addrs), event={}",
                    &first_p[..16.min(first_p.len())],
                    self.receiving_addr_to_peer.len(),
                    &event.id.to_hex()[..16]
                );
                return None;
            }
        };

        let device_id = crate::DeviceId::new(1).expect("valid");
        let remote_address = crate::ProtocolAddress::new(peer_id.clone(), device_id);

        let result = {
            let mut session = session_arc.lock().await;
            session.receive_message(&peer_id, &remote_address, event)
        };

        let (msg, metadata, addr_update) = match result {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "Step3: decrypt failed for peer={}: {e}",
                    &peer_id[..16.min(peer_id.len())]
                );
                return None;
            }
        };

        Some((peer_id, msg, metadata, addr_update, session_arc))
    }

    /// Try to unwrap as NIP-17 DM (Step 4 fallback).
    pub fn try_decrypt_nip17_dm(&self, event: &crate::Event) -> Option<Nip17DmContext> {
        let identity = self.identity.as_ref()?;
        let unwrapped = crate::giftwrap::unwrap_gift_wrap(identity.keys(), event).ok()?;

        Some(Nip17DmContext {
            event_id: event.id.to_hex(),
            sender_pubkey: unwrapped.sender_pubkey.to_hex(),
            content: unwrapped.content.clone(),
            created_at: unwrapped.created_at.as_u64(),
            nostr_event_json: None,
            relay_url: None,
        })
    }

    // ─── Friend Request Protocol ────────────────────────────────

    /// Send a friend request: generate keys → build event → publish → persist → store in memory.
    /// Returns (request_id, peer_nostr_pubkey, event_id_hex).
    pub async fn send_friend_request_protocol(
        &mut self,
        peer_nostr_pubkey: &str,
        my_name: &str,
        device_id_str: &str,
    ) -> Result<(String, String)> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("no identity".into()))?;

        let signal_device_id = self.next_signal_device_id;
        self.next_signal_device_id += 1;

        let keys = crate::generate_prekey_material()?;
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
            crate::serialize_prekey_material(&keys)?;

        let (event, state) = crate::send_friend_request_persistent(
            &identity,
            peer_nostr_pubkey,
            my_name,
            device_id_str,
            keys,
            self.storage.clone(),
            signal_device_id,
        )
        .await?;

        let request_id = state.request_id.clone();
        let first_inbox_secret = state.first_inbox_keys.secret_hex();

        // Persist pending FR to SecureStorage
        if let Ok(store) = self.storage.lock() {
            store.save_pending_fr(
                &request_id,
                signal_device_id,
                &id_pub,
                &id_priv,
                reg_id,
                spk_id,
                &spk_rec,
                pk_id,
                &pk_rec,
                kpk_id,
                &kpk_rec,
                &first_inbox_secret,
                peer_nostr_pubkey,
            )?;
        }

        // Publish
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected".into()))?;
        transport.publish_event_async(event.clone()).await?;

        let event_id_hex = event.id.to_hex();

        // Store in memory
        self.pending_outbound.insert(request_id.clone(), state);

        Ok((request_id, event_id_hex))
    }

    /// Accept a friend request: load FR → generate keys → accept → create session → persist.
    /// Returns (peer_signal_hex, peer_nostr_hex, peer_name, event_id_hex).
    pub async fn accept_friend_request_protocol(
        &mut self,
        request_id: &str,
        my_name: &str,
    ) -> Result<(String, String, String, String)> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("no identity".into()))?;

        // Load inbound FR
        let (sender_pubkey_hex, message_json, payload_json) = {
            let store = self
                .storage
                .lock()
                .map_err(|e| KeychatError::Storage(format!("lock: {e}")))?;
            store.load_inbound_fr(request_id)?.ok_or_else(|| {
                KeychatError::FriendRequest(format!("no inbound FR: {request_id}"))
            })?
        };

        let message: crate::KCMessage = serde_json::from_str(&message_json)?;
        let payload: crate::KCFriendRequestPayload = serde_json::from_str(&payload_json)?;
        let sender_pubkey = crate::PublicKey::from_hex(&sender_pubkey_hex)
            .map_err(|e| KeychatError::FriendRequest(format!("invalid sender pubkey: {e}")))?;

        let received = crate::FriendRequestReceived {
            sender_pubkey,
            sender_pubkey_hex: sender_pubkey_hex.clone(),
            message,
            payload: payload.clone(),
            created_at: 0,
        };

        let signal_device_id = self.next_signal_device_id;
        self.next_signal_device_id += 1;

        let keys = crate::generate_prekey_material()?;
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, _pk_id, _pk_rec, _kpk_id, _kpk_rec) =
            crate::serialize_prekey_material(&keys)?;

        let accepted = crate::accept_friend_request_persistent(
            &identity,
            &received,
            my_name,
            keys,
            self.storage.clone(),
            signal_device_id,
        )
        .await?;

        let peer_signal_hex = payload.signal_identity_key.clone();
        let peer_nostr_hex = sender_pubkey_hex;
        let peer_name = payload.name.clone();

        // Publish
        let event_id_hex = accepted.event.id.to_hex();
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected".into()))?;
        transport.publish_event_async(accepted.event).await?;

        // Create session
        let mut addresses = crate::AddressManager::new();
        addresses.add_peer(
            &peer_signal_hex,
            Some(payload.first_inbox.clone()),
            Some(peer_nostr_hex.clone()),
        );
        if accepted.sender_address.is_some() {
            let _ = addresses.on_encrypt(&peer_signal_hex, accepted.sender_address.as_deref());
        }
        let recv_addrs = addresses.get_all_receiving_address_strings();
        let session = crate::ChatSession::new(accepted.signal_participant, addresses, identity);

        // Persist to SecureStorage
        if let Ok(store) = self.storage.lock() {
            let _ = store.save_signal_participant(
                &peer_signal_hex,
                signal_device_id,
                &id_pub,
                &id_priv,
                reg_id,
                spk_id,
                &spk_rec,
            );
            if let Some(addr_state) = session.addresses.to_serialized(&peer_signal_hex) {
                let _ = store.save_peer_addresses(&peer_signal_hex, &addr_state);
            }
            let _ = store.save_peer_mapping(&peer_nostr_hex, &peer_signal_hex, &peer_name);
            let _ = store.delete_inbound_fr(request_id);
        }

        // Update in-memory state
        self.sessions.insert(
            peer_signal_hex.clone(),
            Arc::new(tokio::sync::Mutex::new(session)),
        );
        self.peer_nostr_to_signal
            .insert(peer_nostr_hex.clone(), peer_signal_hex.clone());
        self.peer_signal_to_nostr
            .insert(peer_signal_hex.clone(), peer_nostr_hex.clone());
        for addr in &recv_addrs {
            self.receiving_addr_to_peer
                .insert(addr.clone(), peer_signal_hex.clone());
        }

        Ok((peer_signal_hex, peer_nostr_hex, peer_name, event_id_hex))
    }

    // ─── Group Protocol ──────────────────────────────────────

    /// Send a message to all members of a Signal group (fan-out encrypt + publish).
    /// Returns (msgid, event_ids, relay_status_json).
    pub async fn send_group_message_protocol(
        &mut self,
        group_id: &str,
        msg: &crate::KCMessage,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let group = self
            .group_manager
            .get_group(group_id)
            .ok_or_else(|| {
                KeychatError::SignalSession(format!(
                    "group not found: {}",
                    &group_id[..16.min(group_id.len())]
                ))
            })?
            .clone();

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected".into()))?;

        let mut event_ids = Vec::new();
        let mut connected_relays = Vec::new();

        // Fan-out encrypt to each other member
        for member in group.other_members() {
            let signal_id = &member.signal_id;
            let session_arc = match self.sessions.get(signal_id) {
                Some(s) => s.clone(),
                None => {
                    tracing::warn!(
                        "group send: no session for member {}",
                        &signal_id[..16.min(signal_id.len())]
                    );
                    continue;
                }
            };
            let mut session = session_arc.lock().await;
            let addr_clone = session.addresses.clone();
            match crate::send_group_message(&mut session.signal, &group, msg, &addr_clone).await {
                Ok(events) => {
                    for (_member_id, event) in events {
                        let eid = event.id.to_hex();
                        transport.publish_event_async(event).await?;
                        event_ids.push(eid);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "group send to {} failed: {e}",
                        &signal_id[..16.min(signal_id.len())]
                    );
                }
            }
        }

        if !event_ids.is_empty() {
            connected_relays = transport.connected_relays().await;
        }

        Ok((event_ids, connected_relays))
    }

    /// Create a Signal group: create group struct, send invites, persist to GroupManager.
    /// Returns (group_id, group_name, member_count).
    pub async fn create_group_protocol(
        &mut self,
        name: &str,
        members: Vec<(String, String)>, // (nostr_pubkey, display_name)
    ) -> Result<(String, String, u32)> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| KeychatError::Identity("no identity".into()))?;
        let my_nostr = identity.pubkey_hex();

        let my_signal_id = if let Some(s) = self.sessions.values().next() {
            s.try_lock()
                .map(|s| s.signal.identity_public_key_hex())
                .unwrap_or_else(|_| my_nostr.clone())
        } else {
            my_nostr.clone()
        };

        // Resolve members to (signal_id, nostr_pubkey, name)
        let mut other_members = Vec::new();
        let mut member_sessions = Vec::new();
        for (nostr_pk, display_name) in &members {
            let signal_id = self
                .peer_nostr_to_signal
                .get(nostr_pk)
                .ok_or_else(|| {
                    KeychatError::SignalSession(format!(
                        "peer not found: {}",
                        &nostr_pk[..16.min(nostr_pk.len())]
                    ))
                })?
                .clone();
            let session = self
                .sessions
                .get(&signal_id)
                .ok_or_else(|| {
                    KeychatError::SignalSession(format!(
                        "no session: {}",
                        &signal_id[..16.min(signal_id.len())]
                    ))
                })?
                .clone();
            other_members.push((signal_id.clone(), nostr_pk.clone(), display_name.clone()));
            member_sessions.push((signal_id, session));
        }

        let group = crate::create_signal_group(name, &my_signal_id, &my_nostr, "Me", other_members);
        let group_id = group.group_id.clone();
        let group_name = group.name.clone();
        let member_count = group.members.len() as u32;

        // Send invite to each member
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected".into()))?;
        for (signal_id, session_arc) in &member_sessions {
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            let event =
                crate::send_group_invite(&mut session.signal, &group, signal_id, &addr).await?;
            let _ = transport.publish_event_async(event).await;
        }

        // Store in GroupManager + persist
        let gid = group.group_id.clone();
        self.group_manager.add_group(group);
        if let Ok(store) = self.storage.lock() {
            let _ = self.group_manager.save_group(&gid, &store);
        }

        Ok((group_id, group_name, member_count))
    }

    /// Send an admin message to all other group members (encrypt + publish).
    pub async fn send_admin_to_all_protocol(
        &self,
        group: &crate::SignalGroup,
        msg: &crate::KCMessage,
    ) -> Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected".into()))?;

        for member in group.other_members() {
            let signal_id = match self.peer_nostr_to_signal.get(&member.nostr_pubkey) {
                Some(s) => s.clone(),
                None => continue,
            };
            let session_arc = match self.sessions.get(&signal_id) {
                Some(s) => s.clone(),
                None => continue,
            };
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            match crate::encrypt_for_group_member(&mut session.signal, &signal_id, msg, &addr).await
            {
                Ok(event) => {
                    let _ = transport.publish_event_async(event).await;
                }
                Err(e) => {
                    tracing::warn!(
                        "admin send to {} failed: {e}",
                        &signal_id[..16.min(signal_id.len())]
                    );
                }
            }
        }
        Ok(())
    }

    /// Leave a group: send self-leave msg + remove from manager.
    pub async fn leave_group_protocol(&mut self, group_id: &str) -> Result<()> {
        let group = self
            .group_manager
            .get_group(group_id)
            .ok_or_else(|| KeychatError::SignalSession(format!("group not found: {group_id}")))?
            .clone();
        let payload = serde_json::json!({ "action": "selfLeave", "memberId": group.my_signal_id });
        let msg = crate::build_group_admin_message(
            crate::KCMessageKind::SignalGroupSelfLeave,
            &group,
            payload,
        );
        self.send_admin_to_all_protocol(&group, &msg).await?;
        if let Ok(store) = self.storage.lock() {
            let _ = self.group_manager.remove_group_persistent(group_id, &store);
        } else {
            self.group_manager.remove_group(group_id);
        }
        Ok(())
    }

    /// Dissolve a group: send dissolve msg + remove from manager.
    pub async fn dissolve_group_protocol(&mut self, group_id: &str) -> Result<()> {
        let group = self
            .group_manager
            .get_group(group_id)
            .ok_or_else(|| KeychatError::SignalSession(format!("group not found: {group_id}")))?
            .clone();
        let payload = serde_json::json!({ "action": "dissolve" });
        let msg = crate::build_group_admin_message(
            crate::KCMessageKind::SignalGroupDissolve,
            &group,
            payload,
        );
        self.send_admin_to_all_protocol(&group, &msg).await?;
        if let Ok(store) = self.storage.lock() {
            let _ = self.group_manager.remove_group_persistent(group_id, &store);
        } else {
            self.group_manager.remove_group(group_id);
        }
        Ok(())
    }

    /// Remove a member from a group: send removal msg + update group.
    pub async fn remove_member_protocol(
        &mut self,
        group_id: &str,
        member_nostr_pubkey: &str,
    ) -> Result<()> {
        let group = self
            .group_manager
            .get_group(group_id)
            .ok_or_else(|| KeychatError::SignalSession(format!("group not found: {group_id}")))?
            .clone();
        let removed_signal_id = self
            .peer_nostr_to_signal
            .get(member_nostr_pubkey)
            .ok_or_else(|| {
                KeychatError::SignalSession(format!("peer not found: {member_nostr_pubkey}"))
            })?
            .clone();
        let payload =
            serde_json::json!({ "action": "memberRemoved", "memberId": removed_signal_id });
        let msg = crate::build_group_admin_message(
            crate::KCMessageKind::SignalGroupMemberRemoved,
            &group,
            payload,
        );
        self.send_admin_to_all_protocol(&group, &msg).await?;
        if let Some(g) = self.group_manager.get_group_mut(group_id) {
            g.remove_member(&removed_signal_id);
        }
        if let Ok(store) = self.storage.lock() {
            let _ = self.group_manager.save_group(group_id, &store);
        }
        Ok(())
    }

    /// Rename a group: send name-changed msg + update group.
    pub async fn rename_group_protocol(&mut self, group_id: &str, new_name: &str) -> Result<()> {
        let group = self
            .group_manager
            .get_group(group_id)
            .ok_or_else(|| KeychatError::SignalSession(format!("group not found: {group_id}")))?
            .clone();
        let payload = serde_json::json!({ "action": "nameChanged", "newName": new_name });
        let msg = crate::build_group_admin_message(
            crate::KCMessageKind::SignalGroupNameChanged,
            &group,
            payload,
        );
        self.send_admin_to_all_protocol(&group, &msg).await?;
        if let Some(g) = self.group_manager.get_group_mut(group_id) {
            g.name = new_name.to_string();
        }
        Ok(())
    }

    /// Complete friend approve: create ChatSession, update peer mappings, persist.
    ///
    /// Called after try_decrypt_pending_outbound returns a FriendApprove message.
    /// Extracts the pending state, creates the Signal session, and updates all indexes.
    pub async fn complete_friend_approve(
        &mut self,
        request_id: &str,
        msg: &crate::KCMessage,
        decrypt_result: &crate::SignalDecryptResult,
    ) -> Result<(String, String, String)> {
        // Extract peer info from signal_prekey_auth
        let peer_name = msg
            .signal_prekey_auth
            .as_ref()
            .map(|a| a.name.clone())
            .unwrap_or_default();
        let peer_signal_id = msg
            .signal_prekey_auth
            .as_ref()
            .map(|a| a.signal_id.clone())
            .unwrap_or_default();
        let peer_nostr_id = msg
            .signal_prekey_auth
            .as_ref()
            .map(|a| a.nostr_id.clone())
            .unwrap_or_else(|| {
                self.pending_outbound
                    .get(request_id)
                    .map(|s| s.peer_nostr_pubkey.clone())
                    .unwrap_or_default()
            });

        let peer_signal_hex = if peer_signal_id.is_empty() {
            peer_nostr_id.clone()
        } else {
            peer_signal_id
        };

        // Take the state out of pending_outbound
        let mut state = self.pending_outbound.remove(request_id).ok_or_else(|| {
            KeychatError::FriendRequest(format!("pending state not found for {request_id}"))
        })?;

        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("no identity".into()))?;

        let device_id = crate::DeviceId::new(1).expect("valid");

        // Relocate session if peer signal key differs from our decrypt address
        let our_signal_hex = state.signal_participant.identity_public_key_hex();
        if peer_signal_hex != our_signal_hex {
            let from_addr = crate::ProtocolAddress::new(our_signal_hex.clone(), device_id);
            let to_addr = crate::ProtocolAddress::new(peer_signal_hex.clone(), device_id);
            if let Err(e) = state
                .signal_participant
                .relocate_session(&from_addr, &to_addr)
            {
                tracing::warn!("relocate_session failed: {e}");
            }
        }

        // Create AddressManager + ChatSession
        let mut addresses = crate::AddressManager::new();
        addresses.add_peer(&peer_signal_hex, None, Some(peer_nostr_id.clone()));

        // Process decrypt result to register ratchet-derived addresses
        if let Some(bob_addr) = decrypt_result.bob_derived_address.as_deref() {
            match addresses.on_decrypt(
                &peer_signal_hex,
                Some(bob_addr),
                decrypt_result.alice_addrs.as_deref(),
            ) {
                Ok(_update) => {}
                Err(e) => {
                    tracing::warn!("complete_friend_approve: on_decrypt failed: {e}");
                }
            }
        }

        let recv_addrs = addresses.get_all_receiving_address_strings();
        let session = crate::ChatSession::new(state.signal_participant, addresses, identity);

        // Persist to SecureStorage
        if let Ok(store) = self.storage.lock() {
            // Save signal participant identity (pub + priv key for restore_sessions)
            let id_pub = session
                .signal
                .identity_key_pair()
                .identity_key()
                .serialize()
                .to_vec();
            let id_priv = session
                .signal
                .identity_key_pair()
                .private_key()
                .serialize()
                .to_vec();
            let _ = store.save_signal_participant(
                &peer_signal_hex,
                u32::from(session.signal.address().device_id()),
                &id_pub,
                &id_priv,
                session.signal.registration_id(),
                0,
                &[],
            );

            // Save peer address state
            if let Some(addr_state) = session.addresses.to_serialized(&peer_signal_hex) {
                let _ = store.save_peer_addresses(&peer_signal_hex, &addr_state);
            }

            // Save peer mapping
            let _ = store.save_peer_mapping(&peer_nostr_id, &peer_signal_hex, &peer_name);

            // Delete the pending FR
            let _ = store.delete_pending_fr(request_id);
        }

        // Update in-memory state
        self.sessions.insert(
            peer_signal_hex.clone(),
            Arc::new(tokio::sync::Mutex::new(session)),
        );
        self.peer_nostr_to_signal
            .insert(peer_nostr_id.clone(), peer_signal_hex.clone());
        self.peer_signal_to_nostr
            .insert(peer_signal_hex.clone(), peer_nostr_id.clone());
        for addr in &recv_addrs {
            self.receiving_addr_to_peer
                .insert(addr.clone(), peer_signal_hex.clone());
        }

        tracing::info!(
            "[complete_friend_approve] session created: signal={} nostr={}",
            &peer_signal_hex[..16.min(peer_signal_hex.len())],
            &peer_nostr_id[..16.min(peer_nostr_id.len())]
        );

        Ok((peer_signal_hex, peer_nostr_id, peer_name))
    }

    /// Reject a friend request: delete from SecureStorage.
    pub fn reject_friend_request_protocol(&self, request_id: &str) -> Result<String> {
        let store = self
            .storage
            .lock()
            .map_err(|e| KeychatError::Storage(format!("lock: {e}")))?;
        let sender = store
            .load_inbound_fr(request_id)?
            .map(|(pubkey, _, _)| pubkey)
            .unwrap_or_default();
        store.delete_inbound_fr(request_id)?;
        Ok(sender)
    }

    // ─── Event Loop Core ────────────────────────────────────────

    /// Run the protocol event loop.
    ///
    /// Receives GiftWrap events from relay, deduplicates, attempts decryption
    /// in priority order (friend request → approve → session → NIP-17 DM),
    /// and notifies the delegate for app-layer persistence.
    ///
    /// Pure protocol: does NOT touch app_storage. All persistence happens
    /// through the `OrchestratorDelegate` callbacks.
    pub async fn run_event_loop(
        client: Arc<tokio::sync::RwLock<Self>>,
        delegate: Arc<dyn OrchestratorDelegate>,
        mut stop_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        // Get nostr client handle
        let nostr_client = {
            let inner = client.read().await;
            match inner.transport.as_ref() {
                Some(t) => t.client().clone(),
                None => {
                    delegate.on_error("transport not initialized".into()).await;
                    return;
                }
            }
        };

        let mut notifications = nostr_client.notifications();

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    tracing::info!("protocol event loop: stop signal received");
                    break;
                }
                result = notifications.recv() => {
                    match result {
                        Ok(crate::RelayPoolNotification::Event { relay_url, event, .. }) => {
                            let eid = event.id.to_hex();

                            // Deduplicate
                            let deduped = {
                                let inner = client.read().await;
                                match inner.transport.as_ref() {
                                    Some(t) => t.deduplicate((*event).clone()).await,
                                    None => None,
                                }
                            };

                            if let Some(event) = deduped {
                                if event.kind == crate::Kind::GiftWrap {
                                    tracing::info!(
                                        "⬇️ RECV kind={} id={} from={}",
                                        event.kind.as_u16(),
                                        &eid[..16.min(eid.len())],
                                        relay_url
                                    );
                                    let relay = relay_url.to_string();
                                    let nostr_event_json = serde_json::to_string(&event).ok();

                                    // Update relay cursor
                                    let event_ts = event.created_at.as_u64();
                                    let cursor_storage = client.read().await.storage.clone();
                                    if let Ok(store) = cursor_storage.lock() {
                                        let _ = store.update_relay_cursor(&relay, event_ts);
                                    }

                                    // Step 1: Try friend request
                                    {
                                        let inner = client.read().await;
                                        if let Some(ctx) = inner.try_decrypt_friend_request(&event) {
                                            delegate.on_friend_request_received(ctx).await;
                                            continue;
                                        }
                                    }

                                    // Step 2: Try friend approve/reject
                                    {
                                        let mut inner = client.write().await;
                                        if let Some((request_id, msg, decrypt_result)) = inner.try_decrypt_pending_outbound(&event) {
                                            if msg.kind == crate::KCMessageKind::FriendApprove {
                                                // Create session + update mappings + persist
                                                match inner.complete_friend_approve(&request_id, &msg, &decrypt_result).await {
                                                    Ok((peer_signal_hex, peer_nostr_id, peer_name)) => {
                                                        // Re-subscribe to new ratchet addresses
                                                        let _ = inner.refresh_subscriptions().await;
                                                        drop(inner);
                                                        delegate.on_friend_approved(FriendApprovedContext {
                                                            request_id,
                                                            peer_nostr_pubkey: peer_nostr_id,
                                                            peer_name,
                                                            peer_signal_id_hex: peer_signal_hex,
                                                            event_id: event.id.to_hex(),
                                                        }).await;
                                                    }
                                                    Err(e) => {
                                                        tracing::error!("complete_friend_approve failed: {e}");
                                                        drop(inner);
                                                    }
                                                }
                                            } else if msg.kind == crate::KCMessageKind::FriendReject {
                                                let peer_pubkey = inner.pending_outbound.get(&request_id)
                                                    .map(|s| s.peer_nostr_pubkey.clone())
                                                    .unwrap_or_default();
                                                inner.pending_outbound.remove(&request_id);
                                                drop(inner);
                                                delegate.on_friend_rejected(FriendRejectedContext {
                                                    request_id,
                                                    peer_pubkey,
                                                }).await;
                                            }
                                            continue;
                                        }
                                    }

                                    // Step 3: Try session message
                                    // Need to drop read lock before async session decrypt
                                    let step3_result = {
                                        let inner = client.read().await;
                                        inner.try_decrypt_session_message(&event).await
                                    };
                                    if let Some((peer_signal_hex, msg, metadata, addr_update, session_mutex)) = step3_result
                                    {
                                        // Update addresses
                                        {
                                            let mut inner_w = client.write().await;
                                            inner_w.update_addresses_after_decrypt(
                                                &peer_signal_hex, &session_mutex, &addr_update,
                                            ).await;
                                        }

                                            // Resolve sender nostr pubkey
                                            let sender_nostr_pubkey = {
                                                let inner = client.read().await;
                                                inner.peer_signal_to_nostr
                                                    .get(&peer_signal_hex)
                                                    .cloned()
                                                    .unwrap_or_else(|| peer_signal_hex.clone())
                                            };

                                            let kind = msg.kind.clone();
                                            let content = msg.text.as_ref().map(|t| t.content.clone());
                                            let payload_json = msg.to_json().ok();
                                            let group_id = msg.group_id.clone();
                                            let thread_id = msg.thread_id.clone();
                                            let fallback = msg.fallback.clone();
                                            let reply_to_event_id = msg.reply_to.as_ref()
                                                .and_then(|r| r.target_event_id.clone());

                                            delegate.on_message_received(MessageReceivedContext {
                                                event_id: metadata.event_id.to_hex(),
                                                sender_pubkey: sender_nostr_pubkey,
                                                kind,
                                                content,
                                                payload_json,
                                                nostr_event_json: nostr_event_json.clone(),
                                                fallback,
                                                reply_to_event_id,
                                                group_id,
                                                thread_id,
                                                relay_url: Some(relay.clone()),
                                                created_at: event.created_at.as_u64(),
                                            }).await;
                                            continue;
                                        }

                                    // Step 4: Try NIP-17 DM fallback
                                    {
                                        let inner = client.read().await;
                                        if let Some(mut ctx) = inner.try_decrypt_nip17_dm(&event) {
                                            ctx.nostr_event_json = nostr_event_json;
                                            ctx.relay_url = Some(relay);
                                            delegate.on_nip17_dm_received(ctx).await;
                                            continue;
                                        }
                                    }
                                }
                            } else {
                                tracing::debug!("⬇️ DUP id={}", &eid[..16.min(eid.len())]);
                            }
                        }
                        Ok(crate::RelayPoolNotification::Message { relay_url, message }) => {
                            if let crate::RelayMessage::Ok { event_id, status, message: msg } = message {
                                delegate.on_relay_ok(
                                    event_id.to_hex(),
                                    relay_url.to_string(),
                                    status,
                                    msg,
                                ).await;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!("event loop notification error: {e}");
                            delegate.on_error(format!("notification error: {e}")).await;
                            break;
                        }
                    }
                }
            }
        }
        tracing::info!("protocol event loop exited");
    }
}
