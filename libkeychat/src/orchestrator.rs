//! Protocol orchestration layer.
//!
//! Provides `ProtocolClient` for multi-session management, session decryption,
//! and address routing. Callers (currently `keychat-app-core`) drive the event
//! loop themselves and use the `try_decrypt_*` methods plus per-event context
//! structs to integrate with their own persistence layer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::address::AddressManager;
use crate::error::{KeychatError, Result};
use crate::friend_request::FriendRequestState;
use crate::group::GroupManager;
use crate::identity::Identity;
use crate::session::ChatSession;
use crate::storage::SecureStorage;
use crate::transport::Transport;

/// `protocol_settings` key for the self Public Agent flag (spec §3.6).
const SELF_PUBLIC_AGENT_KEY: &str = "self_is_public_agent";

// ─── Context Structs ────────────────────────────────────────────
// Pure data returned by the `try_decrypt_*` methods. No app_storage,
// no UI types, no UniFFI annotations.

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
    identity: Option<Identity>,
    transport: Option<Transport>,
    storage: Arc<Mutex<SecureStorage>>,
    sessions: HashMap<String, Arc<tokio::sync::Mutex<ChatSession>>>,
    peer_nostr_to_signal: HashMap<String, String>,
    peer_signal_to_nostr: HashMap<String, String>,
    receiving_addr_to_peer: HashMap<String, String>,
    /// In-memory index of peers flagged as Public Agents (spec §3.6).
    /// Keyed by peer signal identity hex for O(1) lookup on the send path.
    /// Kept in sync with `peer_mappings.is_public_agent` in storage.
    peer_is_public_agent: HashMap<String, bool>,
    /// Whether this client runs in Public Agent mode (spec §3.6). When `true`:
    /// - relay subscription collapses to own npub (plus legacy peer fallback),
    /// - `friendApprove` messages carry `publicAgent: true`,
    /// - peers observed sending dual p-tag events get marked as upgraded.
    /// Persisted in `protocol_settings["self_is_public_agent"]`.
    self_is_public_agent: bool,
    /// In-memory index of peers that have sent us dual p-tag events (spec
    /// §3.6 backward compatibility). Keyed by signal identity hex. Only
    /// consulted when `self_is_public_agent == true` to skip upgraded peers'
    /// ratchet addresses in the subscription filter.
    peer_uses_dual_p_tag: HashMap<String, bool>,
    pending_outbound: HashMap<String, FriendRequestState>,
    /// Per-peer first_inbox pubkeys that must remain subscribed and
    /// routable after friend-approve completes (spec §8.3 / line 250).
    /// After `complete_friend_approve` removes `pending_outbound` entry,
    /// the peer may still send follow-up messages to our first_inbox
    /// until their ratchet advances. Keyed by peer_signal_hex → our
    /// first_inbox pubkey hex. Cleared on first successful session decrypt.
    peer_pending_first_inbox: HashMap<String, String>,
    group_manager: GroupManager,
    next_signal_device_id: u32,
    subscription_ids: Vec<String>,
    last_relay_urls: Vec<String>,
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
            peer_is_public_agent: HashMap::new(),
            self_is_public_agent: false,
            peer_uses_dual_p_tag: HashMap::new(),
            pending_outbound: HashMap::new(),
            peer_pending_first_inbox: HashMap::new(),
            group_manager: GroupManager::new(),
            next_signal_device_id: 1,
            subscription_ids: Vec::new(),
            last_relay_urls: Vec::new(),
        }
    }

    // ─── Accessors ───────────────────────────────────────────────

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }
    pub fn set_identity(&mut self, identity: Option<Identity>) {
        self.identity = identity;
    }

    pub fn transport(&self) -> Option<&Transport> {
        self.transport.as_ref()
    }
    pub fn has_transport(&self) -> bool {
        self.transport.is_some()
    }
    pub fn set_transport(&mut self, transport: Transport) {
        self.transport = Some(transport);
    }
    pub fn take_transport(&mut self) -> Option<Transport> {
        self.transport.take()
    }

    pub fn storage(&self) -> &Arc<Mutex<SecureStorage>> {
        &self.storage
    }

    pub fn get_session(&self, signal_id: &str) -> Option<Arc<tokio::sync::Mutex<ChatSession>>> {
        self.sessions.get(signal_id).cloned()
    }
    pub fn first_session(&self) -> Option<Arc<tokio::sync::Mutex<ChatSession>>> {
        self.sessions.values().next().cloned()
    }
    pub fn all_session_arcs(&self) -> Vec<Arc<tokio::sync::Mutex<ChatSession>>> {
        self.sessions.values().cloned().collect()
    }
    pub fn sessions_len(&self) -> usize {
        self.sessions.len()
    }

    pub fn nostr_to_signal(&self, nostr_pk: &str) -> Option<&String> {
        self.peer_nostr_to_signal.get(nostr_pk)
    }
    pub fn signal_to_nostr(&self, signal_id: &str) -> Option<&String> {
        self.peer_signal_to_nostr.get(signal_id)
    }
    pub fn peer_count(&self) -> usize {
        self.peer_nostr_to_signal.len()
    }
    pub fn receiving_addr_count(&self) -> usize {
        self.receiving_addr_to_peer.len()
    }
    pub fn pending_outbound_len(&self) -> usize {
        self.pending_outbound.len()
    }
    pub fn get_pending_outbound(&self, id: &str) -> Option<&FriendRequestState> {
        self.pending_outbound.get(id)
    }
    pub fn remove_pending_outbound(&mut self, id: &str) -> Option<FriendRequestState> {
        self.pending_outbound.remove(id)
    }

    pub fn group_manager(&self) -> &GroupManager {
        &self.group_manager
    }
    pub fn group_manager_mut(&mut self) -> &mut GroupManager {
        &mut self.group_manager
    }

    pub fn subscription_ids(&self) -> &[String] {
        &self.subscription_ids
    }
    pub fn subscription_ids_mut(&mut self) -> &mut Vec<String> {
        &mut self.subscription_ids
    }
    pub fn last_relay_urls(&self) -> &[String] {
        &self.last_relay_urls
    }
    pub fn set_last_relay_urls(&mut self, urls: Vec<String>) {
        self.last_relay_urls = urls;
    }

    /// Remove a peer from all in-memory indexes (sessions, both peer maps, receiving addresses).
    /// Returns the signal ID if found.
    pub fn remove_peer(&mut self, nostr_pk: &str) -> Option<String> {
        if let Some(signal_id) = self.peer_nostr_to_signal.remove(nostr_pk) {
            self.peer_signal_to_nostr.remove(&signal_id);
            self.sessions.remove(&signal_id);
            self.receiving_addr_to_peer.retain(|_, v| v != &signal_id);
            self.peer_is_public_agent.remove(&signal_id);
            self.peer_uses_dual_p_tag.remove(&signal_id);
            self.pending_outbound
                .retain(|_, s| s.peer_nostr_pubkey != nostr_pk);
            Some(signal_id)
        } else {
            None
        }
    }

    /// Reset all in-memory state (identity, transport, sessions, peer maps, groups, subscriptions).
    /// Does NOT clear storage — call storage.delete_all_data() separately.
    pub fn reset(&mut self) {
        self.identity = None;
        self.transport = None;
        self.sessions.clear();
        self.peer_nostr_to_signal.clear();
        self.peer_signal_to_nostr.clear();
        self.receiving_addr_to_peer.clear();
        self.peer_is_public_agent.clear();
        self.self_is_public_agent = false;
        self.peer_uses_dual_p_tag.clear();
        self.pending_outbound.clear();
        self.group_manager = GroupManager::new();
        self.next_signal_device_id = 1;
        self.subscription_ids.clear();
        self.last_relay_urls.clear();
    }

    // ─── Session Restore ────────────────────────────────────────

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

        // Snapshot self Public Agent mode while we still hold the lock.
        let self_is_public_agent = store
            .get_setting(SELF_PUBLIC_AGENT_KEY)
            .ok()
            .flatten()
            .map(|v| v == "1")
            .unwrap_or(false);

        // Drop the Mutex guard so restore_persistent can lock it
        drop(store);

        // ── Phase 2: Reconstruct objects (may lock storage internally) ──

        // 1. Restore peer mappings
        for peer in &peers {
            self.peer_nostr_to_signal
                .insert(peer.nostr_pubkey.clone(), peer.signal_id.clone());
            self.peer_signal_to_nostr
                .insert(peer.signal_id.clone(), peer.nostr_pubkey.clone());
            if peer.is_public_agent {
                self.peer_is_public_agent
                    .insert(peer.signal_id.clone(), true);
            }
            if peer.peer_uses_dual_p_tag {
                self.peer_uses_dual_p_tag
                    .insert(peer.signal_id.clone(), true);
            }
        }
        if !peers.is_empty() {
            tracing::info!(
                "restored {} peer mappings ({} Public Agent peers, {} upgraded for dual p-tag)",
                peers.len(),
                self.peer_is_public_agent.len(),
                self.peer_uses_dual_p_tag.len()
            );
        }

        // Restore self Public Agent mode flag (spec §3.6).
        self.self_is_public_agent = self_is_public_agent;
        if self.self_is_public_agent {
            tracing::info!(
                "restored self_is_public_agent = true; relay subscription will collapse to own npub"
            );
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

    /// Reconnect a specific relay.
    pub async fn reconnect_relay(&self, url: &str) -> Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected to any relay.".into()))?;
        transport.reconnect_relay(url).await?;
        tracing::info!("reconnected relay: {url}");
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
        // Spec §8.3: after friend-approve, keep our first_inbox subscribed
        // so the peer's follow-up messages arrive until their ratchet takes
        // over. Cleared on first session decrypt.
        for fi_hex in self.peer_pending_first_inbox.values() {
            if let Ok(pk) = nostr::PublicKey::from_hex(fi_hex) {
                identity_pubkeys.push(pk);
            }
        }

        // Ratchet keys: newly derived Signal addresses, no historical messages.
        //
        // Public Agent mode (spec §3.6): when we run as an agent, peers that
        // have upgraded to dual p-tag no longer need a ratchet-address
        // fallback subscription (they'll reach us via our own npub). Legacy
        // peers keep their ratchet addresses until they upgrade.
        let mut ratchet_pubkeys = Vec::new();
        for (signal_hex, session_mutex) in &self.sessions {
            if self.self_is_public_agent
                && *self.peer_uses_dual_p_tag.get(signal_hex).unwrap_or(&false)
            {
                continue;
            }
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

    // ─── Public Agent Mode (spec §3.6) ───────────────────────────

    /// Whether this client is running in Public Agent mode.
    pub fn is_self_public_agent(&self) -> bool {
        self.self_is_public_agent
    }

    /// Whether the given peer is flagged as a Public Agent (learned from
    /// `friendApprove.publicAgent`). Allows callers to observe the flag
    /// without going through the send path.
    pub fn is_peer_public_agent(&self, peer_nostr_pk: &str) -> bool {
        match self.peer_nostr_to_signal.get(peer_nostr_pk) {
            Some(sig) => *self.peer_is_public_agent.get(sig).unwrap_or(&false),
            None => false,
        }
    }

    /// Whether the given peer has been observed sending dual p-tag events.
    /// Only meaningful when this client runs in Public Agent mode.
    pub fn is_peer_upgraded_to_dual_tag(&self, peer_nostr_pk: &str) -> bool {
        match self.peer_nostr_to_signal.get(peer_nostr_pk) {
            Some(sig) => *self.peer_uses_dual_p_tag.get(sig).unwrap_or(&false),
            None => false,
        }
    }

    /// Enable or disable Public Agent mode for this client (spec §3.6).
    ///
    /// When enabled:
    /// - Subsequent `friendApprove` messages carry `publicAgent: true`.
    /// - Relay subscription drops ratchet addresses of peers that have
    ///   upgraded to dual p-tag (see `mark_peer_upgraded_if_dual_tag`).
    /// - Legacy peers keep their ratchet-address fallback subscription.
    ///
    /// Persisted in `protocol_settings`. Callers SHOULD invoke
    /// `refresh_subscriptions()` after toggling to apply the change to the
    /// live relay filter.
    pub fn set_self_public_agent(&mut self, flag: bool) -> Result<()> {
        if let Ok(store) = self.storage.lock() {
            store.set_setting(SELF_PUBLIC_AGENT_KEY, if flag { "1" } else { "0" })?;
        }
        self.self_is_public_agent = flag;
        tracing::info!(
            "self_is_public_agent set to {}; call refresh_subscriptions() to update the filter",
            flag
        );
        Ok(())
    }

    /// Mark a peer as having upgraded to dual p-tag (spec §3.6).
    ///
    /// Called by the event loop after decrypting a session message. The peer
    /// is considered "upgraded" if the event carried two or more `p`-tags AND
    /// one of them matches our own identity pubkey — i.e., the peer is
    /// addressing us as a Public Agent.
    ///
    /// Only has an effect when `self_is_public_agent == true`, because the
    /// flag is only used to shrink the relay subscription in that mode.
    /// Returns `true` if the state transitioned from false to true (caller
    /// should refresh subscriptions in that case).
    pub fn mark_peer_upgraded_if_dual_tag(
        &mut self,
        peer_signal_hex: &str,
        p_tags: &[String],
    ) -> bool {
        if !self.self_is_public_agent {
            return false;
        }
        let identity_hex = match self.identity.as_ref() {
            Some(id) => id.pubkey_hex(),
            None => return false,
        };
        let is_dual = p_tags.len() >= 2 && p_tags.iter().any(|t| t == &identity_hex);
        if !is_dual {
            return false;
        }
        if *self
            .peer_uses_dual_p_tag
            .get(peer_signal_hex)
            .unwrap_or(&false)
        {
            return false; // already marked
        }

        // Persist (best-effort) keyed by nostr pubkey.
        if let Some(nostr_pk) = self.peer_signal_to_nostr.get(peer_signal_hex).cloned() {
            if let Ok(store) = self.storage.lock() {
                if let Err(e) = store.set_peer_uses_dual_p_tag(&nostr_pk, true) {
                    tracing::warn!("mark_peer_upgraded: persist failed: {e}");
                }
            }
        }
        self.peer_uses_dual_p_tag
            .insert(peer_signal_hex.to_string(), true);
        tracing::info!(
            "peer {} upgraded to dual p-tag; ratchet fallback subscription will be dropped on next refresh",
            &peer_signal_hex[..16.min(peer_signal_hex.len())]
        );
        true
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

    /// Spec §8.3: once we receive on a ratchet-derived address, the peer's
    /// ratchet is live and our first_inbox is no longer needed. Drops both
    /// the `peer_pending_first_inbox` entry and its receiving_addr_to_peer
    /// mapping. No-op if the message was received on our first_inbox itself
    /// (peer hasn't seen a ratchet-derived addr from us yet).
    pub fn clear_pending_first_inbox_on_ratchet(
        &mut self,
        peer_signal_hex: &str,
        received_on_addr: &str,
    ) {
        let should_clear = match self.peer_pending_first_inbox.get(peer_signal_hex) {
            Some(fi) => fi != received_on_addr,
            None => false,
        };
        if should_clear {
            if let Some(fi) = self.peer_pending_first_inbox.remove(peer_signal_hex) {
                self.receiving_addr_to_peer.remove(&fi);
                tracing::debug!(
                    "cleared pending first_inbox for peer={} (ratchet active)",
                    &peer_signal_hex[..16.min(peer_signal_hex.len())]
                );
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

        // Public Agent routing (spec §3.6): when the peer is flagged as a
        // Public Agent, emit a second p-tag carrying the peer's Nostr npub so
        // the agent can subscribe only to its own identity address.
        let agent_npub = if *self.peer_is_public_agent.get(&signal_hex).unwrap_or(&false) {
            Some(peer_pubkey.to_string())
        } else {
            None
        };

        let (event, addr_update) = {
            let mut session = session_mutex.lock().await;
            session
                .send_message(&signal_hex, &remote_addr, msg, agent_npub.as_deref())
                .await?
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

    // ─── Bundle (offline / QR) flow (spec §6.5) ──────────────────
    //
    // Protocol-equivalent to the Gift Wrap path, but the FR payload is
    // carried out-of-band (QR code, shared string, etc) instead of via
    // NIP-17. The initiator prepares the payload + firstInbox and waits on
    // the same `pending_outbound` state as the online FR path; the receiver
    // runs the same `accept_friend_request_persistent` logic.
    //
    // Unlike the Gift Wrap path, `export_bundle` does NOT publish anything
    // to relays — the returned JSON must be conveyed out-of-band by the
    // caller. Nothing else about the session model differs.

    /// Prepare a bundle to share out-of-band, and persist the matching
    /// `pending_outbound` state so the eventual PreKey reply decrypts.
    ///
    /// Returns the JSON bundle string. Caller is responsible for the
    /// out-of-band transfer (QR encode, copy-paste, etc.).
    pub async fn export_bundle_protocol(
        &mut self,
        my_name: &str,
        device_id_str: &str,
    ) -> Result<String> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("no identity".into()))?;

        let signal_device_id = self.next_signal_device_id;
        self.next_signal_device_id += 1;

        let keys = crate::generate_prekey_material()?;
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec) =
            crate::serialize_prekey_material(&keys)?;

        // Build a persistent SignalParticipant so OPK/SPK/Kyber are written
        // to SecureStorage and libsignal can find them when Alice's PreKey
        // arrives.
        let signal_participant = crate::SignalParticipant::persistent(
            identity.pubkey_hex(),
            signal_device_id,
            keys,
            self.storage.clone(),
        )?;

        let first_inbox_keys = crate::EphemeralKeypair::generate();
        let first_inbox_hex = first_inbox_keys.pubkey_hex();

        let payload = crate::friend_request::build_friend_request_payload(
            &identity,
            my_name,
            device_id_str,
            &signal_participant,
            &first_inbox_hex,
        )?;

        // The request_id mirrors `parse_bundle_as_friend_request`'s naming so
        // a bundle exported here and consumed by the peer share the same id.
        let time = payload.time.unwrap_or_default();
        let request_id = format!("bundle-{}", time);
        let first_inbox_secret = first_inbox_keys.secret_hex();
        let peer_nostr_placeholder = String::new(); // filled when PreKey arrives

        // Persist pending FR to SecureStorage so that a restart can still
        // decrypt the eventual reply (same contract as send_friend_request_protocol).
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
                &peer_nostr_placeholder,
            )?;
        }

        // In-memory pending state — identical shape to online FR path so the
        // Step 2 decrypt loop treats it the same way.
        self.pending_outbound.insert(
            request_id.clone(),
            crate::FriendRequestState {
                signal_participant,
                first_inbox_keys,
                request_id: request_id.clone(),
                peer_nostr_pubkey: peer_nostr_placeholder,
            },
        );

        // Refresh subscriptions so firstInbox is actually listened on before
        // the peer (Alice) could send us anything. If not yet connected, skip
        // silently — `collect_subscribe_pubkeys` will pick up the pending
        // firstInbox at connect time via the shared pending_outbound map.
        if self.transport.is_some() {
            self.refresh_subscriptions().await?;
        }

        let json = serde_json::to_string(&payload)
            .map_err(|e| KeychatError::Signal(format!("bundle serialize: {e}")))?;
        tracing::info!(
            "[bundle] exported request_id={} firstInbox={}",
            &request_id,
            &first_inbox_hex[..16.min(first_inbox_hex.len())]
        );
        Ok(json)
    }

    /// Consume a peer's bundle (offline-delivered `KCFriendRequestPayload`)
    /// and establish a session: runs the same accept path as an online FR.
    /// Returns (peer_signal_hex, peer_nostr_hex, peer_name, event_id_hex).
    pub async fn add_contact_via_bundle_protocol(
        &mut self,
        bundle_json: &str,
        my_name: &str,
    ) -> Result<(String, String, String, String)> {
        let identity = self
            .identity
            .clone()
            .ok_or_else(|| KeychatError::Identity("no identity".into()))?;

        let received = crate::friend_request::parse_bundle_as_friend_request(bundle_json)?;

        // Reject a bundle that claims to be from ourselves.
        if received.sender_pubkey_hex == identity.pubkey_hex() {
            return Err(KeychatError::FriendRequest(
                "bundle belongs to self".into(),
            ));
        }
        // Reject a bundle from a peer we already have a session with.
        if self
            .peer_nostr_to_signal
            .contains_key(&received.sender_pubkey_hex)
        {
            return Err(KeychatError::FriendRequest(format!(
                "already connected to peer {}",
                &received.sender_pubkey_hex[..16.min(received.sender_pubkey_hex.len())]
            )));
        }

        let signal_device_id = self.next_signal_device_id;
        self.next_signal_device_id += 1;

        let keys = crate::generate_prekey_material()?;
        let (id_pub, id_priv, reg_id, spk_id, spk_rec, _pk_id, _pk_rec, _kpk_id, _kpk_rec) =
            crate::serialize_prekey_material(&keys)?;

        // Reuse the existing accept path wholesale.
        let accepted = crate::accept_friend_request_persistent(
            &identity,
            &received,
            my_name,
            keys,
            self.storage.clone(),
            signal_device_id,
            self.self_is_public_agent,
        )
        .await?;

        let payload = &received.payload;
        let peer_signal_hex = payload.signal_identity_key.clone();
        let peer_nostr_hex = received.sender_pubkey_hex.clone();
        let peer_name = payload.name.clone();

        // Publish the PreKey message to peer's firstInbox.
        let event_id_hex = accepted.event.id.to_hex();
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| KeychatError::Transport("Not connected".into()))?;
        transport.publish_event_async(accepted.event).await?;

        // AddressManager initialization — mirrors accept_friend_request_protocol.
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

        // Persist.
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
        }

        // In-memory state.
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

        // Subscribe to our new ratchet address.
        self.refresh_subscriptions().await?;

        tracing::info!(
            "[bundle] added contact via bundle: signal={} nostr={}",
            &peer_signal_hex[..16.min(peer_signal_hex.len())],
            &peer_nostr_hex[..16.min(peer_nostr_hex.len())]
        );

        Ok((peer_signal_hex, peer_nostr_hex, peer_name, event_id_hex))
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
            self.self_is_public_agent,
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

        // Spec §8.3 line 250: the peer may send follow-up messages to our
        // first_inbox until their ratchet catches up. Keep the pubkey alive
        // so we stay subscribed and can route it to this session. Cleared
        // on first ratchet-derived decrypt (see try_decrypt_session_message).
        let own_first_inbox_hex = state.first_inbox_keys.pubkey_hex();

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

        // Public Agent flag from friendApprove (spec §3.6). When set, future
        // outbound Mode 1 messages to this peer use dual p-tag routing.
        let peer_is_public_agent = msg
            .friend_approve
            .as_ref()
            .and_then(|p| p.public_agent)
            .unwrap_or(false);

        if peer_is_public_agent {
            if let Ok(store) = self.storage.lock() {
                if let Err(e) = store.set_peer_public_agent(&peer_nostr_id, true) {
                    tracing::warn!(
                        "complete_friend_approve: persist public_agent flag failed: {e}"
                    );
                }
            }
            tracing::info!(
                "[complete_friend_approve] peer is Public Agent; future sends will use dual p-tag: nostr={}",
                &peer_nostr_id[..16.min(peer_nostr_id.len())]
            );
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
        if peer_is_public_agent {
            self.peer_is_public_agent
                .insert(peer_signal_hex.clone(), true);
        }
        for addr in &recv_addrs {
            self.receiving_addr_to_peer
                .insert(addr.clone(), peer_signal_hex.clone());
        }

        // Spec §8.3: keep our first_inbox routable until peer's ratchet takes over.
        self.receiving_addr_to_peer
            .insert(own_first_inbox_hex.clone(), peer_signal_hex.clone());
        self.peer_pending_first_inbox
            .insert(peer_signal_hex.clone(), own_first_inbox_hex);

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

    // (The event-loop driver lives in `keychat-app-core::event_loop`,
    // which calls the `try_decrypt_*` methods above directly.)
}

// ─── Tests (Public Agent mode, spec §3.6) ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn make_client() -> ProtocolClient {
        let storage = Arc::new(Mutex::new(
            SecureStorage::open_in_memory("test-key").unwrap(),
        ));
        let mut c = ProtocolClient::new(storage);
        c.set_identity(Some(Identity::generate().unwrap().identity));
        c
    }

    #[test]
    fn self_public_agent_mode_persists_and_restores() {
        let storage = Arc::new(Mutex::new(
            SecureStorage::open_in_memory("test-key").unwrap(),
        ));

        // Enable in one client, then "restart" into another using the same storage.
        {
            let mut c = ProtocolClient::new(storage.clone());
            c.set_identity(Some(Identity::generate().unwrap().identity));
            assert!(!c.is_self_public_agent());
            c.set_self_public_agent(true).unwrap();
            assert!(c.is_self_public_agent());
        }

        // New ProtocolClient over same storage — restore_sessions should
        // rehydrate the flag from protocol_settings.
        let mut c2 = ProtocolClient::new(storage);
        c2.set_identity(Some(Identity::generate().unwrap().identity));
        let _ = c2.restore_sessions();
        assert!(
            c2.is_self_public_agent(),
            "self_is_public_agent must survive restart via protocol_settings"
        );
    }

    #[test]
    fn mark_peer_upgraded_noop_when_not_agent_mode() {
        let mut c = make_client();
        // Not an agent — flag should not flip regardless of p-tags.
        let me = c.identity().unwrap().pubkey_hex();
        let other = "deadbeef".repeat(8);
        let tags = vec![other.clone(), me.clone()];
        assert!(!c.mark_peer_upgraded_if_dual_tag("peer-sig", &tags));
        assert!(c.peer_uses_dual_p_tag.is_empty());
    }

    #[test]
    fn mark_peer_upgraded_requires_own_npub_in_p_tags() {
        let mut c = make_client();
        c.set_self_public_agent(true).unwrap();

        // Single p-tag — no upgrade.
        assert!(!c.mark_peer_upgraded_if_dual_tag("peer-sig", &["x".into()]));
        // Dual p-tag but neither is own npub — not addressing us as agent.
        assert!(!c.mark_peer_upgraded_if_dual_tag("peer-sig", &["x".into(), "y".into()]));
        assert!(c.peer_uses_dual_p_tag.is_empty());
    }

    #[test]
    fn mark_peer_upgraded_flips_once_and_persists() {
        let mut c = make_client();
        c.set_self_public_agent(true).unwrap();
        let me = c.identity().unwrap().pubkey_hex();

        // Seed peer mapping so persist keyed-by-nostr works.
        {
            let store = c.storage.lock().unwrap();
            store
                .save_peer_mapping("npub-peer", "sig-peer", "Peer")
                .unwrap();
        }
        c.peer_signal_to_nostr
            .insert("sig-peer".into(), "npub-peer".into());

        let tags = vec!["ratchet-addr".into(), me.clone()];
        assert!(c.mark_peer_upgraded_if_dual_tag("sig-peer", &tags));
        assert_eq!(c.peer_uses_dual_p_tag.get("sig-peer"), Some(&true));

        // Second call is a no-op — already marked.
        assert!(!c.mark_peer_upgraded_if_dual_tag("sig-peer", &tags));

        // Persisted to storage.
        let row = c
            .storage
            .lock()
            .unwrap()
            .load_peer_by_nostr("npub-peer")
            .unwrap()
            .unwrap();
        assert!(row.peer_uses_dual_p_tag);
    }

    #[tokio::test]
    async fn agent_mode_collects_own_npub_and_respects_upgrade_flag() {
        use crate::address::AddressManager;
        use crate::session::ChatSession;
        use crate::signal_session::SignalParticipant;

        let mut c = make_client();
        c.set_self_public_agent(true).unwrap();

        // Build a minimal session with an EMPTY address manager so we can
        // deterministically assert how the collect-path handles it (empty
        // receiving address list regardless of upgrade status).
        fn build_session() -> Arc<tokio::sync::Mutex<ChatSession>> {
            let id = Identity::generate().unwrap().identity;
            let signal = SignalParticipant::new("peer", 1).unwrap();
            let s = ChatSession::new(signal, AddressManager::new(), id);
            Arc::new(tokio::sync::Mutex::new(s))
        }
        c.sessions.insert("sig-upgraded".into(), build_session());
        c.peer_uses_dual_p_tag.insert("sig-upgraded".into(), true);

        let (identity_pks, ratchet_pks) = c.collect_subscribe_pubkeys().await;

        // Identity list always includes our own pubkey; agent mode does not
        // add anything else beyond it (and any pending firstInboxes we'd have
        // if this client had issued outbound friend requests — none here).
        assert_eq!(
            identity_pks.len(),
            1,
            "agent mode: only own npub in identity list"
        );
        assert!(
            ratchet_pks.is_empty(),
            "upgraded peer contributes no ratchet addresses in agent mode"
        );
    }
}
