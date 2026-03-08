//! High-level Keychat client API.
//!
//! `KeychatClient` is the unified entry point for libkeychat. It combines
//! identity, Signal sessions, Nostr relay transport, address management,
//! and group support into a single struct.

pub mod types;

pub use types::*;

use std::collections::BTreeMap;

use crate::error::{KeychatError, Result};
use crate::identity::{self, NostrKeypair};
use crate::media;
use crate::nostr::NostrEvent;
use crate::protocol::address::{AddressChange, AddressManager};
use crate::protocol::hello;
use crate::protocol::messaging;
use crate::signal::SignalParticipant;
use crate::stamp::{StampConfig, StampProvider};
use crate::storage::sqlite::SqliteStore;
use crate::transport::relay::RelayFilter;
use crate::transport::relay::RelayConnection;
use crate::transport::RelayPool;

use std::collections::HashSet;

const STATE_KEY: &str = "client_snapshot_v1";

/// Returns Unix timestamp for 1 hour ago (used for relay `since` filters).
fn since_one_hour_ago() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(3600)
}

/// High-level Keychat client.
pub struct KeychatClient {
    /// Nostr identity keypair.
    keypair: NostrKeypair,
    /// Display name for hello messages.
    display_name: String,
    /// Mnemonic phrase (if generated or provided).
    mnemonic: Option<String>,
    /// Media relay server URL.
    media_server: String,
    /// Signal participants keyed by peer nostr pubkey hex.
    signals: BTreeMap<String, SignalParticipant>,
    /// Remote Signal addresses keyed by peer nostr pubkey hex.
    remote_addrs: BTreeMap<String, libsignal_protocol::ProtocolAddress>,
    /// Address manager for ratchet-derived receiving addresses.
    address_manager: AddressManager,
    /// SQLite store for persistent state.
    store: SqliteStore,
    /// Connected relay pool.
    relay_pool: RelayPool,
    /// Active subscriptions (sub_id → description).
    subscriptions: BTreeMap<String, String>,
    /// Optional relay stamp fee configuration.
    stamp_config: Option<StampConfig>,
    /// Subscription counter.
    sub_counter: u64,
    /// Dedup set for processed event IDs.
    processed_events: HashSet<String>,
}

impl KeychatClient {
    /// Initialize a new client.
    ///
    /// If `config.mnemonic` is `None`, generates a new BIP-39 mnemonic.
    /// Connects to all configured relays.
    pub async fn init(config: ClientConfig) -> Result<Self> {
        let (mnemonic, keypair) = if let Some(phrase) = &config.mnemonic {
            let m = identity::recover_mnemonic(phrase)?;
            let kp = identity::nostr_keypair_from_mnemonic(&m)?;
            (m.to_string(), kp)
        } else {
            let m = identity::generate_mnemonic(12)?;
            let kp = identity::nostr_keypair_from_mnemonic(&m)?;
            (m.to_string(), kp)
        };

        let store = SqliteStore::open(&config.db_path)?;

        // Restore state from DB if available
        let (signals, remote_addrs, address_manager) = if let Some(blob) =
            store.load_state(STATE_KEY)?
        {
            match serde_json::from_slice::<ClientSnapshot>(&blob) {
                Ok(snap) => {
                    let mut sigs = BTreeMap::new();
                    for (peer_id, participant_snap) in snap.signals {
                        match SignalParticipant::from_snapshot(participant_snap) {
                            Ok(p) => {
                                sigs.insert(peer_id, p);
                            }
                            Err(e) => {
                                eprintln!(
                                    "[keychat-client] failed to restore signal session for {}: {}",
                                    &peer_id[..12.min(peer_id.len())],
                                    e
                                );
                            }
                        }
                    }
                    let mut addrs = BTreeMap::new();
                    for (peer_id, (name, device_id)) in snap.remote_addrs {
                        addrs.insert(
                            peer_id,
                            libsignal_protocol::ProtocolAddress::new(name, device_id.into()),
                        );
                    }
                    (sigs, addrs, snap.address_manager)
                }
                Err(e) => {
                    eprintln!("[keychat-client] failed to deserialize snapshot: {}", e);
                    (BTreeMap::new(), BTreeMap::new(), AddressManager::default())
                }
            }
        } else {
            (BTreeMap::new(), BTreeMap::new(), AddressManager::default())
        };

        let relay_refs: Vec<&str> = config.relays.iter().map(|s| s.as_str()).collect();
        let relay_pool = RelayPool::connect(&relay_refs).await?;

        Ok(Self {
            keypair,
            display_name: config.display_name,
            mnemonic: Some(mnemonic),
            media_server: config
                .media_server
                .unwrap_or_else(|| "https://relay.keychat.io".to_owned()),
            signals,
            remote_addrs,
            address_manager,
            store,
            relay_pool,
            subscriptions: BTreeMap::new(),
            stamp_config: None,
            sub_counter: 0,
            processed_events: HashSet::new(),
        })
    }

    // ── Identity ──

    /// Get the npub (bech32-encoded public key).
    pub fn npub(&self) -> Result<String> {
        self.keypair.npub()
    }

    /// Get the public key hex.
    pub fn pubkey_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// Get the mnemonic (if available).
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Get the Nostr keypair reference.
    pub fn keypair(&self) -> &NostrKeypair {
        &self.keypair
    }

    /// Install a stamp provider implementation used for paid relay publishing.
    pub fn set_stamp_provider(&self, provider: Box<dyn StampProvider>) -> Result<()> {
        self.relay_pool.set_stamp_provider(provider)
    }

    /// Set or clear relay stamp fee configuration.
    pub fn set_stamp_config(&mut self, stamp_config: Option<StampConfig>) {
        self.stamp_config = stamp_config;
    }

    // ── Friends ──

    /// Send a hello (add-friend request) to a peer.
    ///
    /// `recipient` can be an npub or hex pubkey.
    pub async fn add_friend(&mut self, recipient: &str, message: &str) -> Result<()> {
        let recipient_hex = decode_pubkey(recipient)?;

        let hello_result = hello::create_hello(
            &self.keypair,
            &recipient_hex,
            &self.display_name,
            message,
            &recipient_hex,
            &mut self.address_manager,
        )?;

        self.signals
            .insert(recipient_hex.clone(), hello_result.signal.clone());

        // Subscribe to receiving addresses BEFORE publishing hello,
        // so replies arriving immediately are not missed.
        self.apply_address_changes(&hello_result.address_changes)
            .await?;

        // Small delay to ensure relay subscriptions are active
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        self.publish_event(&hello_result.event).await?;

        self.save()?;
        Ok(())
    }

    // ── Messaging ──

    /// Send a plaintext message to a peer with an established Signal session.
    pub async fn send(&mut self, peer_pubkey_hex: &str, text: &str) -> Result<()> {
        let signal = self
            .signals
            .get_mut(peer_pubkey_hex)
            .ok_or_else(|| KeychatError::MissingPeer(peer_pubkey_hex[..12].to_owned()))?;

        let remote_addr = self
            .remote_addrs
            .get(peer_pubkey_hex)
            .ok_or_else(|| KeychatError::MissingPeer(peer_pubkey_hex[..12].to_owned()))?
            .clone();

        let recipient_address = self
            .address_manager
            .get_sending_address(peer_pubkey_hex)
            .ok_or_else(|| KeychatError::MissingSendingAddress(peer_pubkey_hex[..12].to_owned()))?;

        let (event, changes) = messaging::send_signal_plaintext_to_address(
            signal,
            &remote_addr,
            &mut self.address_manager,
            peer_pubkey_hex,
            &recipient_address,
            text,
        )?;

        self.apply_address_changes(&changes).await?;
        self.publish_event(&event).await?;

        self.save()?;
        Ok(())
    }

    /// Send a media file to a peer.
    ///
    /// `file_bytes`: raw file content
    /// `suffix`: file extension (`jpg`, `png`, `mp4`, etc.)
    /// `source_name`: original filename
    /// `media_type`: `image`, `video`, `file`, or `voiceNote`
    pub async fn send_media(
        &mut self,
        peer: &str,
        file_bytes: &[u8],
        suffix: &str,
        source_name: &str,
        media_type: &str,
    ) -> Result<()> {
        let encrypted = media::encrypt_file(file_bytes)?;
        let server = self.media_server.as_str();

        let uploaded_url = if media::is_s3_relay(server).await {
            match media::upload_to_s3_relay(&encrypted.ciphertext, &encrypted.hash, Some(server))
                .await
            {
                Ok(url) => url,
                Err(_) => {
                    let expiration = crate::nostr::now().saturating_add(3600);
                    let auth = media::build_blossom_auth(&encrypted.hash_hex()?, expiration)?;
                    media::upload_to_blossom(&encrypted.ciphertext, &auth, Some(server)).await?
                }
            }
        } else {
            let expiration = crate::nostr::now().saturating_add(3600);
            let auth = media::build_blossom_auth(&encrypted.hash_hex()?, expiration)?;
            media::upload_to_blossom(&encrypted.ciphertext, &auth, Some(server)).await?
        };

        let media_url =
            media::build_media_url(&uploaded_url, &encrypted, suffix, media_type, source_name);
        self.send(peer, &media_url).await
    }

    // ── Events ──

    /// Subscribe to our identity pubkey for incoming hello requests (kind:1059).
    pub async fn start_listening(&mut self) -> Result<()> {
        let pubkey = self.keypair.public_key_hex();
        let since = since_one_hour_ago();

        // Subscribe for kind:1059 (Gift Wrap) addressed to us
        let filter = RelayFilter::for_welcomes(&pubkey).with_since(since);
        let sub_id = self.next_sub_id();
        self.relay_pool.subscribe_with_id(&sub_id, filter).await?;
        self.subscriptions
            .insert(sub_id, "identity-1059".to_owned());

        // Also subscribe for kind:4 on our identity pubkey
        let filter_dm = RelayFilter::new()
            .with_kind(4)
            .with_p_tag(&pubkey)
            .with_since(since);
        let sub_id_dm = self.next_sub_id();
        self.relay_pool
            .subscribe_with_id(&sub_id_dm, filter_dm)
            .await?;
        self.subscriptions
            .insert(sub_id_dm, "identity-dm".to_owned());

        // Re-subscribe to all known receiving addresses from restored state
        let all_addrs = self.address_manager.get_all_receiving_addresses();
        if !all_addrs.is_empty() {
            let filter_recv = RelayFilter::new().with_kind(4).with_since(since);
            // Add all addresses as p-tags in one filter
            let mut f = filter_recv;
            for addr in &all_addrs {
                f = f.with_p_tag(addr);
            }
            let sub_id_recv = self.next_sub_id();
            self.relay_pool.subscribe_with_id(&sub_id_recv, f).await?;
            self.subscriptions
                .insert(sub_id_recv, "restored-addrs".to_owned());
        }

        Ok(())
    }

    /// Wait for the next inbound event.
    ///
    /// Returns `None` if all relay connections are closed.
    pub async fn next_event(&mut self) -> Option<InboundEvent> {
        loop {
            let event = self.relay_pool.next_event().await?;

            match self.process_event(&event) {
                Ok(Some(inbound)) => return Some(inbound),
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
    }

    // ── Contacts ──

    /// List known peer pubkeys (peers with established Signal sessions).
    pub fn peers(&self) -> Vec<String> {
        self.signals.keys().cloned().collect()
    }

    /// Check if we have a Signal session with a peer.
    pub fn has_session(&self, peer_pubkey_hex: &str) -> bool {
        self.signals.contains_key(peer_pubkey_hex)
    }

    /// Get all receiving addresses currently tracked by the address manager.
    pub fn receiving_addresses(&self) -> Vec<String> {
        self.address_manager.get_all_receiving_addresses()
    }

    /// Get all active subscription IDs and their descriptions.
    pub fn subscriptions(&self) -> &BTreeMap<String, String> {
        &self.subscriptions
    }

    /// Get connected relay handles.
    pub fn relays(&self) -> Vec<RelayConnection> {
        self.relay_pool.relays().to_vec()
    }

    // ── Signal-based Small Groups ──

    /// Create a new Signal-based small group.
    ///
    /// Returns the group profile and secret key. The caller should add members
    /// to the profile and send invites via `send_group_invite()`.
    pub fn create_group(&self, group_name: &str) -> Result<crate::group::types::CreateGroupResult> {
        let my_pubkey = self.keypair.public_key_hex();
        let my_name = "libkeychat"; // TODO: make configurable
        crate::group::create_group(&my_pubkey, my_name, group_name)
    }

    /// Send a group invite to a peer via their Signal session.
    ///
    /// The peer must already be a friend (have a Signal session).
    pub async fn send_group_invite(
        &mut self,
        peer_pubkey: &str,
        profile: &crate::group::types::GroupProfile,
        invite_message: &str,
    ) -> Result<()> {
        let my_pubkey = self.keypair.public_key_hex();
        let payload = crate::group::build_invite_message(profile, invite_message, &my_pubkey);
        self.send(peer_pubkey, &payload).await
    }

    /// Send a message to all members of a small group.
    ///
    /// This encrypts the message individually for each member (fan-out).
    /// `member_pubkeys` should be the list of all OTHER members (not self).
    pub async fn send_group_message(
        &mut self,
        group_pubkey: &str,
        member_pubkeys: &[&str],
        content: &str,
    ) -> Result<()> {
        let my_pubkey = self.keypair.public_key_hex();
        let payload = crate::group::build_group_message(group_pubkey, &my_pubkey, content);
        for peer in member_pubkeys {
            if let Err(e) = self.send(peer, &payload).await {
                eprintln!(
                    "[keychat-client] group message to {}... failed: {}",
                    &peer[..12.min(peer.len())],
                    e
                );
            }
        }
        Ok(())
    }

    /// Rename a small group. Sends rename notification to all members.
    pub async fn rename_group(
        &mut self,
        group_pubkey: &str,
        new_name: &str,
        member_pubkeys: &[&str],
    ) -> Result<()> {
        let payload = crate::group::build_rename_message(group_pubkey, new_name);
        for peer in member_pubkeys {
            let _ = self.send(peer, &payload).await;
        }
        Ok(())
    }

    /// Remove a member from a small group. Notifies all remaining members.
    pub async fn remove_group_member(
        &mut self,
        group_pubkey: &str,
        member_to_remove: &str,
        remaining_members: &[&str],
    ) -> Result<()> {
        let payload = crate::group::build_remove_member_message(group_pubkey, member_to_remove);
        for peer in remaining_members {
            let _ = self.send(peer, &payload).await;
        }
        Ok(())
    }

    /// Dissolve a small group. Notifies all members.
    pub async fn dissolve_group(
        &mut self,
        group_pubkey: &str,
        member_pubkeys: &[&str],
    ) -> Result<()> {
        let payload = crate::group::build_dissolve_message(group_pubkey);
        for peer in member_pubkeys {
            let _ = self.send(peer, &payload).await;
        }
        Ok(())
    }

    // ── MLS Large Groups ──

    /// Initialize MLS support. Must be called before any MLS group operations.
    ///
    /// `mls_db_path` is the SQLite database for MLS state (separate from the
    /// main client database).
    pub async fn init_mls(&self, mls_db_path: &str) -> Result<()> {
        let nostr_id = self.pubkey_hex();
        let db_path = mls_db_path.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::init_mls(&db_path, &nostr_id))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Create a new MLS group. Returns the group ID.
    pub async fn create_mls_group(&self, group_name: &str) -> Result<String> {
        let nostr_id = self.pubkey_hex();
        let name = group_name.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::create_mls_group(&nostr_id, &name))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Create a key package for publishing to relays.
    pub async fn create_key_package(&self) -> Result<crate::mls::types::KeyPackageResult> {
        let nostr_id = self.pubkey_hex();
        tokio::task::spawn_blocking(move || crate::mls::create_key_package(&nostr_id))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Add a member to an MLS group using their key package.
    /// Returns the commit + welcome messages to send to the new member.
    pub async fn mls_add_member(
        &self,
        group_id: &str,
        key_package_hex: &str,
    ) -> Result<crate::mls::types::AddMembersResult> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        let kp = key_package_hex.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::add_member(&nostr_id, &gid, &kp))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Join an MLS group from a Welcome message. Returns the group ID.
    pub async fn mls_join_group(&self, welcome_bytes: &[u8]) -> Result<String> {
        let nostr_id = self.pubkey_hex();
        let wb = welcome_bytes.to_vec();
        tokio::task::spawn_blocking(move || crate::mls::join_group_from_welcome(&nostr_id, &wb))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Encrypt a message for an MLS group.
    pub async fn mls_encrypt(&self, group_id: &str, message: &str) -> Result<Vec<u8>> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        let msg = message.to_owned();
        tokio::task::spawn_blocking(move || {
            crate::mls::encrypt_group_message(&nostr_id, &gid, &msg)
        })
        .await
        .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Decrypt an MLS group message.
    pub async fn mls_decrypt(
        &self,
        group_id: &str,
        ciphertext: &[u8],
    ) -> Result<crate::mls::types::DecryptedGroupMessage> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        let ct = ciphertext.to_vec();
        tokio::task::spawn_blocking(move || crate::mls::decrypt_group_message(&nostr_id, &gid, &ct))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Process an MLS message (application message or commit) using the
    /// unified API.
    pub async fn mls_process_message(
        &self,
        group_id: &str,
        message_bytes: &[u8],
    ) -> Result<crate::mls::types::ProcessedMlsMessage> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        let mb = message_bytes.to_vec();
        tokio::task::spawn_blocking(move || crate::mls::process_mls_message(&nostr_id, &gid, &mb))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Remove a member from an MLS group.
    pub async fn mls_remove_member(
        &self,
        group_id: &str,
        member_nostr_id: &str,
    ) -> Result<crate::mls::types::RemoveMemberResult> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        let mid = member_nostr_id.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::remove_member(&nostr_id, &gid, &mid))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Leave an MLS group. Returns the commit message.
    pub async fn mls_leave_group(&self, group_id: &str) -> Result<Vec<u8>> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::leave_group(&nostr_id, &gid))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Get the listen key for an MLS group (for subscribing to group messages).
    pub async fn mls_listen_key(&self, group_id: &str) -> Result<String> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::get_group_listen_key(&nostr_id, &gid))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// Get the export secret keypair for NIP-44 encryption of MLS messages.
    pub async fn mls_export_secret_keypair(&self, group_id: &str) -> Result<NostrKeypair> {
        let nostr_id = self.pubkey_hex();
        let gid = group_id.to_owned();
        tokio::task::spawn_blocking(move || crate::mls::get_export_secret_keypair(&nostr_id, &gid))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    /// List all MLS group IDs.
    pub async fn mls_groups(&self) -> Result<Vec<String>> {
        let nostr_id = self.pubkey_hex();
        tokio::task::spawn_blocking(move || crate::mls::list_groups(&nostr_id))
            .await
            .map_err(|e| KeychatError::Mls(format!("spawn_blocking: {e}")))?
    }

    // ── Persistence ──

    /// Save all client state to the database.
    ///
    /// Call this after important state changes (new friend, received message).
    /// Also called automatically by `add_friend()`, `send()`, and event processing.
    pub fn save(&mut self) -> Result<()> {
        let mut signal_snaps = BTreeMap::new();
        for (peer_id, signal) in &mut self.signals {
            signal_snaps.insert(peer_id.clone(), signal.snapshot()?);
        }

        let mut remote_snap = BTreeMap::new();
        for (peer_id, addr) in &self.remote_addrs {
            remote_snap.insert(
                peer_id.clone(),
                (addr.name().to_owned(), u32::from(addr.device_id())),
            );
        }

        let snapshot = ClientSnapshot {
            signals: signal_snaps,
            remote_addrs: remote_snap,
            address_manager: self.address_manager.clone(),
        };

        let blob = serde_json::to_vec(&snapshot)
            .map_err(|e| KeychatError::Storage(format!("serialize snapshot: {e}")))?;
        self.store.save_state(STATE_KEY, &blob)?;
        Ok(())
    }

    // ── Internal ──

    fn process_event(&mut self, event: &NostrEvent) -> Result<Option<InboundEvent>> {
        // Dedup: skip already-processed events (multi-relay or since-backfill duplicates)
        if !self.processed_events.insert(event.id.clone()) {
            return Ok(None);
        }

        match event.kind {
            1059 => self.process_gift_wrap(event),
            4 => self.process_kind4(event),
            _ => Ok(None),
        }
    }

    fn process_gift_wrap(&mut self, event: &NostrEvent) -> Result<Option<InboundEvent>> {
        // Try to process as hello (friend request)
        // receive_hello needs a local signal participant — create a temporary one
        let mut temp_signal = SignalParticipant::new("temp", 1)?;

        match hello::receive_hello(
            &self.keypair,
            &mut temp_signal,
            &mut self.address_manager,
            event,
        ) {
            Ok(outcome) => {
                let sender = outcome.peer.pubkey.clone();
                let sender_name = outcome.peer.name.clone();
                let message = outcome.hello_message.msg.clone();

                // Store the Signal session and remote address
                self.signals.insert(sender.clone(), temp_signal);
                self.remote_addrs
                    .insert(sender.clone(), outcome.remote_signal_address.clone());

                // Apply address changes
                let _ = futures::executor::block_on(
                    self.apply_address_changes(&outcome.address_changes),
                );

                // Publish auto-reply
                let _ = futures::executor::block_on(self.publish_event(&outcome.auto_reply));

                let _ = self.save();

                Ok(Some(InboundEvent::FriendRequest {
                    sender,
                    sender_name,
                    message,
                }))
            }
            Err(_) => Ok(None),
        }
    }

    fn process_kind4(&mut self, event: &NostrEvent) -> Result<Option<InboundEvent>> {
        let arrived_at = event.tags.iter().find_map(|tag| {
            if tag.len() >= 2 && tag[0] == "p" {
                Some(tag[1].clone())
            } else {
                None
            }
        });

        let arrived_at = match arrived_at {
            Some(a) => a,
            None => return Ok(None),
        };

        let peer_id = match self
            .address_manager
            .resolve_peer_by_receiving_address(&arrived_at)
        {
            Some(id) => id.to_owned(),
            None => {
                // Fallback: if the event arrived at our identity pubkey,
                // try to match by any known peer (agent may send to our
                // nostr pubkey before ratchet addresses are established)
                if arrived_at == self.keypair.public_key_hex() {
                    // Try to find the peer by the first p-tag that matches a known peer
                    // For now, if we have exactly one peer, use that
                    if self.signals.len() == 1 {
                        self.signals.keys().next().unwrap().clone()
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
        };

        let signal = match self.signals.get_mut(&peer_id) {
            Some(s) => s,
            None => {
                return Ok(None);
            }
        };

        let remote_addr = match self.remote_addrs.get(&peer_id) {
            Some(a) => a.clone(),
            None => {
                // For PreKey messages (first message in session), use peer_id as address
                libsignal_protocol::ProtocolAddress::new(peer_id.clone(), 1u32.into())
            }
        };

        // Decode base64 Signal ciphertext
        use base64::Engine;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&event.content)
            .map_err(|e| KeychatError::Nostr(format!("base64 decode: {e}")))?;

        let is_prekey = SignalParticipant::is_prekey_message(&ciphertext);

        // For PreKey messages, use the sender's actual Signal identity key as the
        // remote address (not the nostr pubkey). This is critical for correct
        // session establishment when the sender uses an ephemeral Signal keypair.
        let effective_remote_addr = if is_prekey {
            if let Some(sender_identity_hex) =
                SignalParticipant::extract_prekey_sender_identity(&ciphertext)
            {
                libsignal_protocol::ProtocolAddress::new(sender_identity_hex, 1u32.into())
            } else {
                remote_addr
            }
        } else {
            remote_addr
        };

        let decrypt_result = match signal.decrypt_with_metadata(&effective_remote_addr, &ciphertext)
        {
            Ok(r) => r,
            Err(_) => {
                // Stale events from prior sessions are expected on reconnect; silently skip
                return Ok(None);
            }
        };

        // Store the effective remote address for future sends
        self.remote_addrs
            .entry(peer_id.clone())
            .or_insert_with(|| effective_remote_addr.clone());

        // Update peer's sending address from ratchet (bob_derived_address)
        if let Some(ref bob_addr) = decrypt_result.bob_derived_address {
            self.address_manager
                .set_sending_address(&peer_id, bob_addr.clone());
        }

        // Update our receiving addresses from ratchet advancement
        let changes = self
            .address_manager
            .on_message_decrypted(&peer_id, &decrypt_result);
        let _ = futures::executor::block_on(self.apply_address_changes(&changes));

        let plaintext = String::from_utf8(decrypt_result.plaintext)
            .unwrap_or_else(|_| "(binary data)".to_owned());

        // Check if it's a group message
        if let Ok(km) = serde_json::from_str::<serde_json::Value>(&plaintext) {
            if km.get("c").and_then(|v| v.as_str()) == Some("group") {
                if let Ok(ge) = crate::group::parse_group_message(&plaintext, &peer_id, "") {
                    return Ok(Some(InboundEvent::GroupEvent {
                        from_peer: peer_id,
                        event: ge,
                    }));
                }
            }
        }

        let _ = self.save();

        Ok(Some(InboundEvent::DirectMessage {
            sender: peer_id,
            plaintext,
            is_prekey,
        }))
    }

    async fn apply_address_changes(&mut self, changes: &[AddressChange]) -> Result<()> {
        for change in changes {
            match change {
                AddressChange::Subscribe(addr) => {
                    let filter = RelayFilter::new()
                        .with_kind(4)
                        .with_p_tag(addr)
                        .with_since(since_one_hour_ago());
                    let sub_id = self.next_sub_id();
                    self.relay_pool.subscribe_with_id(&sub_id, filter).await?;
                    self.subscriptions.insert(sub_id, addr.clone());
                }
                AddressChange::Unsubscribe(addr) => {
                    let to_remove: Vec<String> = self
                        .subscriptions
                        .iter()
                        .filter(|(_, v)| *v == addr)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for sub_id in to_remove {
                        let _ = self.relay_pool.unsubscribe(&sub_id).await;
                        self.subscriptions.remove(&sub_id);
                    }
                }
                AddressChange::UpdateSendAddr { .. } => {
                    // Send address updates are handled internally by AddressManager
                }
            }
        }
        Ok(())
    }

    fn next_sub_id(&mut self) -> String {
        self.sub_counter += 1;
        format!("kc-{}", self.sub_counter)
    }

    async fn publish_event(&self, event: &NostrEvent) -> Result<()> {
        if let Some(stamp_config) = &self.stamp_config {
            self.relay_pool.publish_with_stamps(event, stamp_config).await
        } else {
            self.relay_pool.publish(event).await
        }
    }
}

/// Decode an npub or hex pubkey to hex.
fn decode_pubkey(input: &str) -> Result<String> {
    if input.starts_with("npub1") {
        crate::identity::decode_npub(input)
    } else {
        if input.len() != 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(KeychatError::InvalidArgument(
                "expected 64-char hex or npub".to_owned(),
            ));
        }
        Ok(input.to_owned())
    }
}
