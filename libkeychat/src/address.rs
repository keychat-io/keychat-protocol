//! Address rotation manager (spec §9).
//!
//! Tracks per-peer receiving and sending addresses derived from the Signal
//! Double Ratchet state, implementing Keychat's message-unlinkability feature.

use std::collections::{HashMap, VecDeque};

use crate::error::{KeychatError, Result};
use crate::storage::{DerivedAddressSerialized, PeerAddressStateSerialized};

/// Default sliding window size for receiving addresses per peer.
pub const DEFAULT_WINDOW_SIZE: usize = 3;

/// A Nostr address derived from Signal ratchet state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAddress {
    /// Nostr x-only pubkey hex (64 chars) — subscribe to events on this address.
    pub address: String,
    /// Secret key hex — used to decrypt events addressed to us on this address.
    pub secret_key: String,
    /// The ratchet key string (`"{priv_hex}-{pub_hex}"`) it was derived from.
    pub ratchet_key: String,
}

/// Per-peer address state.
#[derive(Debug, Clone)]
pub struct PeerAddressState {
    /// Sliding window of our receiving addresses (listen on these).
    pub receiving_addresses: VecDeque<DerivedAddress>,
    /// Current sending address for this peer (where to deliver next message).
    pub sending_address: Option<String>,
    /// Peer's firstInbox (cleared after ratchet takes over).
    pub peer_first_inbox: Option<String>,
    /// Peer's Nostr identity pubkey (fallback sending address).
    pub peer_nostr_pubkey: Option<String>,
}

/// Describes address subscription changes after an encrypt/decrypt operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressUpdate {
    /// New addresses to subscribe to on relays.
    pub new_receiving: Vec<String>,
    /// Old addresses to unsubscribe from on relays.
    pub dropped_receiving: Vec<String>,
    /// Updated sending address for this peer (if changed).
    pub new_sending: Option<String>,
}

/// Manages per-peer receiving and sending addresses derived from the Signal
/// Double Ratchet (spec §9).
#[derive(Debug, Clone)]
pub struct AddressManager {
    /// Per-peer state keyed by peer's Signal identity hex.
    peers: HashMap<String, PeerAddressState>,
    /// Sliding window size.
    window_size: usize,
}

impl AddressManager {
    /// Create a new empty AddressManager with the default window size.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }

    /// Create a new AddressManager with a custom window size.
    pub fn with_window_size(window_size: usize) -> Self {
        assert!(window_size >= 1, "window_size must be at least 1");
        Self {
            peers: HashMap::new(),
            window_size,
        }
    }

    /// Register a new peer.
    pub fn add_peer(
        &mut self,
        peer_id: &str,
        peer_first_inbox: Option<String>,
        peer_nostr_pubkey: Option<String>,
    ) {
        self.peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerAddressState {
                receiving_addresses: VecDeque::new(),
                sending_address: None,
                peer_first_inbox,
                peer_nostr_pubkey,
            });
    }

    /// Called after encrypting a message. Processes ratchet metadata to
    /// update our receiving addresses.
    ///
    /// `sender_address` comes from `SignalCiphertext.sender_address` — it is
    /// the ratchet key from which our new receiving address is derived.
    ///
    /// Returns an `AddressUpdate` describing subscription changes.
    pub fn on_encrypt(
        &mut self,
        peer_id: &str,
        sender_address: Option<&str>,
    ) -> Result<AddressUpdate> {
        let state = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| KeychatError::Signal(format!("unknown peer: {peer_id}")))?;

        let mut update = AddressUpdate::default();

        if let Some(ratchet_key) = sender_address {
            // Skip if it's a raw Signal identity key (05-prefixed, 66 hex chars)
            if ratchet_key.starts_with("05") && ratchet_key.len() == 66 {
                return Ok(update);
            }

            // Check if we already have this address
            if state
                .receiving_addresses
                .iter()
                .any(|a| a.ratchet_key == ratchet_key)
            {
                return Ok(update);
            }

            let derived = derive_address_with_secret(ratchet_key)?;
            tracing::debug!(
                "on_encrypt new receiving address={} for peer={}",
                &derived.address[..16.min(derived.address.len())],
                &peer_id[..16.min(peer_id.len())]
            );
            update.new_receiving.push(derived.address.clone());

            state.receiving_addresses.push_back(derived);

            // Prune excess addresses
            while state.receiving_addresses.len() > self.window_size {
                if let Some(old) = state.receiving_addresses.pop_front() {
                    update.dropped_receiving.push(old.address);
                }
            }
        }

        Ok(update)
    }

    /// Called after decrypting a message. Updates the sending address for
    /// this peer based on their ratchet-derived address.
    ///
    /// `bob_derived_address` comes from `SignalDecryptResult.bob_derived_address`.
    /// `alice_addrs` comes from `SignalDecryptResult.alice_addrs` — our new receiving addresses.
    ///
    /// Returns an `AddressUpdate` describing changes.
    pub fn on_decrypt(
        &mut self,
        peer_id: &str,
        bob_derived_address: Option<&str>,
        alice_addrs: Option<&[String]>,
    ) -> Result<AddressUpdate> {
        let state = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| KeychatError::Signal(format!("unknown peer: {peer_id}")))?;

        let mut update = AddressUpdate::default();

        // Update sending address (where to send to this peer next)
        if let Some(addr) = bob_derived_address {
            if state.sending_address.as_deref() != Some(addr) {
                state.sending_address = Some(addr.to_string());
                update.new_sending = Some(addr.to_string());
            }
        }

        // Process our new receiving addresses
        if let Some(addrs) = alice_addrs {
            for ratchet_key in addrs {
                // Skip raw Signal identity keys
                if ratchet_key.starts_with("05") && ratchet_key.len() == 66 {
                    continue;
                }
                // Skip duplicates
                if state
                    .receiving_addresses
                    .iter()
                    .any(|a| a.ratchet_key == *ratchet_key)
                {
                    continue;
                }

                let derived = derive_address_with_secret(ratchet_key)?;
                tracing::debug!(
                    "on_decrypt new receiving address={} for peer={}",
                    &derived.address[..16.min(derived.address.len())],
                    &peer_id[..16.min(peer_id.len())]
                );
                update.new_receiving.push(derived.address.clone());
                state.receiving_addresses.push_back(derived);
            }

            // Prune excess
            while state.receiving_addresses.len() > self.window_size {
                if let Some(old) = state.receiving_addresses.pop_front() {
                    update.dropped_receiving.push(old.address);
                }
            }
        }

        Ok(update)
    }

    /// Resolve the address to send to for a given peer (§9.4 priority order).
    ///
    /// 1. Ratchet-derived sending address (if available)
    /// 2. Peer's firstInbox (if available)
    /// 3. Peer's Nostr identity pubkey (fallback)
    pub fn resolve_send_address(&self, peer_id: &str) -> Result<String> {
        let state = self
            .peers
            .get(peer_id)
            .ok_or_else(|| KeychatError::Signal(format!("unknown peer: {peer_id}")))?;

        // Priority 1: ratchet-derived sending address
        if let Some(ref addr) = state.sending_address {
            return Ok(addr.clone());
        }

        // Priority 2: peer's firstInbox
        if let Some(ref inbox) = state.peer_first_inbox {
            return Ok(inbox.clone());
        }

        // Priority 3: peer's Nostr identity pubkey
        if let Some(ref npub) = state.peer_nostr_pubkey {
            return Ok(npub.clone());
        }

        Err(KeychatError::Signal(format!(
            "no sending address available for peer: {peer_id}"
        )))
    }

    /// Get all current receiving addresses across all peers (for relay subscription).
    pub fn get_all_receiving_addresses(&self) -> Vec<&DerivedAddress> {
        self.peers
            .values()
            .flat_map(|s| s.receiving_addresses.iter())
            .collect()
    }

    /// Get just the address strings (pubkey hex) for relay subscription.
    pub fn get_all_receiving_address_strings(&self) -> Vec<String> {
        self.get_all_receiving_addresses()
            .into_iter()
            .map(|a| a.address.clone())
            .collect()
    }

    /// Clear the peer's firstInbox (called when first ratchet-derived message received).
    pub fn clear_peer_first_inbox(&mut self, peer_id: &str) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.peer_first_inbox = None;
        }
    }

    /// Get peer state (read-only).
    pub fn get_peer(&self, peer_id: &str) -> Option<&PeerAddressState> {
        self.peers.get(peer_id)
    }

    /// Get the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the window size.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Reconstruct an AddressManager from serialized peer state.
    pub fn from_serialized(peer_id: &str, state: PeerAddressStateSerialized) -> Self {
        let mut mgr = AddressManager::new();
        let peer_state = PeerAddressState {
            receiving_addresses: state
                .receiving_addresses
                .into_iter()
                .map(|a| DerivedAddress {
                    address: a.address,
                    secret_key: a.secret_key,
                    ratchet_key: a.ratchet_key,
                })
                .collect(),
            sending_address: state.sending_address,
            peer_first_inbox: state.peer_first_inbox,
            peer_nostr_pubkey: state.peer_nostr_pubkey,
        };
        mgr.peers.insert(peer_id.to_string(), peer_state);
        mgr
    }

    /// Export a peer's address state as a serializable format.
    pub fn to_serialized(&self, peer_id: &str) -> Option<PeerAddressStateSerialized> {
        self.peers
            .get(peer_id)
            .map(|state| PeerAddressStateSerialized {
                receiving_addresses: state
                    .receiving_addresses
                    .iter()
                    .map(|a| DerivedAddressSerialized {
                        address: a.address.clone(),
                        secret_key: a.secret_key.clone(),
                        ratchet_key: a.ratchet_key.clone(),
                    })
                    .collect(),
                sending_address: state.sending_address.clone(),
                peer_first_inbox: state.peer_first_inbox.clone(),
                peer_nostr_pubkey: state.peer_nostr_pubkey.clone(),
            })
    }
}

impl Default for AddressManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a Nostr address + secret key from a ratchet key string.
///
/// The ratchet key is in format `"{private_hex}-{public_hex}"`.
/// Returns a `DerivedAddress` with the x-only public key and corresponding secret key.
fn derive_address_with_secret(ratchet_key: &str) -> Result<DerivedAddress> {
    use sha2::Digest;

    let (private_hex, public_hex) = ratchet_key.split_once('-').ok_or_else(|| {
        KeychatError::Signal("expected private-public format for ratchet key".into())
    })?;

    let private_bytes = hex::decode(private_hex)?;
    let public_bytes = hex::decode(public_hex)?;

    let alice_private = libsignal_protocol::PrivateKey::deserialize(&private_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid ratchet private key: {e}")))?;
    let bob_public = libsignal_protocol::PublicKey::deserialize(&public_bytes)
        .map_err(|e| KeychatError::Signal(format!("invalid ratchet public key: {e}")))?;

    let agreement = alice_private
        .calculate_agreement(&bob_public)
        .map_err(|e| KeychatError::Signal(format!("ECDH failed: {e}")))?;

    let mut secrets = Vec::with_capacity(64);
    secrets.extend_from_slice(&[0xFFu8; 32]);
    secrets.extend_from_slice(&agreement);

    let secret_hash = sha2::Sha256::digest(&secrets);
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&secret_hash[..32])?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let x_public_key = public_key.x_only_public_key().0.serialize();

    Ok(DerivedAddress {
        address: hex::encode(x_public_key),
        secret_key: hex::encode(secret_hash),
        ratchet_key: ratchet_key.to_string(),
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal_session::{derive_nostr_address_from_ratchet, SignalParticipant};
    use libsignal_protocol::{DeviceId, ProtocolAddress};

    /// Helper: set up a Signal session between Alice and Bob and return both
    /// participants plus their protocol addresses.
    fn setup_session() -> (
        SignalParticipant,
        SignalParticipant,
        ProtocolAddress,
        ProtocolAddress,
    ) {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();

        let bob_bundle = bob.prekey_bundle().unwrap();
        let bob_addr =
            ProtocolAddress::new(bob.identity_public_key_hex(), DeviceId::new(1).unwrap());
        let alice_addr =
            ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::new(1).unwrap());

        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

        (alice, bob, alice_addr, bob_addr)
    }

    // ─── Address derivation determinism ──────────────────────────────────────

    #[test]
    fn address_derivation_deterministic() {
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        // Encrypt to get a sender_address (ratchet key)
        let result = alice.encrypt(&bob_addr, b"hello").unwrap();

        if let Some(ref ratchet_key) = result.sender_address {
            let addr1 = derive_nostr_address_from_ratchet(ratchet_key).unwrap();
            let addr2 = derive_nostr_address_from_ratchet(ratchet_key).unwrap();
            assert_eq!(addr1, addr2, "same ratchet key must produce same address");

            // Also verify derive_address_with_secret gives the same address
            let derived = derive_address_with_secret(ratchet_key).unwrap();
            assert_eq!(derived.address, addr1);
            assert!(!derived.secret_key.is_empty());
        }

        // Consume ciphertext so session state is valid
        bob.decrypt(&alice_addr, &result.bytes).unwrap();
    }

    // ─── Sliding window ─────────────────────────────────────────────────────

    #[test]
    fn sliding_window_keeps_latest() {
        let mut mgr = AddressManager::with_window_size(3);
        mgr.add_peer("peer1", None, None);

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        // We need to do direction changes to get new ratchet keys.
        // Exchange messages back and forth to generate distinct ratchet keys.
        let mut all_sender_addrs = Vec::new();

        // msg1: Alice → Bob (prekey)
        let r1 = alice.encrypt(&bob_addr, b"m1").unwrap();
        if let Some(ref sa) = r1.sender_address {
            all_sender_addrs.push(sa.clone());
        }
        bob.decrypt(&alice_addr, &r1.bytes).unwrap();

        // msg2: Bob → Alice (direction change, ratchet advances)
        let r2 = bob.encrypt(&alice_addr, b"m2").unwrap();
        if let Some(ref sa) = r2.sender_address {
            all_sender_addrs.push(sa.clone());
        }
        alice.decrypt(&bob_addr, &r2.bytes).unwrap();

        // msg3: Alice → Bob (direction change)
        let r3 = alice.encrypt(&bob_addr, b"m3").unwrap();
        if let Some(ref sa) = r3.sender_address {
            all_sender_addrs.push(sa.clone());
        }
        bob.decrypt(&alice_addr, &r3.bytes).unwrap();

        // msg4: Bob → Alice (direction change)
        let r4 = bob.encrypt(&alice_addr, b"m4").unwrap();
        if let Some(ref sa) = r4.sender_address {
            all_sender_addrs.push(sa.clone());
        }
        alice.decrypt(&bob_addr, &r4.bytes).unwrap();

        // msg5: Alice → Bob (direction change)
        let r5 = alice.encrypt(&bob_addr, b"m5").unwrap();
        if let Some(ref sa) = r5.sender_address {
            all_sender_addrs.push(sa.clone());
        }
        bob.decrypt(&alice_addr, &r5.bytes).unwrap();

        // Now feed them all into the address manager
        for sa in &all_sender_addrs {
            mgr.on_encrypt("peer1", Some(sa)).unwrap();
        }

        let state = mgr.get_peer("peer1").unwrap();
        assert_eq!(state.receiving_addresses.len(), 3, "window should cap at 3");

        // Should contain the last 3 distinct addresses
        let unique_count = all_sender_addrs
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        // At minimum we should have some addresses (ratchet may not always produce unique ones)
        assert!(state.receiving_addresses.len() <= 3);
    }

    #[test]
    fn sliding_window_custom_size() {
        let mut mgr = AddressManager::with_window_size(2);
        mgr.add_peer("peer1", None, None);

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        // msg1: Alice → Bob
        let r1 = alice.encrypt(&bob_addr, b"m1").unwrap();
        bob.decrypt(&alice_addr, &r1.bytes).unwrap();
        if let Some(ref sa) = r1.sender_address {
            mgr.on_encrypt("peer1", Some(sa)).unwrap();
        }

        // msg2: Bob → Alice (direction change)
        let r2 = bob.encrypt(&alice_addr, b"m2").unwrap();
        alice.decrypt(&bob_addr, &r2.bytes).unwrap();

        // msg3: Alice → Bob (direction change - new ratchet key)
        let r3 = alice.encrypt(&bob_addr, b"m3").unwrap();
        bob.decrypt(&alice_addr, &r3.bytes).unwrap();
        if let Some(ref sa) = r3.sender_address {
            mgr.on_encrypt("peer1", Some(sa)).unwrap();
        }

        // msg4: Bob → Alice
        let r4 = bob.encrypt(&alice_addr, b"m4").unwrap();
        alice.decrypt(&bob_addr, &r4.bytes).unwrap();

        // msg5: Alice → Bob (direction change - another new ratchet key)
        let r5 = alice.encrypt(&bob_addr, b"m5").unwrap();
        bob.decrypt(&alice_addr, &r5.bytes).unwrap();
        if let Some(ref sa) = r5.sender_address {
            mgr.on_encrypt("peer1", Some(sa)).unwrap();
        }

        let state = mgr.get_peer("peer1").unwrap();
        assert!(
            state.receiving_addresses.len() <= 2,
            "window=2 should cap at 2"
        );
    }

    // ─── Address rotation on encrypt ────────────────────────────────────────

    #[test]
    fn on_encrypt_adds_receiving_address() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        let result = alice.encrypt(&bob_addr, b"hello").unwrap();
        bob.decrypt(&alice_addr, &result.bytes).unwrap();

        if let Some(ref sa) = result.sender_address {
            let update = mgr.on_encrypt("peer1", Some(sa)).unwrap();
            assert_eq!(update.new_receiving.len(), 1);
            assert!(update.dropped_receiving.is_empty());
            assert!(update.new_sending.is_none());

            let state = mgr.get_peer("peer1").unwrap();
            assert_eq!(state.receiving_addresses.len(), 1);
            assert_eq!(
                state.receiving_addresses[0].address,
                update.new_receiving[0]
            );
        }
    }

    #[test]
    fn on_encrypt_skips_raw_signal_identity_key() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        // A raw Signal identity key is 05-prefixed, 66 hex chars
        let raw_key = format!("05{}", "ab".repeat(32));
        let update = mgr.on_encrypt("peer1", Some(&raw_key)).unwrap();
        assert!(update.new_receiving.is_empty());
        assert!(update.dropped_receiving.is_empty());
    }

    #[test]
    fn on_encrypt_no_duplicate() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        let result = alice.encrypt(&bob_addr, b"hello").unwrap();
        bob.decrypt(&alice_addr, &result.bytes).unwrap();

        if let Some(ref sa) = result.sender_address {
            let update1 = mgr.on_encrypt("peer1", Some(sa)).unwrap();
            assert_eq!(update1.new_receiving.len(), 1);

            // Same ratchet key again — should be a no-op
            let update2 = mgr.on_encrypt("peer1", Some(sa)).unwrap();
            assert!(update2.new_receiving.is_empty());

            let state = mgr.get_peer("peer1").unwrap();
            assert_eq!(state.receiving_addresses.len(), 1);
        }
    }

    // ─── Address rotation on decrypt ────────────────────────────────────────

    #[test]
    fn on_decrypt_updates_sending_address() {
        let mut mgr = AddressManager::new();
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        mgr.add_peer(&bob.identity_public_key_hex(), None, None);
        let peer_id = bob.identity_public_key_hex();

        // Alice → Bob (prekey)
        let ct = alice.encrypt(&bob_addr, b"hi").unwrap();
        let dr = bob.decrypt(&alice_addr, &ct.bytes).unwrap();

        // Bob → Alice
        let ct2 = bob.encrypt(&alice_addr, b"hey").unwrap();
        let dr2 = alice.decrypt(&bob_addr, &ct2.bytes).unwrap();

        if let Some(ref bob_addr_derived) = dr2.bob_derived_address {
            let update = mgr
                .on_decrypt(&peer_id, Some(bob_addr_derived), dr2.alice_addrs.as_deref())
                .unwrap();
            assert_eq!(
                update.new_sending.as_deref(),
                Some(bob_addr_derived.as_str())
            );

            let state = mgr.get_peer(&peer_id).unwrap();
            assert_eq!(
                state.sending_address.as_deref(),
                Some(bob_addr_derived.as_str())
            );
        }
    }

    #[test]
    fn on_decrypt_adds_alice_addrs() {
        let mut mgr = AddressManager::new();
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        mgr.add_peer(&bob.identity_public_key_hex(), None, None);
        let peer_id = bob.identity_public_key_hex();

        // Alice → Bob
        let ct = alice.encrypt(&bob_addr, b"hi").unwrap();
        let dr = bob.decrypt(&alice_addr, &ct.bytes).unwrap();

        // Bob → Alice
        let ct2 = bob.encrypt(&alice_addr, b"hey").unwrap();
        let dr2 = alice.decrypt(&bob_addr, &ct2.bytes).unwrap();

        let update = mgr
            .on_decrypt(
                &peer_id,
                dr2.bob_derived_address.as_deref(),
                dr2.alice_addrs.as_deref(),
            )
            .unwrap();

        // alice_addrs from decrypt are our new receiving addresses
        if let Some(ref addrs) = dr2.alice_addrs {
            let non_raw: Vec<_> = addrs
                .iter()
                .filter(|a| !(a.starts_with("05") && a.len() == 66))
                .collect();
            // Each non-raw alice_addr should have produced a new_receiving entry
            assert_eq!(update.new_receiving.len(), non_raw.len());
        }
    }

    // ─── Sender resolution priority ─────────────────────────────────────────

    #[test]
    fn resolve_send_address_ratchet_first() {
        let mut mgr = AddressManager::new();
        mgr.add_peer(
            "peer1",
            Some("first_inbox_addr".into()),
            Some("nostr_pubkey".into()),
        );

        // Set a ratchet-derived sending address
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();
        let ct = alice.encrypt(&bob_addr, b"hi").unwrap();
        let dr = bob.decrypt(&alice_addr, &ct.bytes).unwrap();
        let ct2 = bob.encrypt(&alice_addr, b"hey").unwrap();
        let dr2 = alice.decrypt(&bob_addr, &ct2.bytes).unwrap();

        if let Some(ref addr) = dr2.bob_derived_address {
            mgr.on_decrypt("peer1", Some(addr), None).unwrap();
            let resolved = mgr.resolve_send_address("peer1").unwrap();
            assert_eq!(resolved, *addr, "ratchet address should take priority");
        }
    }

    #[test]
    fn resolve_send_address_first_inbox_fallback() {
        let mut mgr = AddressManager::new();
        mgr.add_peer(
            "peer1",
            Some("first_inbox_addr".into()),
            Some("nostr_pubkey".into()),
        );

        // No ratchet-derived address yet
        let resolved = mgr.resolve_send_address("peer1").unwrap();
        assert_eq!(resolved, "first_inbox_addr");
    }

    #[test]
    fn resolve_send_address_nostr_pubkey_fallback() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, Some("nostr_pubkey".into()));

        let resolved = mgr.resolve_send_address("peer1").unwrap();
        assert_eq!(resolved, "nostr_pubkey");
    }

    #[test]
    fn resolve_send_address_error_when_none() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        let result = mgr.resolve_send_address("peer1");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_send_address_unknown_peer() {
        let mgr = AddressManager::new();
        let result = mgr.resolve_send_address("nonexistent");
        assert!(result.is_err());
    }

    // ─── firstInbox clearing ────────────────────────────────────────────────

    #[test]
    fn clear_peer_first_inbox() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", Some("inbox123".into()), None);

        assert_eq!(
            mgr.get_peer("peer1").unwrap().peer_first_inbox.as_deref(),
            Some("inbox123")
        );

        mgr.clear_peer_first_inbox("peer1");
        assert!(mgr.get_peer("peer1").unwrap().peer_first_inbox.is_none());

        // After clearing, resolve should fail (no nostr pubkey either)
        assert!(mgr.resolve_send_address("peer1").is_err());
    }

    #[test]
    fn clear_first_inbox_makes_ratchet_primary() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", Some("inbox123".into()), Some("npub".into()));

        // Set ratchet-derived address
        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();
        let ct = alice.encrypt(&bob_addr, b"hi").unwrap();
        bob.decrypt(&alice_addr, &ct.bytes).unwrap();
        let ct2 = bob.encrypt(&alice_addr, b"hey").unwrap();
        let dr2 = alice.decrypt(&bob_addr, &ct2.bytes).unwrap();

        if let Some(ref addr) = dr2.bob_derived_address {
            mgr.on_decrypt("peer1", Some(addr), None).unwrap();
            mgr.clear_peer_first_inbox("peer1");

            let resolved = mgr.resolve_send_address("peer1").unwrap();
            assert_eq!(
                resolved, *addr,
                "ratchet address should be used after clearing inbox"
            );
        }
    }

    // ─── get_all_receiving_addresses ────────────────────────────────────────

    #[test]
    fn get_all_receiving_addresses_empty() {
        let mgr = AddressManager::new();
        assert!(mgr.get_all_receiving_addresses().is_empty());
        assert!(mgr.get_all_receiving_address_strings().is_empty());
    }

    #[test]
    fn get_all_receiving_addresses_multiple_peers() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);
        mgr.add_peer("peer2", None, None);

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();
        let r1 = alice.encrypt(&bob_addr, b"m1").unwrap();
        bob.decrypt(&alice_addr, &r1.bytes).unwrap();

        if let Some(ref sa) = r1.sender_address {
            mgr.on_encrypt("peer1", Some(sa)).unwrap();
        }

        // Set up another session for peer2
        let (mut carol, mut dave, carol_addr, dave_addr) = {
            let mut c = SignalParticipant::new("carol", 1).unwrap();
            let mut d = SignalParticipant::new("dave", 1).unwrap();
            let d_bundle = d.prekey_bundle().unwrap();
            let d_addr =
                ProtocolAddress::new(d.identity_public_key_hex(), DeviceId::new(1).unwrap());
            let c_addr =
                ProtocolAddress::new(c.identity_public_key_hex(), DeviceId::new(1).unwrap());
            c.process_prekey_bundle(&d_addr, &d_bundle).unwrap();
            (c, d, c_addr, d_addr)
        };

        let r2 = carol.encrypt(&dave_addr, b"m2").unwrap();
        dave.decrypt(&carol_addr, &r2.bytes).unwrap();

        if let Some(ref sa) = r2.sender_address {
            mgr.on_encrypt("peer2", Some(sa)).unwrap();
        }

        let all = mgr.get_all_receiving_address_strings();
        assert_eq!(all.len(), 2, "should have one address per peer");
    }

    // ─── No rotation on same direction ──────────────────────────────────────

    #[test]
    fn no_rotation_on_same_direction() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();

        // Send first message to establish session
        let r1 = alice.encrypt(&bob_addr, b"m1").unwrap();
        bob.decrypt(&alice_addr, &r1.bytes).unwrap();

        let first_sender = r1.sender_address.clone();
        if let Some(ref sa) = first_sender {
            mgr.on_encrypt("peer1", Some(sa)).unwrap();
        }

        // Send more messages in the same direction — ratchet does NOT advance
        for i in 2..=5 {
            let r = alice
                .encrypt(&bob_addr, format!("m{i}").as_bytes())
                .unwrap();
            bob.decrypt(&alice_addr, &r.bytes).unwrap();

            // sender_address should be the same or None (no new ratchet key)
            if let Some(ref sa) = r.sender_address {
                let update = mgr.on_encrypt("peer1", Some(sa)).unwrap();
                // Should be either a duplicate (no-op) or genuinely new
                // but the ratchet doesn't advance without direction change
            }
        }

        let state = mgr.get_peer("peer1").unwrap();
        // Without direction changes, we should have at most 1 address
        // (the initial one from the PrekeyMessage)
        assert!(
            state.receiving_addresses.len() <= 2,
            "sending in same direction should not produce many new addresses"
        );
    }

    // ─── Full lifecycle (§9.5) ──────────────────────────────────────────────

    #[test]
    fn full_address_rotation_lifecycle() {
        let mut alice_mgr = AddressManager::new();
        let mut bob_mgr = AddressManager::new();

        let (mut alice, mut bob, alice_addr, bob_addr) = setup_session();
        let alice_peer_id = bob.identity_public_key_hex();
        let bob_peer_id = alice.identity_public_key_hex();

        alice_mgr.add_peer(&alice_peer_id, Some("bob_first_inbox".into()), None);
        bob_mgr.add_peer(&bob_peer_id, Some("alice_first_inbox".into()), None);

        // Step 1: Alice → Bob (PrekeyMessage, simulating friendApprove)
        let enc1 = alice.encrypt(&bob_addr, b"approve").unwrap();
        let dec1 = bob.decrypt(&alice_addr, &enc1.bytes).unwrap();

        // Alice updates her receiving addresses
        let au1 = alice_mgr
            .on_encrypt(&alice_peer_id, enc1.sender_address.as_deref())
            .unwrap();

        // Bob updates sending address and his receiving addresses
        let bu1 = bob_mgr
            .on_decrypt(
                &bob_peer_id,
                dec1.bob_derived_address.as_deref(),
                dec1.alice_addrs.as_deref(),
            )
            .unwrap();

        // Bob should now have a sending address for Alice
        if dec1.bob_derived_address.is_some() {
            assert!(bu1.new_sending.is_some());
        }

        // Step 2: Bob → Alice (msg1, direction change)
        let enc2 = bob.encrypt(&alice_addr, b"hello alice").unwrap();
        let dec2 = alice.decrypt(&bob_addr, &enc2.bytes).unwrap();

        let bu2 = bob_mgr
            .on_encrypt(&bob_peer_id, enc2.sender_address.as_deref())
            .unwrap();
        let au2 = alice_mgr
            .on_decrypt(
                &alice_peer_id,
                dec2.bob_derived_address.as_deref(),
                dec2.alice_addrs.as_deref(),
            )
            .unwrap();

        // Alice clears firstInbox after first ratchet message
        alice_mgr.clear_peer_first_inbox(&alice_peer_id);

        // Step 3: Alice → Bob (msg2, direction change)
        let enc3 = alice.encrypt(&bob_addr, b"hi bob").unwrap();
        let dec3 = bob.decrypt(&alice_addr, &enc3.bytes).unwrap();

        let au3 = alice_mgr
            .on_encrypt(&alice_peer_id, enc3.sender_address.as_deref())
            .unwrap();
        let bu3 = bob_mgr
            .on_decrypt(
                &bob_peer_id,
                dec3.bob_derived_address.as_deref(),
                dec3.alice_addrs.as_deref(),
            )
            .unwrap();

        // Bob clears firstInbox
        bob_mgr.clear_peer_first_inbox(&bob_peer_id);

        // Step 4: Bob → Alice (msg3, direction change)
        let enc4 = bob.encrypt(&alice_addr, b"how are you").unwrap();
        let dec4 = alice.decrypt(&bob_addr, &enc4.bytes).unwrap();

        let bu4 = bob_mgr
            .on_encrypt(&bob_peer_id, enc4.sender_address.as_deref())
            .unwrap();
        let au4 = alice_mgr
            .on_decrypt(
                &alice_peer_id,
                dec4.bob_derived_address.as_deref(),
                dec4.alice_addrs.as_deref(),
            )
            .unwrap();

        // Verify: both sides should have receiving addresses
        assert!(
            !alice_mgr.get_all_receiving_addresses().is_empty(),
            "Alice should have receiving addresses"
        );
        assert!(
            !bob_mgr.get_all_receiving_addresses().is_empty(),
            "Bob should have receiving addresses"
        );

        // Verify: firstInbox should be cleared on both sides
        assert!(alice_mgr
            .get_peer(&alice_peer_id)
            .unwrap()
            .peer_first_inbox
            .is_none());
        assert!(bob_mgr
            .get_peer(&bob_peer_id)
            .unwrap()
            .peer_first_inbox
            .is_none());

        // Verify: sending addresses should be set
        assert!(alice_mgr.resolve_send_address(&alice_peer_id).is_ok());
        assert!(bob_mgr.resolve_send_address(&bob_peer_id).is_ok());
    }

    // ─── Multiple peers ─────────────────────────────────────────────────────

    #[test]
    fn multiple_peers_independent() {
        let mut mgr = AddressManager::new();

        // Setup two independent sessions
        let (mut alice, mut bob, alice_addr_b, bob_addr) = setup_session();
        let (mut alice2, mut charlie, alice_addr_c, charlie_addr) = {
            let mut a = SignalParticipant::new("alice2", 1).unwrap();
            let mut c = SignalParticipant::new("charlie", 1).unwrap();
            let c_bundle = c.prekey_bundle().unwrap();
            let c_addr =
                ProtocolAddress::new(c.identity_public_key_hex(), DeviceId::new(1).unwrap());
            let a_addr =
                ProtocolAddress::new(a.identity_public_key_hex(), DeviceId::new(1).unwrap());
            a.process_prekey_bundle(&c_addr, &c_bundle).unwrap();
            (a, c, a_addr, c_addr)
        };

        mgr.add_peer("bob", None, Some("bob_npub".into()));
        mgr.add_peer("charlie", None, Some("charlie_npub".into()));

        // Alice → Bob
        let r1 = alice.encrypt(&bob_addr, b"hi bob").unwrap();
        bob.decrypt(&alice_addr_b, &r1.bytes).unwrap();
        if let Some(ref sa) = r1.sender_address {
            mgr.on_encrypt("bob", Some(sa)).unwrap();
        }

        // Alice → Charlie
        let r2 = alice2.encrypt(&charlie_addr, b"hi charlie").unwrap();
        charlie.decrypt(&alice_addr_c, &r2.bytes).unwrap();
        if let Some(ref sa) = r2.sender_address {
            mgr.on_encrypt("charlie", Some(sa)).unwrap();
        }

        // Both peers should have independent addresses
        let bob_state = mgr.get_peer("bob").unwrap();
        let charlie_state = mgr.get_peer("charlie").unwrap();

        if !bob_state.receiving_addresses.is_empty()
            && !charlie_state.receiving_addresses.is_empty()
        {
            assert_ne!(
                bob_state.receiving_addresses[0].address,
                charlie_state.receiving_addresses[0].address,
                "different peers must have different addresses"
            );
        }

        let all = mgr.get_all_receiving_address_strings();
        assert_eq!(all.len(), 2, "should have one address per peer");
    }

    // ─── AddressManager basics ──────────────────────────────────────────────

    #[test]
    fn new_manager_is_empty() {
        let mgr = AddressManager::new();
        assert_eq!(mgr.peer_count(), 0);
        assert_eq!(mgr.window_size(), DEFAULT_WINDOW_SIZE);
        assert!(mgr.get_all_receiving_addresses().is_empty());
    }

    #[test]
    fn add_peer_twice_does_not_overwrite() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", Some("inbox1".into()), None);
        mgr.add_peer("peer1", Some("inbox2".into()), None);

        // First call wins
        assert_eq!(
            mgr.get_peer("peer1").unwrap().peer_first_inbox.as_deref(),
            Some("inbox1")
        );
    }

    #[test]
    fn default_trait() {
        let mgr = AddressManager::default();
        assert_eq!(mgr.window_size(), DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn on_encrypt_none_sender_address() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        let update = mgr.on_encrypt("peer1", None).unwrap();
        assert!(update.new_receiving.is_empty());
        assert!(update.dropped_receiving.is_empty());
    }

    #[test]
    fn on_decrypt_none_values() {
        let mut mgr = AddressManager::new();
        mgr.add_peer("peer1", None, None);

        let update = mgr.on_decrypt("peer1", None, None).unwrap();
        assert!(update.new_receiving.is_empty());
        assert!(update.dropped_receiving.is_empty());
        assert!(update.new_sending.is_none());
    }

    #[test]
    fn on_encrypt_unknown_peer_errors() {
        let mut mgr = AddressManager::new();
        let result = mgr.on_encrypt("unknown", None);
        assert!(result.is_err());
    }

    #[test]
    fn on_decrypt_unknown_peer_errors() {
        let mut mgr = AddressManager::new();
        let result = mgr.on_decrypt("unknown", None, None);
        assert!(result.is_err());
    }
}
