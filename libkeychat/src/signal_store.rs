//! In-memory Signal Protocol stores.
//!
//! Wraps `libsignal-protocol`'s built-in `InMem*` stores. The `CapturingSessionStore`
//! intercepts `store_session` to parse the SessionRecord protobuf and extract
//! ratchet key information for Keychat's address rotation (§9).
//!
//! The official libsignal v0.88.3 does NOT expose ratchet keys via public API.
//! We extract them by deserializing the SessionRecord's protobuf (the same wire
//! format used by `SessionRecord::serialize()`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use libsignal_protocol::{
    InMemIdentityKeyStore, InMemKyberPreKeyStore, InMemPreKeyStore, InMemSessionStore,
    InMemSignedPreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError,
};

use crate::persistent_signal_store::{
    IdentityStoreBackend, KyberPreKeyStoreBackend, PersistentIdentityKeyStore,
    PersistentKyberPreKeyStore, PersistentPreKeyStore, PersistentSessionStore,
    PersistentSignedPreKeyStore, PreKeyStoreBackend, SessionStoreBackend,
    SignedPreKeyStoreBackend,
};
use crate::storage::SecureStorage;

// ─── Protobuf parsing ───────────────────────────────────────────────────────
//
// SessionRecord serializes to a RecordStructure protobuf:
//   RecordStructure {
//     field 1: current_session (SessionStructure, length-delimited)
//   }
//   SessionStructure {
//     field 6: sender_chain (Chain, length-delimited)
//     field 7: repeated receiver_chains (Chain, length-delimited)
//   }
//   Chain {
//     field 1: sender_ratchet_key (bytes)         — public key (33 bytes)
//     field 2: sender_ratchet_key_private (bytes)  — private key (32 bytes)
//   }

/// Ratchet key snapshot extracted from a SessionRecord.
#[derive(Clone, Debug, Default)]
struct RatchetSnapshot {
    /// Our sender chain private key (hex).
    sender_private: Option<String>,
    /// Our sender chain public key (hex).
    sender_public: Option<String>,
    /// Their latest ratchet public key (hex, from last receiver chain).
    their_public: Option<String>,
}

impl RatchetSnapshot {
    /// Build a ratchet key pair string "{our_priv}-{their_pub}" for address derivation.
    fn ratchet_key_pair(&self) -> Option<String> {
        match (&self.sender_private, &self.their_public) {
            (Some(priv_hex), Some(pub_hex)) => Some(format!("{}-{}", priv_hex, pub_hex)),
            _ => None,
        }
    }
}

/// Parse a SessionRecord's serialized bytes to extract ratchet key info.
fn parse_ratchet_snapshot(record: &SessionRecord) -> Option<RatchetSnapshot> {
    let bytes = record.serialize().ok()?;

    // RecordStructure field 1 = current_session
    let session_data = find_length_delimited_field(&bytes, 1)?;

    // SessionStructure field 6 = sender_chain
    let sender_chain = find_length_delimited_field(&session_data, 6)?;

    // Chain field 2 = sender_ratchet_key_private
    let private_key = find_length_delimited_field(&sender_chain, 2)?;

    // Chain field 1 = sender_ratchet_key (public)
    let public_key = find_length_delimited_field(&sender_chain, 1)?;

    // SessionStructure field 7 = receiver_chains (repeated)
    // Get the LAST one (most recent ratchet step)
    let receiver_chains = find_all_length_delimited_fields(&session_data, 7);
    let their_public = receiver_chains
        .last()
        .and_then(|chain| find_length_delimited_field(chain, 1))
        .filter(|k| !k.is_empty())
        .map(|k| hex::encode(&k));

    Some(RatchetSnapshot {
        sender_private: if !private_key.is_empty() {
            Some(hex::encode(&private_key))
        } else {
            None
        },
        sender_public: if !public_key.is_empty() {
            Some(hex::encode(&public_key))
        } else {
            None
        },
        their_public,
    })
}

// ─── CapturingSessionStore ──────────────────────────────────────────────────

/// A session store wrapper that captures ratchet-derived address information
/// by parsing SessionRecord protobuf on each store_session call.
///
/// Tracks two things per peer:
/// - `bob_addresses`: "{old_sender_priv}-{their_pub}" — for deriving the address where we
///   SEND to this peer (set when a DH ratchet step happens during decrypt)
/// - `my_receiver_addresses`: "{our_sender_priv}-{their_pub}" — for deriving the address
///   where THEY send to us (our receiving address)
/// - `last_alice_addrs`: ratchet key pairs from last decrypt (our new receiving addresses)
#[derive(Clone)]
pub struct CapturingSessionStore {
    inner: SessionStoreBackend,
    /// Peer name → ratchet key pair for bob's address ("{old_priv}-{their_pub}")
    pub bob_addresses: Arc<Mutex<BTreeMap<String, String>>>,
    /// Peer name → our receiving ratchet key ("{our_priv}-{their_pub}")
    pub my_receiver_addresses: Arc<Mutex<BTreeMap<String, String>>>,
    /// Peer name → snapshot BEFORE the latest encrypt/decrypt
    snapshots: Arc<Mutex<BTreeMap<String, RatchetSnapshot>>>,
    /// Peer name → alice_addrs from last store_session (ratchet keys for our receiving addrs)
    pub last_alice_addrs: Arc<Mutex<BTreeMap<String, Vec<String>>>>,
}

impl Default for CapturingSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CapturingSessionStore {
    pub fn new() -> Self {
        Self {
            inner: SessionStoreBackend::InMemory(InMemSessionStore::new()),
            bob_addresses: Arc::new(Mutex::new(BTreeMap::new())),
            my_receiver_addresses: Arc::new(Mutex::new(BTreeMap::new())),
            snapshots: Arc::new(Mutex::new(BTreeMap::new())),
            last_alice_addrs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Create a persistent session store backed by SecureStorage.
    pub fn persistent(storage: Arc<Mutex<SecureStorage>>) -> Self {
        Self {
            inner: SessionStoreBackend::Persistent(PersistentSessionStore::new(storage)),
            bob_addresses: Arc::new(Mutex::new(BTreeMap::new())),
            my_receiver_addresses: Arc::new(Mutex::new(BTreeMap::new())),
            snapshots: Arc::new(Mutex::new(BTreeMap::new())),
            last_alice_addrs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Snapshot the current session state for a peer. Must be called BEFORE encrypt/decrypt.
    pub fn snapshot_session(&self, address: &ProtocolAddress) {
        if let Ok(Some(record)) = futures::executor::block_on(self.inner.load_session(address)) {
            if let Some(snap) = parse_ratchet_snapshot(&record) {
                self.snapshots
                    .lock()
                    .unwrap()
                    .insert(address.name().to_owned(), snap);
            }
        }
    }

    /// Take and clear the last alice_addrs for a peer.
    pub fn take_alice_addrs(&self, peer: &str) -> Option<Vec<String>> {
        self.last_alice_addrs.lock().unwrap().remove(peer)
    }
}

#[async_trait::async_trait(?Send)]
impl SessionStore for CapturingSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> std::result::Result<Option<SessionRecord>, SignalProtocolError> {
        self.inner.load_session(address).await
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        let new_snap = parse_ratchet_snapshot(record);
        let old_snap = self
            .snapshots
            .lock()
            .unwrap()
            .get(address.name())
            .cloned();

        if let Some(ref snap) = new_snap {
            // Always update my_receiver_addresses with current ratchet key pair
            if let Some(addr) = snap.ratchet_key_pair() {
                self.my_receiver_addresses
                    .lock()
                    .unwrap()
                    .insert(address.name().to_owned(), addr);
            }

            // Detect DH ratchet step: sender chain private key changed
            let ratchet_stepped = match &old_snap {
                Some(old) => old.sender_private != snap.sender_private,
                None => snap.their_public.is_some(), // First store with receiver chain
            };

            if ratchet_stepped {
                // DH ratchet happened (during decrypt).
                // bob_address = "{old_sender_priv}-{their_new_pub}" → where we SEND to them
                if let Some(ref old) = old_snap {
                    if let (Some(ref old_priv), Some(ref their_pub)) =
                        (&old.sender_private, &snap.their_public)
                    {
                        let bob_addr = format!("{}-{}", old_priv, their_pub);
                        self.bob_addresses
                            .lock()
                            .unwrap()
                            .insert(address.name().to_owned(), bob_addr);
                    }
                }

                // alice_addrs = ratchet key pairs for our new receiving addresses
                if let Some(addr) = snap.ratchet_key_pair() {
                    self.last_alice_addrs
                        .lock()
                        .unwrap()
                        .insert(address.name().to_owned(), vec![addr]);
                }
            }
        }

        self.inner.store_session(address, record).await
    }
}

// ─── SignalProtocolStoreBundle ───────────────────────────────────────────────

/// Complete Signal Protocol store bundle for a single participant.
#[derive(Clone)]
pub struct SignalProtocolStoreBundle {
    pub session_store: CapturingSessionStore,
    pub pre_key_store: PreKeyStoreBackend,
    pub signed_pre_key_store: SignedPreKeyStoreBackend,
    pub kyber_pre_key_store: KyberPreKeyStoreBackend,
    pub identity_store: IdentityStoreBackend,
}

impl SignalProtocolStoreBundle {
    /// Create an in-memory store bundle (for tests and backward compatibility).
    pub fn new(
        identity_key_pair: libsignal_protocol::IdentityKeyPair,
        registration_id: u32,
    ) -> Self {
        Self {
            session_store: CapturingSessionStore::new(),
            pre_key_store: PreKeyStoreBackend::InMemory(InMemPreKeyStore::new()),
            signed_pre_key_store: SignedPreKeyStoreBackend::InMemory(
                InMemSignedPreKeyStore::new(),
            ),
            kyber_pre_key_store: KyberPreKeyStoreBackend::InMemory(InMemKyberPreKeyStore::new()),
            identity_store: IdentityStoreBackend::InMemory(InMemIdentityKeyStore::new(
                identity_key_pair,
                registration_id,
            )),
        }
    }

    /// Create a persistent store bundle backed by SecureStorage (SQLCipher).
    pub fn persistent(
        storage: Arc<Mutex<SecureStorage>>,
        identity_key_pair: libsignal_protocol::IdentityKeyPair,
        registration_id: u32,
    ) -> Self {
        Self {
            session_store: CapturingSessionStore::persistent(storage.clone()),
            pre_key_store: PreKeyStoreBackend::Persistent(PersistentPreKeyStore::new(
                storage.clone(),
            )),
            signed_pre_key_store: SignedPreKeyStoreBackend::Persistent(
                PersistentSignedPreKeyStore::new(storage.clone()),
            ),
            kyber_pre_key_store: KyberPreKeyStoreBackend::Persistent(
                PersistentKyberPreKeyStore::new(storage.clone()),
            ),
            identity_store: IdentityStoreBackend::Persistent(PersistentIdentityKeyStore::new(
                storage,
                identity_key_pair,
                registration_id,
            )),
        }
    }
}

// ─── Minimal protobuf decoder ───────────────────────────────────────────────

/// Parse a protobuf varint. Returns (value, bytes_consumed).
fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= ((byte & 0x7F) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

/// Find the first length-delimited field (wire type 2) with the given field number.
fn find_length_delimited_field(data: &[u8], field_number: u32) -> Option<Vec<u8>> {
    find_all_length_delimited_fields(data, field_number)
        .into_iter()
        .next()
}

/// Find ALL length-delimited fields with the given field number (for repeated fields).
fn find_all_length_delimited_fields(data: &[u8], field_number: u32) -> Vec<Vec<u8>> {
    let mut results = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let Some((tag, tag_len)) = parse_varint(&data[offset..]) else {
            break;
        };
        offset += tag_len;
        let wire_type = (tag & 0x07) as u32;
        let field_num = (tag >> 3) as u32;

        match wire_type {
            0 => {
                // Varint — skip
                let Some((_, val_len)) = parse_varint(&data[offset..]) else {
                    break;
                };
                offset += val_len;
            }
            1 => {
                // 64-bit fixed
                if offset + 8 > data.len() {
                    break;
                }
                offset += 8;
            }
            2 => {
                // Length-delimited
                let Some((len, len_len)) = parse_varint(&data[offset..]) else {
                    break;
                };
                offset += len_len;
                let len = len as usize;
                if offset + len > data.len() {
                    break;
                }
                if field_num == field_number {
                    results.push(data[offset..offset + len].to_vec());
                }
                offset += len;
            }
            5 => {
                // 32-bit fixed
                if offset + 4 > data.len() {
                    break;
                }
                offset += 4;
            }
            _ => break,
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::IdentityKeyPair;
    #[test]
    fn store_bundle_creation() {
        let identity = IdentityKeyPair::generate(&mut ::rand::rng());
        let bundle = SignalProtocolStoreBundle::new(identity, 42);
        assert!(bundle
            .session_store
            .bob_addresses
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn protobuf_varint_parsing() {
        assert_eq!(parse_varint(&[10]), Some((10, 1)));
        assert_eq!(parse_varint(&[0xAC, 0x02]), Some((300, 2)));
        assert_eq!(parse_varint(&[]), None);
    }

    #[test]
    fn protobuf_field_extraction() {
        // field 1 (wire type 2), length 3, data "abc"
        let data = vec![0x0A, 0x03, b'a', b'b', b'c'];
        assert_eq!(find_length_delimited_field(&data, 1), Some(b"abc".to_vec()));
        assert_eq!(find_length_delimited_field(&data, 2), None);
    }

    #[test]
    fn protobuf_repeated_fields() {
        // Two field 7 entries
        let mut data = Vec::new();
        // field 7, wire type 2 → tag = (7 << 3) | 2 = 58 = 0x3A
        data.extend_from_slice(&[0x3A, 0x02, b'A', b'B']);
        data.extend_from_slice(&[0x3A, 0x03, b'C', b'D', b'E']);
        let results = find_all_length_delimited_fields(&data, 7);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], b"AB");
        assert_eq!(results[1], b"CDE");
    }
}
