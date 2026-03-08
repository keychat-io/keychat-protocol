use libkeychat::client::types::ClientSnapshot;
use libkeychat::protocol::address::AddressManager;
use libkeychat::signal::SignalParticipant;
use libkeychat::storage::sqlite::SqliteStore;
use std::collections::BTreeMap;

#[test]
fn snapshot_roundtrip_through_sqlite() {
    let db_path = "/tmp/libkeychat_test_persistence.db";
    let _ = std::fs::remove_file(db_path);
    let store = SqliteStore::open(db_path).unwrap();

    // Build a snapshot with a real Signal participant
    let mut alice = SignalParticipant::new("alice", 1).unwrap();
    let mut bob = SignalParticipant::new("bob", 1).unwrap();

    // Establish session
    let bob_bundle = bob.prekey_bundle().unwrap();
    alice
        .process_prekey_bundle(bob.address(), &bob_bundle)
        .unwrap();
    let ct = alice.encrypt(bob.address(), b"init").unwrap();
    bob.decrypt(alice.address(), &ct).unwrap();

    // Snapshot alice
    let alice_snap = alice.snapshot().unwrap();

    let mut signals = BTreeMap::new();
    signals.insert("bob_pubkey".to_string(), alice_snap);

    let mut remote_addrs = BTreeMap::new();
    remote_addrs.insert("bob_pubkey".to_string(), ("bob".to_string(), 1u32));

    let snapshot = ClientSnapshot {
        signals,
        remote_addrs,
        address_manager: AddressManager::default(),
    };

    // Save
    let blob = serde_json::to_vec(&snapshot).unwrap();
    store.save_state("client_snapshot_v1", &blob).unwrap();

    // Load
    let loaded_blob = store.load_state("client_snapshot_v1").unwrap().unwrap();
    let loaded: ClientSnapshot = serde_json::from_slice(&loaded_blob).unwrap();

    assert_eq!(loaded.signals.len(), 1);
    assert!(loaded.signals.contains_key("bob_pubkey"));
    assert_eq!(loaded.remote_addrs["bob_pubkey"], ("bob".to_string(), 1u32));

    // Restore Signal participant and verify it can still encrypt
    let restored_snap = loaded.signals.get("bob_pubkey").unwrap().clone();
    let mut restored_alice = SignalParticipant::from_snapshot(restored_snap).unwrap();

    // Send a message with the restored session
    let ct2 = restored_alice
        .encrypt(bob.address(), b"after restore")
        .unwrap();
    let pt2 = bob.decrypt(alice.address(), &ct2).unwrap();
    assert_eq!(pt2, b"after restore");

    // Cleanup
    let _ = std::fs::remove_file(db_path);
}

#[test]
fn save_state_overwrites_previous() {
    let db_path = "/tmp/libkeychat_test_overwrite.db";
    let _ = std::fs::remove_file(db_path);
    let store = SqliteStore::open(db_path).unwrap();

    store.save_state("key1", b"value1").unwrap();
    assert_eq!(store.load_state("key1").unwrap().unwrap(), b"value1");

    store.save_state("key1", b"value2").unwrap();
    assert_eq!(store.load_state("key1").unwrap().unwrap(), b"value2");

    assert!(store.load_state("nonexistent").unwrap().is_none());

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn list_peers_returns_stored_peers() {
    let db_path = "/tmp/libkeychat_test_list_peers.db";
    let _ = std::fs::remove_file(db_path);
    let mut store = SqliteStore::open(db_path).unwrap();

    use libkeychat::storage::DataStore;
    use libkeychat::storage::StoredPeer;

    store
        .upsert_peer(StoredPeer {
            peer_id: "peer1".into(),
            nostr_pubkey: "npub1".into(),
            signal_pubkey: "sig1".into(),
            name: "Alice".into(),
        })
        .unwrap();

    store
        .upsert_peer(StoredPeer {
            peer_id: "peer2".into(),
            nostr_pubkey: "npub2".into(),
            signal_pubkey: "sig2".into(),
            name: "Bob".into(),
        })
        .unwrap();

    let peers = store.list_peers().unwrap();
    assert_eq!(peers.len(), 2);

    let _ = std::fs::remove_file(db_path);
}
