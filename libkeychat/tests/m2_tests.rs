use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::ProtocolAddress;

use libkeychat::identity::generate_random_nostr_keypair;
use libkeychat::protocol::address::AddressManager;
use libkeychat::protocol::hello::{create_hello, receive_hello};
use libkeychat::protocol::message_types::{KeychatMessage, TYPE_DM};
use libkeychat::protocol::messaging::{receive_message, send_signal_message};
use libkeychat::signal::keys::generate_prekey_material;
use libkeychat::signal::{SignalDecryptResult, SignalParticipant};
use libkeychat::storage::memory::MemoryStore;
use libkeychat::storage::sqlite::SqliteStore;
use libkeychat::storage::{DataStore, StoredPeer, StoredSignalIdentity, StoredSignalSession};

#[test]
fn address_manager_tracks_hello_and_rotating_addresses() {
    let mut manager = AddressManager::default();
    manager.track_pending_hello(
        "peer",
        "peer_nostr".to_owned(),
        "one".to_owned(),
        "sig".to_owned(),
    );
    assert_eq!(
        manager.get_sending_address("peer").as_deref(),
        Some("peer_nostr")
    );
    assert_eq!(manager.get_all_receiving_addresses(), vec!["one", "sig"]);

    let result = SignalDecryptResult {
        plaintext: Vec::new(),
        message_key_hash: "hash".to_owned(),
        alice_addrs: Some(vec![
            "a1".to_owned(),
            "a2".to_owned(),
            "a3".to_owned(),
            "a4".to_owned(),
        ]),
        bob_derived_address: None,
    };
    let changes = manager.on_message_decrypted("peer", &result);
    assert!(changes.iter().any(|change| matches!(change, libkeychat::protocol::address::AddressChange::Subscribe(value) if value == "a4")));
    assert_eq!(
        manager.get_sending_address("peer").as_deref(),
        Some("peer_nostr")
    );
    assert_eq!(
        manager.get_all_receiving_addresses(),
        vec!["a2", "a3", "a4"]
    );
}

#[test]
fn hello_message_roundtrip_and_auto_reply_decrypts() {
    let alice_nostr = generate_random_nostr_keypair();
    let bob_nostr = generate_random_nostr_keypair();

    let bob_material = generate_prekey_material().expect("bob prekeys");
    let bob_signal_name = hex::encode(bob_material.identity_key_pair.identity_key().serialize());
    let mut bob_signal =
        SignalParticipant::from_prekey_material(bob_signal_name.clone(), 1, bob_material)
            .expect("bob signal");

    let mut alice_manager = AddressManager::default();
    let hello = create_hello(
        &alice_nostr,
        &bob_nostr.public_key_hex(),
        "alice",
        "Hi, I'm Alice",
        &bob_nostr.public_key_hex(),
        &mut alice_manager,
    )
    .expect("hello");

    let mut alice_signal = hello.signal.clone();
    let mut bob_manager = AddressManager::default();
    let outcome = receive_hello(&bob_nostr, &mut bob_signal, &mut bob_manager, &hello.event)
        .expect("receive hello");

    let reply = receive_message(
        &alice_nostr,
        &mut alice_signal,
        &ProtocolAddress::new(bob_nostr.public_key_hex(), 1u32.into()),
        &mut alice_manager,
        &bob_nostr.public_key_hex(),
        &outcome.auto_reply,
    )
    .expect("receive reply");

    assert_eq!(reply.message.r#type, TYPE_DM);
    assert!(reply.message.msg.contains("Hi"));
    assert!(reply
        .decrypt_result
        .as_ref()
        .and_then(|result| result.bob_derived_address.as_ref())
        .is_some());
}

#[test]
fn hello_reverse_bob_initiates_alice_receives() {
    let alice_nostr = generate_random_nostr_keypair();
    let bob_nostr = generate_random_nostr_keypair();

    let mut bob_manager = AddressManager::default();
    let hello = create_hello(
        &bob_nostr,
        &alice_nostr.public_key_hex(),
        "bob",
        "Hi, I'm Bob",
        &alice_nostr.public_key_hex(),
        &mut bob_manager,
    )
    .expect("hello");

    let mut bob_signal = hello.signal.clone();
    let mut alice_signal = SignalParticipant::new("alice", 1).expect("alice signal");
    let mut alice_manager = AddressManager::default();
    let outcome = receive_hello(
        &alice_nostr,
        &mut alice_signal,
        &mut alice_manager,
        &hello.event,
    )
    .expect("receive hello");

    assert!(!outcome.address_changes.is_empty());
    assert!(outcome.address_changes.iter().any(|change| {
        matches!(
            change,
            libkeychat::protocol::address::AddressChange::UpdateSendAddr { peer_id, address }
                if peer_id == &bob_nostr.public_key_hex() && address == &outcome.peer.onetimekey
        )
    }));
    // After accepting hello and sending auto-reply, there should be a Subscribe
    // for the ratchet-derived Nostr address (from encrypt's my_receiver_address)
    assert!(
        outcome.address_changes.iter().any(|change| {
            matches!(
                change,
                libkeychat::protocol::address::AddressChange::Subscribe(_)
            )
        }),
        "expected at least one Subscribe address change from auto-reply encrypt"
    );
    assert_eq!(
        alice_manager
            .get_sending_address(&bob_nostr.public_key_hex())
            .as_deref(),
        Some(outcome.peer.onetimekey.as_str())
    );
    // After accepting hello and auto-replying, receiving addresses should contain
    // a ratchet-derived Nostr address (not the raw identity key)
    assert!(
        !alice_manager.get_all_receiving_addresses().is_empty(),
        "should have at least one receiving address after auto-reply"
    );

    let auto_reply = receive_message(
        &bob_nostr,
        &mut bob_signal,
        alice_signal.address(),
        &mut bob_manager,
        &alice_nostr.public_key_hex(),
        &outcome.auto_reply,
    )
    .expect("receive auto reply");

    assert_eq!(auto_reply.message.r#type, TYPE_DM);
    assert!(auto_reply.message.msg.contains("Hi, bob"));
    assert_ne!(
        bob_manager
            .get_sending_address(&alice_nostr.public_key_hex())
            .as_deref(),
        Some(alice_nostr.public_key_hex().as_str())
    );

    let follow_up = KeychatMessage {
        c: "signal".to_owned(),
        r#type: TYPE_DM,
        msg: "Did you get my hello?".to_owned(),
        name: None,
    };
    let (follow_up_event, _) = send_signal_message(
        &bob_nostr,
        &mut bob_signal,
        alice_signal.address(),
        &mut bob_manager,
        &alice_nostr.public_key_hex(),
        &follow_up,
    )
    .expect("send follow up");

    let follow_up_received = receive_message(
        &alice_nostr,
        &mut alice_signal,
        &outcome.remote_signal_address,
        &mut alice_manager,
        &bob_nostr.public_key_hex(),
        &follow_up_event,
    )
    .expect("receive follow up");

    assert_eq!(follow_up_received.message, follow_up);
    assert!(follow_up_received
        .decrypt_result
        .as_ref()
        .and_then(|result| result.bob_derived_address.as_ref())
        .is_some());

    let alice_reply = KeychatMessage {
        c: "signal".to_owned(),
        r#type: TYPE_DM,
        msg: "Yes, and this is my reply.".to_owned(),
        name: None,
    };
    let (alice_reply_event, _) = send_signal_message(
        &alice_nostr,
        &mut alice_signal,
        &outcome.remote_signal_address,
        &mut alice_manager,
        &bob_nostr.public_key_hex(),
        &alice_reply,
    )
    .expect("send alice reply");

    let alice_reply_received = receive_message(
        &bob_nostr,
        &mut bob_signal,
        alice_signal.address(),
        &mut bob_manager,
        &alice_nostr.public_key_hex(),
        &alice_reply_event,
    )
    .expect("receive alice reply");

    assert_eq!(alice_reply_received.message, alice_reply);
}

#[test]
fn signal_messages_roundtrip_over_kind4() {
    let alice_nostr = generate_random_nostr_keypair();
    let bob_nostr = generate_random_nostr_keypair();
    let mut alice = SignalParticipant::new("alice", 1).expect("alice");
    let mut bob = SignalParticipant::new("bob", 1).expect("bob");

    let bob_bundle = bob.prekey_bundle().expect("bundle");
    alice
        .process_prekey_bundle(bob.address(), &bob_bundle)
        .expect("process bundle");

    let mut alice_manager = AddressManager::default();
    let mut bob_manager = AddressManager::default();
    let _ = alice_manager.set_sending_address("bob", "bob-addr".to_owned());
    let _ = bob_manager.set_sending_address("alice", "alice-addr".to_owned());

    let outbound = KeychatMessage {
        c: "signal".to_owned(),
        r#type: TYPE_DM,
        msg: "hello".to_owned(),
        name: None,
    };
    let (event, _) = send_signal_message(
        &alice_nostr,
        &mut alice,
        bob.address(),
        &mut alice_manager,
        "bob",
        &outbound,
    )
    .expect("send");

    let received = receive_message(
        &bob_nostr,
        &mut bob,
        alice.address(),
        &mut bob_manager,
        "alice",
        &event,
    )
    .expect("receive");

    assert_eq!(received.message, outbound);
    assert!(event.first_tag_value("p").is_some());
}

#[test]
fn sqlite_and_memory_store_roundtrip() {
    let mut memory = MemoryStore::default();
    exercise_store(&mut memory);

    let path = std::env::temp_dir().join(format!(
        "libkeychat-{}.sqlite",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let mut sqlite = SqliteStore::open(path.to_str().expect("path")).expect("sqlite open");
    exercise_store(&mut sqlite);
    let _ = std::fs::remove_file(path);
}

fn exercise_store(store: &mut dyn DataStore) {
    let session = StoredSignalSession {
        peer_id: "peer".to_owned(),
        device_id: 1,
        record: vec![1, 2, 3],
    };
    store
        .upsert_signal_session(session.clone())
        .expect("session");
    assert_eq!(
        store.load_signal_sessions("peer").expect("load sessions"),
        vec![session]
    );

    store.upsert_prekey("pre", vec![7]).expect("prekey");
    assert_eq!(
        store.load_prekey("pre").expect("load prekey"),
        Some(vec![7])
    );

    store
        .upsert_signed_prekey("signed", vec![8])
        .expect("signed prekey");
    assert_eq!(
        store.load_signed_prekey("signed").expect("load signed"),
        Some(vec![8])
    );

    let identity = StoredSignalIdentity {
        key_id: "identity".to_owned(),
        registration_id: 9,
        record: vec![1, 1, 1],
    };
    store
        .upsert_identity_key(identity.clone())
        .expect("identity");
    assert_eq!(
        store.load_identity_key("identity").expect("load identity"),
        Some(identity)
    );

    let peer = StoredPeer {
        peer_id: "peer".to_owned(),
        nostr_pubkey: "nostr".to_owned(),
        signal_pubkey: "signal".to_owned(),
        name: "Peer".to_owned(),
    };
    store.upsert_peer(peer.clone()).expect("peer");
    assert_eq!(store.load_peer("peer").expect("load peer"), Some(peer));

    store
        .map_receiving_address("addr", "peer")
        .expect("addr map");
    assert_eq!(
        store.resolve_receiving_address("addr").expect("resolve"),
        Some("peer".to_owned())
    );

    assert!(!store.has_processed_event("evt").expect("missing evt"));
    store.mark_processed_event("evt").expect("mark evt");
    assert!(store.has_processed_event("evt").expect("evt"));
}
