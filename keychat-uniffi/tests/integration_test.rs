use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use keychat_uniffi::*;

/// A minimal EventListener that counts events received.
struct TestListener {
    count: Arc<AtomicU32>,
}

impl TestListener {
    fn new() -> (Self, Arc<AtomicU32>) {
        let count = Arc::new(AtomicU32::new(0));
        (
            TestListener {
                count: count.clone(),
            },
            count,
        )
    }
}

impl EventListener for TestListener {
    fn on_event(&self, _event: ClientEvent) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

/// A DataListener that records all DataChange events.
struct TestDataListener {
    changes: Arc<Mutex<Vec<String>>>,
}

impl TestDataListener {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let changes = Arc::new(Mutex::new(Vec::new()));
        (
            TestDataListener {
                changes: changes.clone(),
            },
            changes,
        )
    }
}

impl DataListener for TestDataListener {
    fn on_data_change(&self, change: DataChange) {
        let label = match change {
            DataChange::RoomUpdated { room_id } => format!("RoomUpdated:{room_id}"),
            DataChange::RoomDeleted { room_id } => format!("RoomDeleted:{room_id}"),
            DataChange::RoomListChanged => "RoomListChanged".into(),
            DataChange::MessageAdded { room_id, msgid } => {
                format!("MessageAdded:{room_id}:{msgid}")
            }
            DataChange::MessageUpdated { room_id, msgid } => {
                format!("MessageUpdated:{room_id}:{msgid}")
            }
            DataChange::ContactUpdated { pubkey } => format!("ContactUpdated:{pubkey}"),
            DataChange::ContactListChanged => "ContactListChanged".into(),
            DataChange::IdentityListChanged => "IdentityListChanged".into(),
        };
        self.changes.lock().unwrap().push(label);
    }
}

fn temp_db(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_str().unwrap().to_string()
}

/// KeychatClient embeds its own tokio Runtime. Dropping a Runtime inside
/// another Runtime's `block_on` panics. To work around this, each test
/// runs on a dedicated OS thread and explicitly drops the client before
/// the outer Runtime is dropped.
macro_rules! async_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            std::thread::spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async { $body });
            })
            .join()
            .unwrap();
        }
    };
}

async_test!(create_client_and_identity, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let result = client.create_identity().await.unwrap();
    assert!(!result.pubkey_hex.is_empty(), "pubkey should not be empty");
    assert!(!result.mnemonic.is_empty(), "mnemonic should not be empty");

    let pubkey = client.get_pubkey_hex().await.unwrap();
    assert_eq!(pubkey, result.pubkey_hex);

    // Drop client before runtime shutdown
    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(import_identity_from_mnemonic, {
    let dir = tempfile::tempdir().unwrap();
    let db1 = temp_db(&dir, "client1.db");
    let db2 = temp_db(&dir, "client2.db");

    let client1 = KeychatClient::new(db1, "test-key".into()).unwrap();
    let result = client1.create_identity().await.unwrap();

    let client2 = KeychatClient::new(db2, "test-key".into()).unwrap();
    let pubkey2 = client2.import_identity(result.mnemonic).await.unwrap();

    assert_eq!(result.pubkey_hex, pubkey2);

    tokio::task::spawn_blocking(move || {
        drop(client1);
        drop(client2);
    })
    .await
    .unwrap();
});

async_test!(get_pubkey_before_identity_fails, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let result = client.get_pubkey_hex().await;
    assert!(
        result.is_err(),
        "get_pubkey_hex should fail without identity"
    );

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(set_event_listener_works, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();
    let (listener, _count) = TestListener::new();

    client.set_event_listener(Box::new(listener)).await;

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(two_clients_different_identities, {
    let dir = tempfile::tempdir().unwrap();
    let db1 = temp_db(&dir, "alice.db");
    let db2 = temp_db(&dir, "bob.db");

    let alice = KeychatClient::new(db1, "test-key".into()).unwrap();
    let bob = KeychatClient::new(db2, "test-key".into()).unwrap();

    let alice_id = alice.create_identity().await.unwrap();
    let bob_id = bob.create_identity().await.unwrap();

    assert_ne!(alice_id.pubkey_hex, bob_id.pubkey_hex);
    assert_ne!(alice_id.mnemonic, bob_id.mnemonic);

    tokio::task::spawn_blocking(move || {
        drop(alice);
        drop(bob);
    })
    .await
    .unwrap();
});

async_test!(empty_receiving_addresses_without_sessions, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();
    client.create_identity().await.unwrap();

    let addrs = client.get_all_receiving_addresses().await;
    assert!(
        addrs.is_empty(),
        "should have no receiving addresses without sessions"
    );

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(connect_without_identity_fails, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let result = client.connect(vec!["wss://relay.example.com".into()]).await;
    assert!(result.is_err(), "connect should fail without identity");

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

// ─── Phase 2: DataListener + App Data Tests ─────────────────────

async_test!(set_data_listener_works, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();
    let (listener, _changes) = TestDataListener::new();

    client.set_data_listener(Box::new(listener)).await;

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(app_identity_crud_via_ffi, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    // Initially empty
    let ids = client.get_identities().await.unwrap();
    assert!(ids.is_empty());

    // Save identity
    client
        .save_app_identity_ffi(
            "npub1test".into(),
            "abcd1234".into(),
            "Alice".into(),
            0,
            true,
        )
        .await
        .unwrap();

    let ids = client.get_identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].name, "Alice");
    assert_eq!(ids[0].npub, "npub1test");
    assert!(ids[0].is_default);

    // Update identity
    client
        .update_app_identity_ffi(
            "npub1test".into(),
            Some("Alice Updated".into()),
            None,
            None,
        )
        .await
        .unwrap();

    let ids = client.get_identities().await.unwrap();
    assert_eq!(ids[0].name, "Alice Updated");

    // Delete identity
    client
        .delete_app_identity_ffi("npub1test".into())
        .await
        .unwrap();

    let ids = client.get_identities().await.unwrap();
    assert!(ids.is_empty());

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(app_room_and_message_crud_via_ffi, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let identity_npub = "npub1me";

    // Create a room via FFI
    let room_id = client
        .save_app_room_ffi(
            "peer_pubkey_hex".into(), identity_npub.into(),
            1, 0, Some("Bob".into()),
        )
        .await
        .unwrap();

    // Query rooms via FFI
    let rooms = client.get_rooms(identity_npub.into()).await.unwrap();
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].name.as_deref(), Some("Bob"));
    assert_eq!(rooms[0].status, 1);
    assert_eq!(rooms[0].unread_count, 0);

    // Get room by ID
    let room = client.get_room(room_id.clone()).await.unwrap();
    assert!(room.is_some());
    assert_eq!(room.unwrap().to_main_pubkey, "peer_pubkey_hex");

    // Add messages via FFI
    client
        .save_app_message_ffi(
            "msg1".into(), Some("evt1".into()), room_id.clone(), identity_npub.into(),
            "peer_pubkey_hex".into(), "Hello!".into(), false, 1, 1000,
        )
        .await
        .unwrap();
    client
        .save_app_message_ffi(
            "msg2".into(), Some("evt2".into()), room_id.clone(), identity_npub.into(),
            identity_npub.into(), "Hi back!".into(), true, 1, 1001,
        )
        .await
        .unwrap();
    client.increment_app_room_unread_ffi(room_id.clone()).await.unwrap();
    client.increment_app_room_unread_ffi(room_id.clone()).await.unwrap();

    // Query messages via FFI
    let msgs = client.get_messages(room_id.clone(), 100, 0).await.unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].content, "Hello!");
    assert!(!msgs[0].is_me_send);
    assert_eq!(msgs[1].content, "Hi back!");
    assert!(msgs[1].is_me_send);

    // Message count
    let count = client.get_message_count(room_id.clone()).await.unwrap();
    assert_eq!(count, 2);

    // Check unread
    let rooms = client.get_rooms(identity_npub.into()).await.unwrap();
    assert_eq!(rooms[0].unread_count, 2);

    // Mark room read
    client.mark_room_read(room_id.clone()).await.unwrap();

    let rooms = client.get_rooms(identity_npub.into()).await.unwrap();
    assert_eq!(rooms[0].unread_count, 0);

    // Verify messages are marked read
    let msgs = client.get_messages(room_id, 100, 0).await.unwrap();
    assert!(msgs[0].is_read);
    assert!(msgs[1].is_read);

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(app_contact_crud_via_ffi, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let identity_npub = "npub1me";

    // Create contacts via FFI
    client
        .save_app_contact_ffi(
            "pubkey_bob".into(), "npub1bob".into(),
            identity_npub.into(), Some("Bob".into()),
        )
        .await
        .unwrap();
    client
        .save_app_contact_ffi(
            "pubkey_alice".into(), "npub1alice".into(),
            identity_npub.into(), Some("Alice".into()),
        )
        .await
        .unwrap();

    // Query via FFI
    let contacts = client.get_contacts(identity_npub.into()).await.unwrap();
    assert_eq!(contacts.len(), 2);

    // Update petname via FFI
    client
        .update_contact_petname(
            "pubkey_bob".into(),
            identity_npub.into(),
            "Bobby".into(),
        )
        .await
        .unwrap();

    let contacts = client.get_contacts(identity_npub.into()).await.unwrap();
    let bob = contacts.iter().find(|c| c.pubkey == "pubkey_bob").unwrap();
    assert_eq!(bob.petname.as_deref(), Some("Bobby"));

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(message_dedup_via_ffi, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let identity_npub = "npub1me";

    // Create room
    let room_id = client
        .save_app_room_ffi("peer".into(), identity_npub.into(), 1, 0, None)
        .await
        .unwrap();

    // First message
    client
        .save_app_message_ffi(
            "msg1".into(), Some("event_abc".into()), room_id.clone(), identity_npub.into(),
            "peer".into(), "Hello".into(), false, 1, 1000,
        )
        .await
        .unwrap();

    // Check dedup via FFI
    assert!(client.is_app_message_duplicate_ffi("event_abc".into()).await.unwrap());
    assert!(!client.is_app_message_duplicate_ffi("event_xyz".into()).await.unwrap());

    // INSERT OR IGNORE: second save with same msgid should not error
    client
        .save_app_message_ffi(
            "msg1".into(), Some("event_abc".into()), room_id.clone(), identity_npub.into(),
            "peer".into(), "Hello duplicate".into(), false, 1, 1000,
        )
        .await
        .unwrap();

    // Should still have only 1 message with original content
    let count = client.get_message_count(room_id.clone()).await.unwrap();
    assert_eq!(count, 1);

    let msgs = client.get_messages(room_id, 100, 0).await.unwrap();
    assert_eq!(msgs[0].content, "Hello");

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(message_reply_to_resolution_via_ffi, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let identity_npub = "npub1me";

    let room_id = client
        .save_app_room_ffi("peer".into(), identity_npub.into(), 1, 0, None)
        .await
        .unwrap();

    // Original message
    client
        .save_app_message_ffi(
            "msg1".into(), Some("event_original".into()), room_id.clone(), identity_npub.into(),
            "peer".into(), "Original message".into(), false, 1, 1000,
        )
        .await
        .unwrap();

    // Reply message
    client
        .save_app_message_ffi(
            "msg2".into(), Some("event_reply".into()), room_id.clone(), identity_npub.into(),
            identity_npub.into(), "Reply text".into(), true, 1, 1001,
        )
        .await
        .unwrap();

    // Update reply with reply_to metadata via FFI
    client
        .update_app_message_ffi(
            "msg2".into(),
            None, None, None, None, None,
            Some("event_original".into()),
            Some("Original message".into()),
        )
        .await
        .unwrap();

    // Verify
    let msgs = client.get_messages(room_id, 100, 0).await.unwrap();
    assert_eq!(msgs.len(), 2);
    let reply = &msgs[1];
    assert_eq!(reply.reply_to_event_id.as_deref(), Some("event_original"));
    assert_eq!(reply.reply_to_content.as_deref(), Some("Original message"));

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(room_last_message_and_ordering, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();

    let identity_npub = "npub1me";

    // Room A - older last message
    let room_a_id = client
        .save_app_room_ffi("peer_a".into(), identity_npub.into(), 1, 0, Some("Alice".into()))
        .await
        .unwrap();
    client
        .update_app_room_ffi(room_a_id, None, None, Some("Old msg".into()), Some(1000))
        .await
        .unwrap();

    // Room B - newer last message
    let room_b_id = client
        .save_app_room_ffi("peer_b".into(), identity_npub.into(), 1, 0, Some("Bob".into()))
        .await
        .unwrap();
    client
        .update_app_room_ffi(room_b_id, None, None, Some("New msg".into()), Some(2000))
        .await
        .unwrap();

    // Rooms should be ordered by last_message_at DESC
    let rooms = client.get_rooms(identity_npub.into()).await.unwrap();
    assert_eq!(rooms.len(), 2);
    assert_eq!(rooms[0].name.as_deref(), Some("Bob")); // newer first
    assert_eq!(rooms[0].last_message_content.as_deref(), Some("New msg"));
    assert_eq!(rooms[1].name.as_deref(), Some("Alice"));
    assert_eq!(rooms[1].last_message_content.as_deref(), Some("Old msg"));

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(npub_hex_conversion, {
    // Generate a real identity to get a valid pubkey hex
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "test.db");
    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();
    let result = client.create_identity().await.unwrap();
    let hex = result.pubkey_hex;

    let npub = npub_from_hex(hex.clone()).unwrap();
    assert!(npub.starts_with("npub1"));

    let back = hex_from_npub(npub.clone()).unwrap();
    assert_eq!(back, hex);

    // normalize_to_hex should handle both formats
    let from_hex = normalize_to_hex(hex.clone()).unwrap();
    assert_eq!(from_hex, hex);

    let from_npub = normalize_to_hex(npub).unwrap();
    assert_eq!(from_npub, hex);

    // Invalid inputs
    assert!(npub_from_hex("not-a-hex".into()).is_err());
    assert!(hex_from_npub("not-an-npub".into()).is_err());

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});
