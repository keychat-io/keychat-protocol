use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use keychat_uniffi::*;

// ─── Network test helpers ────────────────────────────────────────

const TEST_RELAY: &str = "wss://backup.keychat.io";

/// EventListener that captures the last received ClientEvent for network tests.
struct CapturingEventListener {
    events: Arc<Mutex<Vec<ClientEvent>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl CapturingEventListener {
    fn new(notify: Arc<tokio::sync::Notify>) -> (Self, Arc<Mutex<Vec<ClientEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            CapturingEventListener {
                events: events.clone(),
                notify,
            },
            events,
        )
    }
}

impl EventListener for CapturingEventListener {
    fn on_event(&self, event: ClientEvent) {
        self.events.lock().unwrap().push(event);
        self.notify.notify_one();
    }
}

/// Wait until the predicate is true on the captured events, or timeout.
/// Returns true if predicate matched, false on timeout.
async fn wait_for_event<F>(
    events: &Arc<Mutex<Vec<ClientEvent>>>,
    notify: &Arc<tokio::sync::Notify>,
    timeout_secs: u64,
    predicate: F,
) -> bool
where
    F: Fn(&ClientEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        {
            let guard = events.lock().unwrap();
            if guard.iter().any(|e| predicate(e)) {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::timeout(deadline - tokio::time::Instant::now(), notify.notified())
            .await
            .ok();
    }
}

/// Create a fresh KeychatClient with a temp DB.
fn make_client(dir: &tempfile::TempDir, name: &str) -> KeychatClient {
    KeychatClient::new(
        dir.path().join(name).to_str().unwrap().to_string(),
        "test-key".into(),
    )
    .unwrap()
}

/// Drop a KeychatClient safely from within an async context (avoids Runtime-in-Runtime panic).
async fn drop_client(client: KeychatClient) {
    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
}

/// Establish a friendship: sender → send_friend_request → receiver accepts → wait for accepted.
/// Returns (sender_pubkey_hex, receiver_pubkey_hex).
async fn establish_friendship(
    sender: &KeychatClient,
    sender_name: &str,
    receiver: &KeychatClient,
    receiver_name: &str,
    receiver_events: &Arc<Mutex<Vec<ClientEvent>>>,
    receiver_notify: &Arc<tokio::sync::Notify>,
    sender_events: &Arc<Mutex<Vec<ClientEvent>>>,
    sender_notify: &Arc<tokio::sync::Notify>,
) -> (String, String) {
    let sender_pubkey = sender.get_pubkey_hex().await.unwrap();
    let receiver_pubkey = receiver.get_pubkey_hex().await.unwrap();

    // Give the event loop a moment to subscribe
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let pending = sender
        .send_friend_request(
            receiver_pubkey.clone(),
            sender_name.into(),
            "device-1".into(),
        )
        .await
        .unwrap();

    // Wait for receiver to get the friend request
    let got_request = wait_for_event(receiver_events, receiver_notify, 30, |e| {
        matches!(e, ClientEvent::FriendRequestReceived { .. })
    })
    .await;
    assert!(
        got_request,
        "receiver did not receive friend request in time"
    );

    // Extract request_id
    let request_id = {
        let guard = receiver_events.lock().unwrap();
        guard
            .iter()
            .find_map(|e| {
                if let ClientEvent::FriendRequestReceived { request_id, .. } = e {
                    Some(request_id.clone())
                } else {
                    None
                }
            })
            .unwrap_or(pending.request_id.clone())
    };

    receiver
        .accept_friend_request(request_id, receiver_name.into())
        .await
        .unwrap();

    // Wait for sender to receive acceptance
    let got_accepted = wait_for_event(sender_events, sender_notify, 30, |e| {
        matches!(e, ClientEvent::FriendRequestAccepted { .. })
    })
    .await;
    assert!(
        got_accepted,
        "sender did not receive friend request acceptance in time"
    );

    (sender_pubkey, receiver_pubkey)
}

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
            DataChange::ConnectionStatusChanged { status, message } => {
                format!(
                    "ConnectionStatusChanged:{:?}:{}",
                    status,
                    message.unwrap_or_default()
                )
            }
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
            "abcd1234".into(),
            "npub1test".into(),
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
        .update_app_identity_ffi("abcd1234".into(), Some("Alice Updated".into()), None, None)
        .await
        .unwrap();

    let ids = client.get_identities().await.unwrap();
    assert_eq!(ids[0].name, "Alice Updated");

    // Delete identity
    client
        .delete_app_identity_ffi("abcd1234".into())
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
            "peer_pubkey_hex".into(),
            identity_npub.into(),
            RoomStatus::Enabled,
            RoomType::Dm,
            Some("Bob".into()),
            None,
        )
        .await
        .unwrap();

    // Query rooms via FFI
    let rooms = client.get_rooms(identity_npub.into()).await.unwrap();
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].name.as_deref(), Some("Bob"));
    assert_eq!(rooms[0].status, RoomStatus::Enabled);
    assert_eq!(rooms[0].unread_count, 0);

    // Get room by ID
    let room = client.get_room(room_id.clone()).await.unwrap();
    assert!(room.is_some());
    assert_eq!(room.unwrap().to_main_pubkey, "peer_pubkey_hex");

    // Add messages via FFI
    client
        .save_app_message_ffi(
            "msg1".into(),
            Some("evt1".into()),
            room_id.clone(),
            identity_npub.into(),
            "peer_pubkey_hex".into(),
            "Hello!".into(),
            false,
            MessageStatus::Success,
            1000,
        )
        .await
        .unwrap();
    client
        .save_app_message_ffi(
            "msg2".into(),
            Some("evt2".into()),
            room_id.clone(),
            identity_npub.into(),
            identity_npub.into(),
            "Hi back!".into(),
            true,
            MessageStatus::Success,
            1001,
        )
        .await
        .unwrap();
    client
        .increment_app_room_unread_ffi(room_id.clone())
        .await
        .unwrap();
    client
        .increment_app_room_unread_ffi(room_id.clone())
        .await
        .unwrap();

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
            "pubkey_bob".into(),
            "npub1bob".into(),
            identity_npub.into(),
            Some("Bob".into()),
        )
        .await
        .unwrap();
    client
        .save_app_contact_ffi(
            "pubkey_alice".into(),
            "npub1alice".into(),
            identity_npub.into(),
            Some("Alice".into()),
        )
        .await
        .unwrap();

    // Query via FFI
    let contacts = client.get_contacts(identity_npub.into()).await.unwrap();
    assert_eq!(contacts.len(), 2);

    // Update petname via FFI
    client
        .update_contact_petname("pubkey_bob".into(), identity_npub.into(), "Bobby".into())
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
        .save_app_room_ffi(
            "peer".into(),
            identity_npub.into(),
            RoomStatus::Enabled,
            RoomType::Dm,
            None,
            None,
        )
        .await
        .unwrap();

    // First message
    client
        .save_app_message_ffi(
            "msg1".into(),
            Some("event_abc".into()),
            room_id.clone(),
            identity_npub.into(),
            "peer".into(),
            "Hello".into(),
            false,
            MessageStatus::Success,
            1000,
        )
        .await
        .unwrap();

    // Check dedup via FFI
    assert!(client
        .is_app_message_duplicate_ffi("event_abc".into())
        .await
        .unwrap());
    assert!(!client
        .is_app_message_duplicate_ffi("event_xyz".into())
        .await
        .unwrap());

    // INSERT OR IGNORE: second save with same msgid should not error
    client
        .save_app_message_ffi(
            "msg1".into(),
            Some("event_abc".into()),
            room_id.clone(),
            identity_npub.into(),
            "peer".into(),
            "Hello duplicate".into(),
            false,
            MessageStatus::Success,
            1000,
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
        .save_app_room_ffi(
            "peer".into(),
            identity_npub.into(),
            RoomStatus::Enabled,
            RoomType::Dm,
            None,
            None,
        )
        .await
        .unwrap();

    // Original message
    client
        .save_app_message_ffi(
            "msg1".into(),
            Some("event_original".into()),
            room_id.clone(),
            identity_npub.into(),
            "peer".into(),
            "Original message".into(),
            false,
            MessageStatus::Success,
            1000,
        )
        .await
        .unwrap();

    // Reply message
    client
        .save_app_message_ffi(
            "msg2".into(),
            Some("event_reply".into()),
            room_id.clone(),
            identity_npub.into(),
            identity_npub.into(),
            "Reply text".into(),
            true,
            MessageStatus::Success,
            1001,
        )
        .await
        .unwrap();

    // Update reply with reply_to metadata via FFI
    client
        .update_app_message_ffi(
            "msg2".into(),
            None,
            None,
            None,
            None,
            None,
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
        .save_app_room_ffi(
            "peer_a".into(),
            identity_npub.into(),
            RoomStatus::Enabled,
            RoomType::Dm,
            Some("Alice".into()),
            None,
        )
        .await
        .unwrap();
    client
        .update_app_room_ffi(room_a_id, None, None, Some("Old msg".into()), Some(1000))
        .await
        .unwrap();

    // Room B - newer last message
    let room_b_id = client
        .save_app_room_ffi(
            "peer_b".into(),
            identity_npub.into(),
            RoomStatus::Enabled,
            RoomType::Dm,
            Some("Bob".into()),
            None,
        )
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

// ─── Network Integration Tests ───────────────────────────────────
//
// These tests require a live relay at wss://backup.keychat.io.
// Run with: cargo test -p keychat-uniffi --test integration_test -- network_ --ignored
//
// Marked #[ignore] so normal `cargo test` skips them; CI can opt-in explicitly.

/// Friend request → accept → verify both sides have enabled DM room + contact in DB.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_friend_request_and_accept_db() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice.db"));
            let bob = Arc::new(make_client(&dir, "bob.db"));

            let alice_result = alice.create_identity().await.unwrap();
            let bob_result = bob.create_identity().await.unwrap();
            let alice_pubkey = alice_result.pubkey_hex.clone();
            let bob_pubkey = bob_result.pubkey_hex.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();

            // Set up event listeners before starting event loops
            let alice_notify = Arc::new(tokio::sync::Notify::new());
            let bob_notify = Arc::new(tokio::sync::Notify::new());
            let (alice_listener, alice_events) = CapturingEventListener::new(alice_notify.clone());
            let (bob_listener, bob_events) = CapturingEventListener::new(bob_notify.clone());
            alice.set_event_listener(Box::new(alice_listener)).await;
            bob.set_event_listener(Box::new(bob_listener)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();

            establish_friendship(
                &alice,
                "Alice",
                &bob,
                "Bob",
                &bob_events,
                &bob_notify,
                &alice_events,
                &alice_notify,
            )
            .await;

            // Allow DB writes to settle
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Alice: DM room with Bob exists, status=Enabled, type=Dm
            let alice_rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
            let alice_dm = alice_rooms.iter().find(|r| r.to_main_pubkey == bob_pubkey);
            assert!(alice_dm.is_some(), "Alice should have a room with Bob");
            assert_eq!(alice_dm.unwrap().status, RoomStatus::Enabled);
            assert_eq!(alice_dm.unwrap().room_type, RoomType::Dm);

            // Alice: Bob is in contacts
            let alice_contacts = alice.get_contacts(alice_pubkey.clone()).await.unwrap();
            assert!(
                alice_contacts.iter().any(|c| c.pubkey == bob_pubkey),
                "Alice should have Bob as a contact"
            );

            // Bob: DM room with Alice exists, status=Enabled
            let bob_rooms = bob.get_rooms(bob_pubkey.clone()).await.unwrap();
            let bob_dm = bob_rooms.iter().find(|r| r.to_main_pubkey == alice_pubkey);
            assert!(bob_dm.is_some(), "Bob should have a room with Alice");
            assert_eq!(bob_dm.unwrap().status, RoomStatus::Enabled);
            assert_eq!(bob_dm.unwrap().room_type, RoomType::Dm);

            // Bob: Alice is in contacts
            let bob_contacts = bob.get_contacts(bob_pubkey.clone()).await.unwrap();
            assert!(
                bob_contacts.iter().any(|c| c.pubkey == alice_pubkey),
                "Bob should have Alice as a contact"
            );

            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

/// Send 3 alternating messages → verify both sides see correct content, direction, count,
/// and that room.last_message_content reflects the final message.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_message_persisted_after_send_and_receive() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice.db"));
            let bob = Arc::new(make_client(&dir, "bob.db"));

            let alice_result = alice.create_identity().await.unwrap();
            let bob_result = bob.create_identity().await.unwrap();
            let alice_pubkey = alice_result.pubkey_hex.clone();
            let bob_pubkey = bob_result.pubkey_hex.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let alice_notify = Arc::new(tokio::sync::Notify::new());
            let bob_notify = Arc::new(tokio::sync::Notify::new());
            let (alice_listener, alice_events) = CapturingEventListener::new(alice_notify.clone());
            let (bob_listener, bob_events) = CapturingEventListener::new(bob_notify.clone());
            alice.set_event_listener(Box::new(alice_listener)).await;
            bob.set_event_listener(Box::new(bob_listener)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();

            establish_friendship(
                &alice, "Alice", &bob, "Bob",
                &bob_events, &bob_notify,
                &alice_events, &alice_notify,
            )
            .await;

            // Wait for Signal session to stabilize after ratchet exchange
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Helper: wait until a MessageReceived event with matching content appears
            let wait_msg = |events: Arc<Mutex<Vec<ClientEvent>>>,
                             notify: Arc<tokio::sync::Notify>,
                             expected: String| async move {
                let matched = wait_for_event(&events, &notify, 30, |e| {
                    matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if c == &expected)
                })
                .await;
                assert!(matched, "did not receive message '{}' in time", expected);
            };

            // Round 1: Alice → Bob
            alice
                .send_text(bob_pubkey.clone(), "msg1".into(), None, None, None)
                .await
                .unwrap();
            wait_msg(bob_events.clone(), bob_notify.clone(), "msg1".into()).await;

            // Round 2: Bob → Alice
            bob
                .send_text(alice_pubkey.clone(), "msg2".into(), None, None, None)
                .await
                .unwrap();
            wait_msg(alice_events.clone(), alice_notify.clone(), "msg2".into()).await;

            // Round 3: Alice → Bob
            alice
                .send_text(bob_pubkey.clone(), "msg3".into(), None, None, None)
                .await
                .unwrap();
            wait_msg(bob_events.clone(), bob_notify.clone(), "msg3".into()).await;

            // Allow DB writes to settle
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // ── Alice DB assertions ──
            let alice_rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
            let alice_dm = alice_rooms.iter().find(|r| r.to_main_pubkey == bob_pubkey).unwrap();
            let alice_msgs = alice
                .get_messages(alice_dm.id.clone(), 50, 0)
                .await
                .unwrap();
            // Filter out system messages (e.g. "[Friend Request Sent]")
            let alice_text: Vec<_> = alice_msgs.iter().filter(|m| !m.content.starts_with('[')).collect();
            assert_eq!(alice_text.len(), 3, "Alice should have 3 text messages");
            assert_eq!(alice_text[0].content, "msg1");
            assert!(alice_text[0].is_me_send, "msg1 should be sent by Alice");
            assert_eq!(alice_text[1].content, "msg2");
            assert!(!alice_text[1].is_me_send, "msg2 should be received by Alice");
            assert_eq!(alice_text[2].content, "msg3");
            assert!(alice_text[2].is_me_send, "msg3 should be sent by Alice");

            let alice_count = alice.get_message_count(alice_dm.id.clone()).await.unwrap();
            // At least 3 text messages (system messages may also be present)
            assert!(alice_count >= 3, "Alice message count should be >= 3");

            let alice_room = alice.get_room(alice_dm.id.clone()).await.unwrap().unwrap();
            assert_eq!(alice_room.last_message_content.as_deref(), Some("msg3"));

            // ── Bob DB assertions ──
            let bob_rooms = bob.get_rooms(bob_pubkey.clone()).await.unwrap();
            let bob_dm = bob_rooms.iter().find(|r| r.to_main_pubkey == alice_pubkey).unwrap();
            let bob_msgs = bob
                .get_messages(bob_dm.id.clone(), 50, 0)
                .await
                .unwrap();
            let bob_text: Vec<_> = bob_msgs.iter().filter(|m| !m.content.starts_with('[')).collect();
            assert_eq!(bob_text.len(), 3, "Bob should have 3 text messages");
            assert_eq!(bob_text[0].content, "msg1");
            assert!(!bob_text[0].is_me_send, "msg1 should be received by Bob");
            assert_eq!(bob_text[1].content, "msg2");
            assert!(bob_text[1].is_me_send, "msg2 should be sent by Bob");
            assert_eq!(bob_text[2].content, "msg3");
            assert!(!bob_text[2].is_me_send, "msg3 should be received by Bob");

            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

/// Create a Signal group with Alice + Bob + Charlie → verify room type and member count in DB.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_group_db_state_after_create() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice.db"));
            let bob = Arc::new(make_client(&dir, "bob.db"));
            let charlie = Arc::new(make_client(&dir, "charlie.db"));

            let alice_result = alice.create_identity().await.unwrap();
            let bob_result = bob.create_identity().await.unwrap();
            let charlie_result = charlie.create_identity().await.unwrap();
            let alice_pubkey = alice_result.pubkey_hex.clone();
            let bob_pubkey = bob_result.pubkey_hex.clone();
            let charlie_pubkey = charlie_result.pubkey_hex.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();
            charlie.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let alice_notify = Arc::new(tokio::sync::Notify::new());
            let bob_notify = Arc::new(tokio::sync::Notify::new());
            let charlie_notify = Arc::new(tokio::sync::Notify::new());
            let (alice_listener, alice_events) = CapturingEventListener::new(alice_notify.clone());
            let (bob_listener, bob_events) = CapturingEventListener::new(bob_notify.clone());
            let (charlie_listener, charlie_events) =
                CapturingEventListener::new(charlie_notify.clone());
            alice.set_event_listener(Box::new(alice_listener)).await;
            bob.set_event_listener(Box::new(bob_listener)).await;
            charlie.set_event_listener(Box::new(charlie_listener)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();
            Arc::clone(&charlie).start_event_loop().await.unwrap();

            // Alice ↔ Bob friendship
            establish_friendship(
                &alice,
                "Alice",
                &bob,
                "Bob",
                &bob_events,
                &bob_notify,
                &alice_events,
                &alice_notify,
            )
            .await;

            // Alice ↔ Charlie friendship
            // Reset alice_events for reuse in second friendship
            alice_events.lock().unwrap().clear();
            establish_friendship(
                &alice,
                "Alice",
                &charlie,
                "Charlie",
                &charlie_events,
                &charlie_notify,
                &alice_events,
                &alice_notify,
            )
            .await;

            // Wait for sessions to stabilize
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Alice creates group with Bob and Charlie
            let group_info = alice
                .create_signal_group(
                    "TestGroup".into(),
                    vec![
                        GroupMemberInput {
                            nostr_pubkey: bob_pubkey.clone(),
                            name: "Bob".into(),
                        },
                        GroupMemberInput {
                            nostr_pubkey: charlie_pubkey.clone(),
                            name: "Charlie".into(),
                        },
                    ],
                )
                .await
                .unwrap();

            assert_eq!(group_info.member_count, 3, "Group should have 3 members");

            // Wait for Bob and Charlie to receive invites
            let bob_got_invite = wait_for_event(&bob_events, &bob_notify, 30, |e| {
                matches!(e, ClientEvent::GroupInviteReceived { .. })
            })
            .await;
            assert!(bob_got_invite, "Bob should receive group invite");

            let charlie_got_invite = wait_for_event(&charlie_events, &charlie_notify, 30, |e| {
                matches!(e, ClientEvent::GroupInviteReceived { .. })
            })
            .await;
            assert!(charlie_got_invite, "Charlie should receive group invite");

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Alice: group room exists with type=SignalGroup
            let alice_rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
            let group_room = alice_rooms.iter().find(|r| r.id == group_info.group_id);
            assert!(group_room.is_some(), "Alice should have the group room");
            assert_eq!(group_room.unwrap().room_type, RoomType::SignalGroup);

            // Alice: group has 3 members
            let members = alice
                .get_signal_group_members(group_info.group_id.clone())
                .await
                .unwrap();
            assert_eq!(members.len(), 3, "Group should have 3 members in DB");
            assert!(
                members.iter().any(|m| m.is_admin),
                "Group should have at least one admin"
            );

            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            charlie.stop_event_loop().await;
            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(charlie).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

/// Send 3 group messages (alternating Alice/Bob) → verify both sides have all messages in DB.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_group_message_persisted() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice.db"));
            let bob = Arc::new(make_client(&dir, "bob.db"));

            let alice_result = alice.create_identity().await.unwrap();
            let bob_result = bob.create_identity().await.unwrap();
            let alice_pubkey = alice_result.pubkey_hex.clone();
            let bob_pubkey = bob_result.pubkey_hex.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let alice_notify = Arc::new(tokio::sync::Notify::new());
            let bob_notify = Arc::new(tokio::sync::Notify::new());
            let (alice_listener, alice_events) = CapturingEventListener::new(alice_notify.clone());
            let (bob_listener, bob_events) = CapturingEventListener::new(bob_notify.clone());
            alice.set_event_listener(Box::new(alice_listener)).await;
            bob.set_event_listener(Box::new(bob_listener)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();

            establish_friendship(
                &alice, "Alice", &bob, "Bob",
                &bob_events, &bob_notify,
                &alice_events, &alice_notify,
            )
            .await;

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Alice creates group with Bob
            let group_info = alice
                .create_signal_group(
                    "MsgTestGroup".into(),
                    vec![GroupMemberInput {
                        nostr_pubkey: bob_pubkey.clone(),
                        name: "Bob".into(),
                    }],
                )
                .await
                .unwrap();
            let group_id = group_info.group_id.clone();

            // Wait for Bob to receive the invite
            let bob_got_invite = wait_for_event(&bob_events, &bob_notify, 30, |e| {
                matches!(e, ClientEvent::GroupInviteReceived { .. })
            })
            .await;
            assert!(bob_got_invite, "Bob should receive group invite");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let wait_group_msg = |events: Arc<Mutex<Vec<ClientEvent>>>,
                                   notify: Arc<tokio::sync::Notify>,
                                   expected: String| async move {
                let matched = wait_for_event(&events, &notify, 30, |e| {
                    matches!(e, ClientEvent::MessageReceived { content: Some(c), group_id: Some(_), .. } if c == &expected)
                })
                .await;
                assert!(matched, "did not receive group message '{}' in time", expected);
            };

            // Round 1: Alice → group
            alice
                .send_group_text(group_id.clone(), "grp1".into(), None)
                .await
                .unwrap();
            wait_group_msg(bob_events.clone(), bob_notify.clone(), "grp1".into()).await;

            // Round 2: Bob → group
            bob
                .send_group_text(group_id.clone(), "grp2".into(), None)
                .await
                .unwrap();
            wait_group_msg(alice_events.clone(), alice_notify.clone(), "grp2".into()).await;

            // Round 3: Alice → group
            alice
                .send_group_text(group_id.clone(), "grp3".into(), None)
                .await
                .unwrap();
            wait_group_msg(bob_events.clone(), bob_notify.clone(), "grp3".into()).await;

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // ── DB assertions ──
            let alice_msgs = alice.get_messages(group_id.clone(), 50, 0).await.unwrap();
            let alice_group_text: Vec<_> =
                alice_msgs.iter().filter(|m| !m.content.starts_with('[')).collect();
            assert_eq!(alice_group_text.len(), 3, "Alice should see 3 group messages");
            assert_eq!(alice_group_text[0].content, "grp1");
            assert!(alice_group_text[0].is_me_send);
            assert_eq!(alice_group_text[1].content, "grp2");
            assert!(!alice_group_text[1].is_me_send);
            assert_eq!(alice_group_text[2].content, "grp3");
            assert!(alice_group_text[2].is_me_send);

            let bob_rooms = bob.get_rooms(bob_pubkey.clone()).await.unwrap();
            let bob_group = bob_rooms
                .iter()
                .find(|r| r.room_type == RoomType::SignalGroup);
            assert!(bob_group.is_some(), "Bob should have a group room");
            let bob_group_id = bob_group.unwrap().id.clone();

            let bob_msgs = bob.get_messages(bob_group_id.clone(), 50, 0).await.unwrap();
            let bob_group_text: Vec<_> =
                bob_msgs.iter().filter(|m| !m.content.starts_with('[')).collect();
            assert_eq!(bob_group_text.len(), 3, "Bob should see 3 group messages");
            assert_eq!(bob_group_text[0].content, "grp1");
            assert!(!bob_group_text[0].is_me_send);
            assert_eq!(bob_group_text[1].content, "grp2");
            assert!(bob_group_text[1].is_me_send);
            assert_eq!(bob_group_text[2].content, "grp3");
            assert!(!bob_group_text[2].is_me_send);

            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════
// Tests for the architectural fixes (Issues 1-10)
// ═══════════════════════════════════════════════════════════════════════

// ─── Issue 8: cached_identity_pubkey ─────────────────────────────────

async_test!(cached_identity_pubkey_after_create, {
    let dir = tempfile::tempdir().unwrap();
    let client = KeychatClient::new(temp_db(&dir, "t.db"), "k".into()).unwrap();

    // Before identity: fails
    assert!(client.get_pubkey_hex().await.is_err());

    // After create: works without inner lock
    let result = client.create_identity().await.unwrap();
    let pubkey = client.get_pubkey_hex().await.unwrap();
    assert_eq!(pubkey, result.pubkey_hex);
    assert_eq!(pubkey.len(), 64, "hex pubkey must be 64 chars");

    drop_client(client).await;
});

async_test!(cached_identity_pubkey_after_import, {
    let dir = tempfile::tempdir().unwrap();
    let c1 = KeychatClient::new(temp_db(&dir, "c1.db"), "k".into()).unwrap();
    let r = c1.create_identity().await.unwrap();

    let c2 = KeychatClient::new(temp_db(&dir, "c2.db"), "k".into()).unwrap();
    let pubkey = c2.import_identity(r.mnemonic).await.unwrap();
    assert_eq!(c2.get_pubkey_hex().await.unwrap(), pubkey);
    assert_eq!(pubkey.len(), 64);

    drop_client(c1).await;
    drop_client(c2).await;
});

async_test!(cached_identity_pubkey_is_stable, {
    let dir = tempfile::tempdir().unwrap();
    let client = KeychatClient::new(temp_db(&dir, "t.db"), "k".into()).unwrap();
    client.create_identity().await.unwrap();

    // Multiple calls must be identical
    let pk1 = client.get_pubkey_hex().await.unwrap();
    let pk2 = client.get_pubkey_hex().await.unwrap();
    let pk3 = client.get_pubkey_hex().await.unwrap();
    assert_eq!(pk1, pk2);
    assert_eq!(pk2, pk3);

    drop_client(client).await;
});

// ─── Schema sanity ──────────────────────────────────────────────────

async_test!(schema_created_on_open, {
    let dir = tempfile::tempdir().unwrap();
    let client = KeychatClient::new(temp_db(&dir, "t.db"), "k".into()).unwrap();

    client.create_identity().await.unwrap();
    let summary = client.debug_state_summary().await.unwrap();
    assert!(summary.contains("sessions="));

    drop_client(client).await;
});

// ─── Issue 1/3: restore_sessions ─────────────────────────────────────

async_test!(restore_sessions_zero_on_fresh_db, {
    let dir = tempfile::tempdir().unwrap();
    let client = KeychatClient::new(temp_db(&dir, "t.db"), "k".into()).unwrap();
    client.create_identity().await.unwrap();

    let count = client.restore_sessions().await.unwrap();
    assert_eq!(count, 0, "fresh DB has no sessions");

    drop_client(client).await;
});

async_test!(restore_sessions_fails_without_identity, {
    let dir = tempfile::tempdir().unwrap();
    let client = KeychatClient::new(temp_db(&dir, "t.db"), "k".into()).unwrap();

    assert!(client.restore_sessions().await.is_err());

    drop_client(client).await;
});

// ─── NIP-17 DM Fallback ──────────────────────────────────────

/// Alice sends a standard NIP-17 DM (no keychat protocol) to Bob.
/// Bob's event loop should receive it via Step 4 fallback and persist
/// it as a Nip17Dm room.
async_test!(nip17_dm_receive_creates_room_and_message, {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(make_client(&dir, "alice.db"));
    let bob = Arc::new(make_client(&dir, "bob.db"));

    alice.create_identity().await.unwrap();
    bob.create_identity().await.unwrap();

    let alice_pubkey = alice.get_pubkey_hex().await.unwrap();
    let bob_pubkey = bob.get_pubkey_hex().await.unwrap();

    alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
    bob.connect(vec![TEST_RELAY.into()]).await.unwrap();

    // Bob starts event loop to receive messages
    let bob_notify = Arc::new(tokio::sync::Notify::new());
    let (bob_listener, bob_events) = CapturingEventListener::new(bob_notify.clone());
    bob.set_event_listener(Box::new(bob_listener)).await;
    Arc::clone(&bob).start_event_loop().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Alice sends NIP-17 DM to Bob (not a keychat protocol message)
    let sent = alice
        .send_nip17_dm(bob_pubkey.clone(), "Hello from standard Nostr!".into())
        .await
        .unwrap();
    assert!(!sent.event_id.is_empty());

    // Bob should receive the message
    let received = wait_for_event(&bob_events, &bob_notify, 30, |e| {
        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if c == "Hello from standard Nostr!")
    }).await;
    assert!(received, "Bob should receive NIP-17 DM via Step 4 fallback");

    // Verify room was created as Nip17Dm type
    let bob_rooms = bob.get_rooms(bob_pubkey.clone()).await.unwrap();
    let nip17_room = bob_rooms.iter().find(|r| r.to_main_pubkey == alice_pubkey);
    assert!(
        nip17_room.is_some(),
        "Bob should have a NIP-17 DM room with Alice"
    );
    assert_eq!(
        nip17_room.unwrap().room_type,
        RoomType::Nip17Dm,
        "Room type should be Nip17Dm"
    );

    // Verify message was persisted
    let room_id = format!("{}:{}", alice_pubkey, bob_pubkey);
    let messages = bob.get_messages(room_id, 50, 0).await.unwrap();
    let dm_msgs: Vec<_> = messages.iter().filter(|m| !m.is_me_send).collect();
    assert!(
        !dm_msgs.is_empty(),
        "Bob should have received message in DB"
    );
    assert_eq!(dm_msgs[0].content, "Hello from standard Nostr!");

    bob.stop_event_loop().await;
    alice.disconnect().await.unwrap();
    bob.disconnect().await.unwrap();
    // Event loop holds an Arc clone internally; drop on a blocking thread
    // to avoid Runtime-in-Runtime panic (same pattern as existing network tests).
    tokio::task::spawn_blocking(move || {
        drop(alice);
        drop(bob);
    })
    .await
    .unwrap();
});

/// Alice sends NIP-17 DM, Bob replies with NIP-17 DM — full round-trip.
async_test!(nip17_dm_send_and_receive_roundtrip, {
    let dir = tempfile::tempdir().unwrap();
    let alice = Arc::new(make_client(&dir, "alice.db"));
    let bob = Arc::new(make_client(&dir, "bob.db"));

    alice.create_identity().await.unwrap();
    bob.create_identity().await.unwrap();

    let alice_pubkey = alice.get_pubkey_hex().await.unwrap();
    let bob_pubkey = bob.get_pubkey_hex().await.unwrap();

    alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
    bob.connect(vec![TEST_RELAY.into()]).await.unwrap();

    // Both start event loops
    let alice_notify = Arc::new(tokio::sync::Notify::new());
    let (alice_listener, alice_events) = CapturingEventListener::new(alice_notify.clone());
    alice.set_event_listener(Box::new(alice_listener)).await;
    Arc::clone(&alice).start_event_loop().await.unwrap();

    let bob_notify = Arc::new(tokio::sync::Notify::new());
    let (bob_listener, bob_events) = CapturingEventListener::new(bob_notify.clone());
    bob.set_event_listener(Box::new(bob_listener)).await;
    Arc::clone(&bob).start_event_loop().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Alice → Bob
    alice
        .send_nip17_dm(bob_pubkey.clone(), "Hey Bob, this is Alice!".into())
        .await
        .unwrap();

    let bob_got = wait_for_event(&bob_events, &bob_notify, 30, |e| {
        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if c == "Hey Bob, this is Alice!")
    }).await;
    assert!(bob_got, "Bob should receive Alice's NIP-17 DM");

    // Bob → Alice reply
    bob.send_nip17_dm(alice_pubkey.clone(), "Hi Alice, Bob here!".into())
        .await
        .unwrap();

    let alice_got = wait_for_event(&alice_events, &alice_notify, 30, |e| {
        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if c == "Hi Alice, Bob here!")
    }).await;
    assert!(alice_got, "Alice should receive Bob's NIP-17 DM reply");

    alice.stop_event_loop().await;
    bob.stop_event_loop().await;
    alice.disconnect().await.unwrap();
    bob.disconnect().await.unwrap();
    tokio::task::spawn_blocking(move || {
        drop(alice);
        drop(bob);
    })
    .await
    .unwrap();
});

// ─── Full Lifecycle Test ────────────────────────────────────────────────────
//
// Exercises the complete protocol lifecycle:
//   Phase 1: Three-party friend requests (Alice↔Bob, Alice↔Tom, Bob↔Tom)
//   Phase 2: Bidirectional Signal-encrypted DM between all 3 pairs (6 directions)
//   Phase 3: Signal group creation, invite delivery, multi-party group messaging
//   Phase 4: Session persistence — close, reopen, restore_sessions, continue ratchet
//   Phase 5: DB state verification (rooms, members, addresses)
//
// MLS groups are NOT exposed at the UniFFI layer yet — add Phase 3b when ready.

#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn full_lifecycle_three_party() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();

            // ══════════════════════════════════════════════════════════════
            // Phase 1: Create identities, connect, establish 3 friendships
            // ══════════════════════════════════════════════════════════════

            let alice = Arc::new(make_client(&dir, "alice.db"));
            let bob = Arc::new(make_client(&dir, "bob.db"));
            let tom = Arc::new(make_client(&dir, "tom.db"));

            let alice_r = alice.create_identity().await.unwrap();
            let bob_r = bob.create_identity().await.unwrap();
            let tom_r = tom.create_identity().await.unwrap();
            let alice_pub = alice_r.pubkey_hex.clone();
            let bob_pub = bob_r.pubkey_hex.clone();
            let tom_pub = tom_r.pubkey_hex.clone();
            let alice_mnemonic = alice_r.mnemonic.clone();
            let bob_mnemonic = bob_r.mnemonic.clone();
            let tom_mnemonic = tom_r.mnemonic.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();
            tom.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an = Arc::new(tokio::sync::Notify::new());
            let bn = Arc::new(tokio::sync::Notify::new());
            let tn = Arc::new(tokio::sync::Notify::new());
            let (al, ae) = CapturingEventListener::new(an.clone());
            let (bl, be) = CapturingEventListener::new(bn.clone());
            let (tl, te) = CapturingEventListener::new(tn.clone());
            alice.set_event_listener(Box::new(al)).await;
            bob.set_event_listener(Box::new(bl)).await;
            tom.set_event_listener(Box::new(tl)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();
            Arc::clone(&tom).start_event_loop().await.unwrap();

            // Alice ↔ Bob
            establish_friendship(&alice, "Alice", &bob, "Bob", &be, &bn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Bob ✓");

            ae.lock().unwrap().clear();
            // Alice ↔ Tom
            establish_friendship(&alice, "Alice", &tom, "Tom", &te, &tn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Tom ✓");

            be.lock().unwrap().clear();
            te.lock().unwrap().clear();
            // Bob ↔ Tom
            establish_friendship(&bob, "Bob", &tom, "Tom", &te, &tn, &be, &bn).await;
            eprintln!("[Phase1] Bob ↔ Tom ✓");

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Verify receiving addresses exist (ratchet-derived)
            let a_addrs = alice.get_all_receiving_addresses().await;
            let b_addrs = bob.get_all_receiving_addresses().await;
            let t_addrs = tom.get_all_receiving_addresses().await;
            assert!(!a_addrs.is_empty(), "Alice needs receiving addresses");
            assert!(!b_addrs.is_empty(), "Bob needs receiving addresses");
            assert!(!t_addrs.is_empty(), "Tom needs receiving addresses");
            eprintln!("[Phase1] Addresses: A={}, B={}, T={}", a_addrs.len(), b_addrs.len(), t_addrs.len());

            // ══════════════════════════════════════════════════════════════
            // Phase 2: Bidirectional DM — all 6 directions
            // ══════════════════════════════════════════════════════════════

            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();
            te.lock().unwrap().clear();

            let wait_msg = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                            ntf: &Arc<tokio::sync::Notify>,
                            expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if *c == expected)
                    }).await
                }
            };

            alice.send_text(bob_pub.clone(), "dm:A→B".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&be, &bn, "dm:A→B").await, "Bob should get A→B");
            eprintln!("[Phase2] A→B ✓");

            bob.send_text(alice_pub.clone(), "dm:B→A".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&ae, &an, "dm:B→A").await, "Alice should get B→A");
            eprintln!("[Phase2] B→A ✓");

            alice.send_text(tom_pub.clone(), "dm:A→T".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&te, &tn, "dm:A→T").await, "Tom should get A→T");
            eprintln!("[Phase2] A→T ✓");

            ae.lock().unwrap().clear();
            tom.send_text(alice_pub.clone(), "dm:T→A".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&ae, &an, "dm:T→A").await, "Alice should get T→A");
            eprintln!("[Phase2] T→A ✓");

            te.lock().unwrap().clear();
            bob.send_text(tom_pub.clone(), "dm:B→T".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&te, &tn, "dm:B→T").await, "Tom should get B→T");
            eprintln!("[Phase2] B→T ✓");

            be.lock().unwrap().clear();
            tom.send_text(bob_pub.clone(), "dm:T→B".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&be, &bn, "dm:T→B").await, "Bob should get T→B");
            eprintln!("[Phase2] T→B ✓ — all 6 DM directions verified");

            // ══════════════════════════════════════════════════════════════
            // Phase 3: Signal Group — create, invite, 3-party messaging
            // ══════════════════════════════════════════════════════════════

            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();
            te.lock().unwrap().clear();

            // Debug: print subscription state of all 3 clients before group creation
            eprintln!("[Phase3-debug] Alice: {}", alice.debug_subscription_state().await);
            eprintln!("[Phase3-debug] Bob: {}", bob.debug_subscription_state().await);
            eprintln!("[Phase3-debug] Tom: {}", tom.debug_subscription_state().await);

            let gi = alice.create_signal_group(
                "Lifecycle".into(),
                vec![
                    GroupMemberInput { nostr_pubkey: bob_pub.clone(), name: "Bob".into() },
                    GroupMemberInput { nostr_pubkey: tom_pub.clone(), name: "Tom".into() },
                ],
            ).await.unwrap();
            let gid = gi.group_id.clone();
            assert_eq!(gi.member_count, 3);
            eprintln!("[Phase3] Group created: id={}…", &gid[..16]);

            assert!(
                wait_for_event(&be, &bn, 30, |e| matches!(e, ClientEvent::GroupInviteReceived { .. })).await,
                "Bob should get group invite"
            );
            assert!(
                wait_for_event(&te, &tn, 30, |e| matches!(e, ClientEvent::GroupInviteReceived { .. })).await,
                "Tom should get group invite"
            );
            eprintln!("[Phase3] Invites received");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let wait_group = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                              ntf: &Arc<tokio::sync::Notify>,
                              expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), group_id: Some(_), .. } if *c == expected)
                    }).await
                }
            };

            // Alice → group
            be.lock().unwrap().clear(); te.lock().unwrap().clear();
            alice.send_group_text(gid.clone(), "grp:Alice".into(), None).await.unwrap();
            assert!(wait_group(&be, &bn, "grp:Alice").await, "Bob should get Alice's group msg");
            assert!(wait_group(&te, &tn, "grp:Alice").await, "Tom should get Alice's group msg");
            eprintln!("[Phase3] Alice→group ✓");

            // Bob → group
            ae.lock().unwrap().clear(); te.lock().unwrap().clear();
            bob.send_group_text(gid.clone(), "grp:Bob".into(), None).await.unwrap();
            assert!(wait_group(&ae, &an, "grp:Bob").await, "Alice should get Bob's group msg");
            assert!(wait_group(&te, &tn, "grp:Bob").await, "Tom should get Bob's group msg");
            eprintln!("[Phase3] Bob→group ✓");

            // Tom → group
            ae.lock().unwrap().clear(); be.lock().unwrap().clear();
            tom.send_group_text(gid.clone(), "grp:Tom".into(), None).await.unwrap();
            assert!(wait_group(&ae, &an, "grp:Tom").await, "Alice should get Tom's group msg");
            assert!(wait_group(&be, &bn, "grp:Tom").await, "Bob should get Tom's group msg");
            eprintln!("[Phase3] Tom→group ✓ — all group messaging verified");

            // ══════════════════════════════════════════════════════════════
            // Phase 4: Session persistence — restart and verify ratchet
            // ══════════════════════════════════════════════════════════════

            let pre_a = alice.get_all_receiving_addresses().await;
            let pre_b = bob.get_all_receiving_addresses().await;
            let pre_t = tom.get_all_receiving_addresses().await;
            eprintln!("[Phase4] Pre-restart addrs: A={}, B={}, T={}", pre_a.len(), pre_b.len(), pre_t.len());

            // Graceful shutdown
            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            tom.stop_event_loop().await;
            alice.close_storage().await.unwrap();
            bob.close_storage().await.unwrap();
            tom.close_storage().await.unwrap();
            alice.disconnect().await.unwrap();
            bob.disconnect().await.unwrap();
            tom.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || { drop(alice); drop(bob); drop(tom); }).await.unwrap();
            eprintln!("[Phase4] Clients shut down");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Reopen from same DB
            let a2 = Arc::new(make_client(&dir, "alice.db"));
            let b2 = Arc::new(make_client(&dir, "bob.db"));
            let t2 = Arc::new(make_client(&dir, "tom.db"));

            assert_eq!(a2.import_identity(alice_mnemonic).await.unwrap(), alice_pub);
            assert_eq!(b2.import_identity(bob_mnemonic).await.unwrap(), bob_pub);
            assert_eq!(t2.import_identity(tom_mnemonic).await.unwrap(), tom_pub);

            let ar = a2.restore_sessions().await.unwrap();
            let br = b2.restore_sessions().await.unwrap();
            let tr = t2.restore_sessions().await.unwrap();
            eprintln!("[Phase4] Restored: A={ar}, B={br}, T={tr}");
            assert!(ar >= 2, "Alice restore ≥2, got {ar}");
            assert!(br >= 2, "Bob restore ≥2, got {br}");
            assert!(tr >= 2, "Tom restore ≥2, got {tr}");

            // Address counts must match (ratchet NOT reset)
            let post_a = a2.get_all_receiving_addresses().await;
            let post_b = b2.get_all_receiving_addresses().await;
            let post_t = t2.get_all_receiving_addresses().await;
            assert_eq!(post_a.len(), pre_a.len(), "Alice addr count should match pre-restart");
            assert_eq!(post_b.len(), pre_b.len(), "Bob addr count should match pre-restart");
            assert_eq!(post_t.len(), pre_t.len(), "Tom addr count should match pre-restart");
            eprintln!("[Phase4] Address counts match ✓");

            // Reconnect
            a2.connect(vec![TEST_RELAY.into()]).await.unwrap();
            b2.connect(vec![TEST_RELAY.into()]).await.unwrap();
            t2.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an2 = Arc::new(tokio::sync::Notify::new());
            let bn2 = Arc::new(tokio::sync::Notify::new());
            let tn2 = Arc::new(tokio::sync::Notify::new());
            let (al2, ae2) = CapturingEventListener::new(an2.clone());
            let (bl2, be2) = CapturingEventListener::new(bn2.clone());
            let (tl2, te2) = CapturingEventListener::new(tn2.clone());
            a2.set_event_listener(Box::new(al2)).await;
            b2.set_event_listener(Box::new(bl2)).await;
            t2.set_event_listener(Box::new(tl2)).await;

            Arc::clone(&a2).start_event_loop().await.unwrap();
            Arc::clone(&b2).start_event_loop().await.unwrap();
            Arc::clone(&t2).start_event_loop().await.unwrap();

            // Wait for relays to be fully connected (TLS handshake may retry)
            for attempt in 1..=15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let a_relays = a2.connected_relays().await.unwrap_or_default();
                let b_relays = b2.connected_relays().await.unwrap_or_default();
                let t_relays = t2.connected_relays().await.unwrap_or_default();
                if !a_relays.is_empty() && !b_relays.is_empty() && !t_relays.is_empty() {
                    eprintln!("[Phase4] All relays connected after {attempt} attempts");
                    break;
                }
                if attempt == 15 {
                    panic!("Relays did not reconnect within 30s");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Post-restart DMs (prove ratchet continues)
            let wait2 = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                         ntf: &Arc<tokio::sync::Notify>,
                         expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if *c == expected)
                    }).await
                }
            };

            a2.send_text(bob_pub.clone(), "restart:A→B".into(), None, None, None).await.unwrap();
            assert!(wait2(&be2, &bn2, "restart:A→B").await, "Post-restart A→B failed");
            eprintln!("[Phase4] Post-restart A→B ✓");

            b2.send_text(alice_pub.clone(), "restart:B→A".into(), None, None, None).await.unwrap();
            assert!(wait2(&ae2, &an2, "restart:B→A").await, "Post-restart B→A failed");
            eprintln!("[Phase4] Post-restart B→A ✓");

            ae2.lock().unwrap().clear();
            t2.send_text(alice_pub.clone(), "restart:T→A".into(), None, None, None).await.unwrap();
            assert!(wait2(&ae2, &an2, "restart:T→A").await, "Post-restart T→A failed");
            eprintln!("[Phase4] Post-restart T→A ✓");

            // Post-restart group message
            be2.lock().unwrap().clear(); te2.lock().unwrap().clear();
            a2.send_group_text(gid.clone(), "restart:grp".into(), None).await.unwrap();
            let wait_g2 = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                           ntf: &Arc<tokio::sync::Notify>,
                           expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), group_id: Some(_), .. } if *c == expected)
                    }).await
                }
            };
            assert!(wait_g2(&be2, &bn2, "restart:grp").await, "Post-restart group msg → Bob failed");
            assert!(wait_g2(&te2, &tn2, "restart:grp").await, "Post-restart group msg → Tom failed");
            eprintln!("[Phase4] Post-restart group ✓ — ratchet continuity verified");

            // ══════════════════════════════════════════════════════════════
            // Phase 5: Final DB state verification
            // ══════════════════════════════════════════════════════════════

            let rooms = a2.get_rooms(alice_pub.clone()).await.unwrap();
            let dm_n = rooms.iter().filter(|r| r.room_type == RoomType::Dm).count();
            let grp_n = rooms.iter().filter(|r| r.room_type == RoomType::SignalGroup).count();
            assert_eq!(dm_n, 2, "Alice should have 2 DM rooms");
            assert!(grp_n >= 1, "Alice should have ≥1 group room");

            let mems = a2.get_signal_group_members(gid).await.unwrap();
            assert_eq!(mems.len(), 3, "Group still 3 members");
            eprintln!("[Phase5] DB: {dm_n} DMs, {grp_n} groups, {} members ✓", mems.len());

            // Cleanup
            a2.stop_event_loop().await;
            b2.stop_event_loop().await;
            t2.stop_event_loop().await;
            a2.disconnect().await.unwrap();
            b2.disconnect().await.unwrap();
            t2.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || { drop(a2); drop(b2); drop(t2); }).await.unwrap();

            eprintln!("══════════════════════════════════════════");
            eprintln!("  FULL LIFECYCLE TEST PASSED");
            eprintln!("══════════════════════════════════════════");
        });
    })
    .join()
    .unwrap();
}

// ─── Comprehensive E2E Test ────────────────────────────────────────────────────
//
// Exercises the complete protocol with persistence and restart:
//   Phase 1: Alice adds Bob + Tom as friends; Bob and Tom accept
//   Phase 2: All 3 pairs exchange bidirectional Signal DMs (6 directions)
//   Phase 3: Alice creates Signal small group; all 3 send and receive group messages
//   Phase 4: Graceful shutdown → reopen from same DB → restore_sessions
//            Verify: address counts match, sessions exist, ratchet not reset
//   Phase 5: Post-restart DM messaging (all 6 directions) — proves ratchet continuity
//   Phase 6: Post-restart Signal group messaging — proves group state persisted
//   Phase 7: Second restart cycle — double-restart proves stability
//   Phase 8: Final DB state verification (rooms, contacts, messages, members)
//
// MLS large groups are NOT yet exposed at the UniFFI layer — tracked for future.

#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn comprehensive_e2e_with_double_restart() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();

            // ══════════════════════════════════════════════════════════════
            // Phase 1: Create identities, connect, establish friendships
            //   Alice adds Bob; Alice adds Tom; Bob and Tom accept
            // ══════════════════════════════════════════════════════════════

            let alice = Arc::new(make_client(&dir, "e2e_alice.db"));
            let bob = Arc::new(make_client(&dir, "e2e_bob.db"));
            let tom = Arc::new(make_client(&dir, "e2e_tom.db"));

            let alice_r = alice.create_identity().await.unwrap();
            let bob_r = bob.create_identity().await.unwrap();
            let tom_r = tom.create_identity().await.unwrap();
            let alice_pub = alice_r.pubkey_hex.clone();
            let bob_pub = bob_r.pubkey_hex.clone();
            let tom_pub = tom_r.pubkey_hex.clone();
            let alice_mnemonic = alice_r.mnemonic.clone();
            let bob_mnemonic = bob_r.mnemonic.clone();
            let tom_mnemonic = tom_r.mnemonic.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();
            tom.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an = Arc::new(tokio::sync::Notify::new());
            let bn = Arc::new(tokio::sync::Notify::new());
            let tn = Arc::new(tokio::sync::Notify::new());
            let (al, ae) = CapturingEventListener::new(an.clone());
            let (bl, be) = CapturingEventListener::new(bn.clone());
            let (tl, te) = CapturingEventListener::new(tn.clone());
            alice.set_event_listener(Box::new(al)).await;
            bob.set_event_listener(Box::new(bl)).await;
            tom.set_event_listener(Box::new(tl)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();
            Arc::clone(&tom).start_event_loop().await.unwrap();

            // Alice → Bob (Alice sends, Bob accepts)
            establish_friendship(&alice, "Alice", &bob, "Bob", &be, &bn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Bob ✓");

            // Alice → Tom (Alice sends, Tom accepts)
            ae.lock().unwrap().clear();
            establish_friendship(&alice, "Alice", &tom, "Tom", &te, &tn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Tom ✓");

            // Bob ↔ Tom: also establish so all 3 can communicate
            be.lock().unwrap().clear();
            te.lock().unwrap().clear();
            establish_friendship(&bob, "Bob", &tom, "Tom", &te, &tn, &be, &bn).await;
            eprintln!("[Phase1] Bob ↔ Tom ✓");

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // Verify all have receiving addresses
            let a_addrs_init = alice.get_all_receiving_addresses().await;
            let b_addrs_init = bob.get_all_receiving_addresses().await;
            let t_addrs_init = tom.get_all_receiving_addresses().await;
            assert!(!a_addrs_init.is_empty(), "Alice needs receiving addresses after friendship");
            assert!(!b_addrs_init.is_empty(), "Bob needs receiving addresses after friendship");
            assert!(!t_addrs_init.is_empty(), "Tom needs receiving addresses after friendship");
            eprintln!("[Phase1] Initial addrs: A={}, B={}, T={}", a_addrs_init.len(), b_addrs_init.len(), t_addrs_init.len());

            // Verify contacts in DB
            let a_contacts = alice.get_contacts(alice_pub.clone()).await.unwrap();
            assert!(a_contacts.iter().any(|c| c.pubkey == bob_pub), "Alice should have Bob as contact");
            assert!(a_contacts.iter().any(|c| c.pubkey == tom_pub), "Alice should have Tom as contact");
            let b_contacts = bob.get_contacts(bob_pub.clone()).await.unwrap();
            assert!(b_contacts.iter().any(|c| c.pubkey == alice_pub), "Bob should have Alice as contact");
            assert!(b_contacts.iter().any(|c| c.pubkey == tom_pub), "Bob should have Tom as contact");
            eprintln!("[Phase1] Contact DB assertions ✓");

            // ══════════════════════════════════════════════════════════════
            // Phase 2: Bidirectional Signal DMs — all 6 directions
            // ══════════════════════════════════════════════════════════════

            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();
            te.lock().unwrap().clear();

            let wait_msg = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                            ntf: &Arc<tokio::sync::Notify>,
                            expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if *c == expected)
                    }).await
                }
            };

            // A→B
            alice.send_text(bob_pub.clone(), "e2e:A→B".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&be, &bn, "e2e:A→B").await, "Bob should get A→B");
            eprintln!("[Phase2] A→B ✓");

            // B→A
            be.lock().unwrap().clear();
            bob.send_text(alice_pub.clone(), "e2e:B→A".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&ae, &an, "e2e:B→A").await, "Alice should get B→A");
            eprintln!("[Phase2] B→A ✓");

            // A→T
            alice.send_text(tom_pub.clone(), "e2e:A→T".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&te, &tn, "e2e:A→T").await, "Tom should get A→T");
            eprintln!("[Phase2] A→T ✓");

            // T→A
            ae.lock().unwrap().clear();
            tom.send_text(alice_pub.clone(), "e2e:T→A".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&ae, &an, "e2e:T→A").await, "Alice should get T→A");
            eprintln!("[Phase2] T→A ✓");

            // B→T
            te.lock().unwrap().clear();
            bob.send_text(tom_pub.clone(), "e2e:B→T".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&te, &tn, "e2e:B→T").await, "Tom should get B→T");
            eprintln!("[Phase2] B→T ✓");

            // T→B
            be.lock().unwrap().clear();
            tom.send_text(bob_pub.clone(), "e2e:T→B".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&be, &bn, "e2e:T→B").await, "Bob should get T→B");
            eprintln!("[Phase2] T→B ✓ — all 6 DM directions verified");

            // Brief pause for DB writes
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            eprintln!("[Phase2] DM DB assertions deferred to Phase 8");

            // ══════════════════════════════════════════════════════════════
            // Phase 3: Signal small group — create, invite, 3-party messaging
            // ══════════════════════════════════════════════════════════════

            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();
            te.lock().unwrap().clear();

            let gi = alice.create_signal_group(
                "E2E-TestGroup".into(),
                vec![
                    GroupMemberInput { nostr_pubkey: bob_pub.clone(), name: "Bob".into() },
                    GroupMemberInput { nostr_pubkey: tom_pub.clone(), name: "Tom".into() },
                ],
            ).await.unwrap();
            let gid = gi.group_id.clone();
            assert_eq!(gi.member_count, 3);
            eprintln!("[Phase3] Signal group created: id={}…", &gid[..16]);

            // Wait for invites
            assert!(
                wait_for_event(&be, &bn, 30, |e| matches!(e, ClientEvent::GroupInviteReceived { .. })).await,
                "Bob should get group invite"
            );
            assert!(
                wait_for_event(&te, &tn, 30, |e| matches!(e, ClientEvent::GroupInviteReceived { .. })).await,
                "Tom should get group invite"
            );
            eprintln!("[Phase3] Invites received ✓");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let wait_group = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                              ntf: &Arc<tokio::sync::Notify>,
                              expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), group_id: Some(_), .. } if *c == expected)
                    }).await
                }
            };

            // Alice → group
            be.lock().unwrap().clear(); te.lock().unwrap().clear();
            alice.send_group_text(gid.clone(), "grp:Alice-1".into(), None).await.unwrap();
            assert!(wait_group(&be, &bn, "grp:Alice-1").await, "Bob should get Alice's group msg");
            assert!(wait_group(&te, &tn, "grp:Alice-1").await, "Tom should get Alice's group msg");
            eprintln!("[Phase3] Alice→group ✓");

            // Bob → group
            ae.lock().unwrap().clear(); te.lock().unwrap().clear();
            bob.send_group_text(gid.clone(), "grp:Bob-1".into(), None).await.unwrap();
            assert!(wait_group(&ae, &an, "grp:Bob-1").await, "Alice should get Bob's group msg");
            assert!(wait_group(&te, &tn, "grp:Bob-1").await, "Tom should get Bob's group msg");
            eprintln!("[Phase3] Bob→group ✓");

            // Tom → group
            ae.lock().unwrap().clear(); be.lock().unwrap().clear();
            tom.send_group_text(gid.clone(), "grp:Tom-1".into(), None).await.unwrap();
            assert!(wait_group(&ae, &an, "grp:Tom-1").await, "Alice should get Tom's group msg");
            assert!(wait_group(&be, &bn, "grp:Tom-1").await, "Bob should get Tom's group msg");
            eprintln!("[Phase3] Tom→group ✓ — all group messaging verified");

            // Verify group in DB — Alice (creator) always has group room
            let a_rooms = alice.get_rooms(alice_pub.clone()).await.unwrap();
            let a_grp_rooms: Vec<_> = a_rooms.iter().filter(|r| r.room_type == RoomType::SignalGroup).collect();
            eprintln!("[Phase3] Alice rooms: total={}, signal_groups={}, ids={:?}",
                a_rooms.len(), a_grp_rooms.len(),
                a_rooms.iter().map(|r| format!("{}:{:?}", &r.id[..16.min(r.id.len())], r.room_type)).collect::<Vec<_>>());
            assert!(!a_grp_rooms.is_empty(), "Alice should have SignalGroup room");

            let members = alice.get_signal_group_members(gid.clone()).await.unwrap();
            assert_eq!(members.len(), 3, "Group should have 3 members");
            assert!(members.iter().any(|m| m.is_admin), "Group should have an admin");
            eprintln!("[Phase3] Group DB assertions ✓");

            // ══════════════════════════════════════════════════════════════
            // Phase 4: First restart — verify persistence
            // ══════════════════════════════════════════════════════════════

            let pre_a = alice.get_all_receiving_addresses().await;
            let pre_b = bob.get_all_receiving_addresses().await;
            let pre_t = tom.get_all_receiving_addresses().await;
            eprintln!("[Phase4] Pre-restart addrs: A={}, B={}, T={}", pre_a.len(), pre_b.len(), pre_t.len());

            // Graceful shutdown
            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            tom.stop_event_loop().await;
            alice.close_storage().await.unwrap();
            bob.close_storage().await.unwrap();
            tom.close_storage().await.unwrap();
            alice.disconnect().await.unwrap();
            bob.disconnect().await.unwrap();
            tom.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || { drop(alice); drop(bob); drop(tom); }).await.unwrap();
            eprintln!("[Phase4] Clients shut down");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Reopen from same DB
            let a2 = Arc::new(make_client(&dir, "e2e_alice.db"));
            let b2 = Arc::new(make_client(&dir, "e2e_bob.db"));
            let t2 = Arc::new(make_client(&dir, "e2e_tom.db"));

            assert_eq!(a2.import_identity(alice_mnemonic.clone()).await.unwrap(), alice_pub);
            assert_eq!(b2.import_identity(bob_mnemonic.clone()).await.unwrap(), bob_pub);
            assert_eq!(t2.import_identity(tom_mnemonic.clone()).await.unwrap(), tom_pub);

            let ar = a2.restore_sessions().await.unwrap();
            let br = b2.restore_sessions().await.unwrap();
            let tr = t2.restore_sessions().await.unwrap();
            eprintln!("[Phase4] Restored sessions: A={ar}, B={br}, T={tr}");
            assert!(ar >= 2, "Alice should restore ≥2 sessions, got {ar}");
            assert!(br >= 2, "Bob should restore ≥2 sessions, got {br}");
            assert!(tr >= 2, "Tom should restore ≥2 sessions, got {tr}");

            // Address counts must match (ratchet NOT reset)
            let post_a = a2.get_all_receiving_addresses().await;
            let post_b = b2.get_all_receiving_addresses().await;
            let post_t = t2.get_all_receiving_addresses().await;
            assert_eq!(post_a.len(), pre_a.len(), "Alice addr count mismatch: pre={} post={}", pre_a.len(), post_a.len());
            assert_eq!(post_b.len(), pre_b.len(), "Bob addr count mismatch: pre={} post={}", pre_b.len(), post_b.len());
            assert_eq!(post_t.len(), pre_t.len(), "Tom addr count mismatch: pre={} post={}", pre_t.len(), post_t.len());
            eprintln!("[Phase4] Address counts match ✓ — ratchet not reset");

            // Verify sessions are still present via debug_state_summary
            let a_summary = a2.debug_state_summary().await.unwrap();
            assert!(a_summary.contains("sessions="), "Alice debug summary should show sessions");
            eprintln!("[Phase4] Session state verified ✓");

            // Reconnect
            a2.connect(vec![TEST_RELAY.into()]).await.unwrap();
            b2.connect(vec![TEST_RELAY.into()]).await.unwrap();
            t2.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an2 = Arc::new(tokio::sync::Notify::new());
            let bn2 = Arc::new(tokio::sync::Notify::new());
            let tn2 = Arc::new(tokio::sync::Notify::new());
            let (al2, ae2) = CapturingEventListener::new(an2.clone());
            let (bl2, be2) = CapturingEventListener::new(bn2.clone());
            let (tl2, te2) = CapturingEventListener::new(tn2.clone());
            a2.set_event_listener(Box::new(al2)).await;
            b2.set_event_listener(Box::new(bl2)).await;
            t2.set_event_listener(Box::new(tl2)).await;

            Arc::clone(&a2).start_event_loop().await.unwrap();
            Arc::clone(&b2).start_event_loop().await.unwrap();
            Arc::clone(&t2).start_event_loop().await.unwrap();

            // Wait for relays to reconnect
            for attempt in 1..=15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let a_relays = a2.connected_relays().await.unwrap_or_default();
                let b_relays = b2.connected_relays().await.unwrap_or_default();
                let t_relays = t2.connected_relays().await.unwrap_or_default();
                if !a_relays.is_empty() && !b_relays.is_empty() && !t_relays.is_empty() {
                    eprintln!("[Phase4] All relays connected after {attempt} attempts");
                    break;
                }
                if attempt == 15 { panic!("Relays did not reconnect within 30s"); }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // ══════════════════════════════════════════════════════════════
            // Phase 5: Post-restart DMs — all 6 directions (ratchet continuity)
            // ══════════════════════════════════════════════════════════════

            let wait2 = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                         ntf: &Arc<tokio::sync::Notify>,
                         expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if *c == expected)
                    }).await
                }
            };

            // A→B
            a2.send_text(bob_pub.clone(), "r1:A→B".into(), None, None, None).await.unwrap();
            assert!(wait2(&be2, &bn2, "r1:A→B").await, "Post-restart A→B failed");
            eprintln!("[Phase5] Post-restart A→B ✓");

            // B→A
            ae2.lock().unwrap().clear();
            b2.send_text(alice_pub.clone(), "r1:B→A".into(), None, None, None).await.unwrap();
            assert!(wait2(&ae2, &an2, "r1:B→A").await, "Post-restart B→A failed");
            eprintln!("[Phase5] Post-restart B→A ✓");

            // A→T
            a2.send_text(tom_pub.clone(), "r1:A→T".into(), None, None, None).await.unwrap();
            assert!(wait2(&te2, &tn2, "r1:A→T").await, "Post-restart A→T failed");
            eprintln!("[Phase5] Post-restart A→T ✓");

            // T→A
            ae2.lock().unwrap().clear();
            t2.send_text(alice_pub.clone(), "r1:T→A".into(), None, None, None).await.unwrap();
            assert!(wait2(&ae2, &an2, "r1:T→A").await, "Post-restart T→A failed");
            eprintln!("[Phase5] Post-restart T→A ✓");

            // B→T
            te2.lock().unwrap().clear();
            b2.send_text(tom_pub.clone(), "r1:B→T".into(), None, None, None).await.unwrap();
            assert!(wait2(&te2, &tn2, "r1:B→T").await, "Post-restart B→T failed");
            eprintln!("[Phase5] Post-restart B→T ✓");

            // T→B
            be2.lock().unwrap().clear();
            t2.send_text(bob_pub.clone(), "r1:T→B".into(), None, None, None).await.unwrap();
            assert!(wait2(&be2, &bn2, "r1:T→B").await, "Post-restart T→B failed");
            eprintln!("[Phase5] Post-restart T→B ✓ — all 6 DM directions post-restart verified");

            // ══════════════════════════════════════════════════════════════
            // Phase 6: Post-restart Signal group messaging
            // ══════════════════════════════════════════════════════════════

            ae2.lock().unwrap().clear();
            be2.lock().unwrap().clear();
            te2.lock().unwrap().clear();

            let wait_g2 = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                           ntf: &Arc<tokio::sync::Notify>,
                           expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), group_id: Some(_), .. } if *c == expected)
                    }).await
                }
            };

            // Alice → group (post-restart)
            a2.send_group_text(gid.clone(), "r1:grp:Alice".into(), None).await.unwrap();
            assert!(wait_g2(&be2, &bn2, "r1:grp:Alice").await, "Post-restart group → Bob failed");
            assert!(wait_g2(&te2, &tn2, "r1:grp:Alice").await, "Post-restart group → Tom failed");
            eprintln!("[Phase6] Post-restart Alice→group ✓");

            // Bob → group (post-restart)
            ae2.lock().unwrap().clear(); te2.lock().unwrap().clear();
            b2.send_group_text(gid.clone(), "r1:grp:Bob".into(), None).await.unwrap();
            assert!(wait_g2(&ae2, &an2, "r1:grp:Bob").await, "Post-restart group → Alice failed");
            assert!(wait_g2(&te2, &tn2, "r1:grp:Bob").await, "Post-restart group → Tom failed");
            eprintln!("[Phase6] Post-restart Bob→group ✓");

            // Tom → group (post-restart)
            ae2.lock().unwrap().clear(); be2.lock().unwrap().clear();
            t2.send_group_text(gid.clone(), "r1:grp:Tom".into(), None).await.unwrap();
            assert!(wait_g2(&ae2, &an2, "r1:grp:Tom").await, "Post-restart group → Alice failed");
            assert!(wait_g2(&be2, &bn2, "r1:grp:Tom").await, "Post-restart group → Bob failed");
            eprintln!("[Phase6] Post-restart Tom→group ✓ — group persistence verified");

            // ══════════════════════════════════════════════════════════════
            // Phase 7: Second restart cycle — double-restart stability
            // ══════════════════════════════════════════════════════════════

            let pre2_a = a2.get_all_receiving_addresses().await;
            let pre2_b = b2.get_all_receiving_addresses().await;
            let pre2_t = t2.get_all_receiving_addresses().await;
            eprintln!("[Phase7] Pre-2nd-restart addrs: A={}, B={}, T={}", pre2_a.len(), pre2_b.len(), pre2_t.len());

            a2.stop_event_loop().await;
            b2.stop_event_loop().await;
            t2.stop_event_loop().await;
            a2.close_storage().await.unwrap();
            b2.close_storage().await.unwrap();
            t2.close_storage().await.unwrap();
            a2.disconnect().await.unwrap();
            b2.disconnect().await.unwrap();
            t2.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || { drop(a2); drop(b2); drop(t2); }).await.unwrap();
            eprintln!("[Phase7] 2nd shutdown complete");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Third incarnation
            let a3 = Arc::new(make_client(&dir, "e2e_alice.db"));
            let b3 = Arc::new(make_client(&dir, "e2e_bob.db"));
            let t3 = Arc::new(make_client(&dir, "e2e_tom.db"));

            assert_eq!(a3.import_identity(alice_mnemonic).await.unwrap(), alice_pub);
            assert_eq!(b3.import_identity(bob_mnemonic).await.unwrap(), bob_pub);
            assert_eq!(t3.import_identity(tom_mnemonic).await.unwrap(), tom_pub);

            let ar3 = a3.restore_sessions().await.unwrap();
            let br3 = b3.restore_sessions().await.unwrap();
            let tr3 = t3.restore_sessions().await.unwrap();
            eprintln!("[Phase7] 2nd restore: A={ar3}, B={br3}, T={tr3}");
            assert!(ar3 >= 2, "Alice 2nd restore ≥2, got {ar3}");
            assert!(br3 >= 2, "Bob 2nd restore ≥2, got {br3}");
            assert!(tr3 >= 2, "Tom 2nd restore ≥2, got {tr3}");

            // Address counts must still match
            let post2_a = a3.get_all_receiving_addresses().await;
            let post2_b = b3.get_all_receiving_addresses().await;
            let post2_t = t3.get_all_receiving_addresses().await;
            assert_eq!(post2_a.len(), pre2_a.len(), "Alice addr count mismatch after 2nd restart");
            assert_eq!(post2_b.len(), pre2_b.len(), "Bob addr count mismatch after 2nd restart");
            assert_eq!(post2_t.len(), pre2_t.len(), "Tom addr count mismatch after 2nd restart");
            eprintln!("[Phase7] 2nd restart address counts match ✓");

            // Reconnect and verify messaging still works
            a3.connect(vec![TEST_RELAY.into()]).await.unwrap();
            b3.connect(vec![TEST_RELAY.into()]).await.unwrap();
            t3.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an3 = Arc::new(tokio::sync::Notify::new());
            let bn3 = Arc::new(tokio::sync::Notify::new());
            let tn3 = Arc::new(tokio::sync::Notify::new());
            let (al3, ae3) = CapturingEventListener::new(an3.clone());
            let (bl3, be3) = CapturingEventListener::new(bn3.clone());
            let (tl3, te3) = CapturingEventListener::new(tn3.clone());
            a3.set_event_listener(Box::new(al3)).await;
            b3.set_event_listener(Box::new(bl3)).await;
            t3.set_event_listener(Box::new(tl3)).await;

            Arc::clone(&a3).start_event_loop().await.unwrap();
            Arc::clone(&b3).start_event_loop().await.unwrap();
            Arc::clone(&t3).start_event_loop().await.unwrap();

            // Wait for relays
            for attempt in 1..=15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let a_r = a3.connected_relays().await.unwrap_or_default();
                let b_r = b3.connected_relays().await.unwrap_or_default();
                let t_r = t3.connected_relays().await.unwrap_or_default();
                if !a_r.is_empty() && !b_r.is_empty() && !t_r.is_empty() {
                    eprintln!("[Phase7] All relays connected after {attempt} attempts");
                    break;
                }
                if attempt == 15 { panic!("Relays did not reconnect after 2nd restart"); }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let wait3 = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                         ntf: &Arc<tokio::sync::Notify>,
                         expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if *c == expected)
                    }).await
                }
            };

            // DM after double-restart: A→B, B→A
            a3.send_text(bob_pub.clone(), "r2:A→B".into(), None, None, None).await.unwrap();
            assert!(wait3(&be3, &bn3, "r2:A→B").await, "2nd restart A→B failed");
            eprintln!("[Phase7] 2nd restart A→B ✓");

            ae3.lock().unwrap().clear();
            b3.send_text(alice_pub.clone(), "r2:B→A".into(), None, None, None).await.unwrap();
            assert!(wait3(&ae3, &an3, "r2:B→A").await, "2nd restart B→A failed");
            eprintln!("[Phase7] 2nd restart B→A ✓");

            // Group after double-restart
            be3.lock().unwrap().clear(); te3.lock().unwrap().clear();
            a3.send_group_text(gid.clone(), "r2:grp:Alice".into(), None).await.unwrap();
            let wait_g3 = |evts: &Arc<Mutex<Vec<ClientEvent>>>,
                           ntf: &Arc<tokio::sync::Notify>,
                           expected: &str| {
                let evts = evts.clone();
                let ntf = ntf.clone();
                let expected = expected.to_string();
                async move {
                    wait_for_event(&evts, &ntf, 30, |e| {
                        matches!(e, ClientEvent::MessageReceived { content: Some(c), group_id: Some(_), .. } if *c == expected)
                    }).await
                }
            };
            assert!(wait_g3(&be3, &bn3, "r2:grp:Alice").await, "2nd restart group → Bob failed");
            assert!(wait_g3(&te3, &tn3, "r2:grp:Alice").await, "2nd restart group → Tom failed");
            eprintln!("[Phase7] 2nd restart group messaging ✓ — double-restart stability verified");

            // ══════════════════════════════════════════════════════════════
            // Phase 8: Final DB state verification
            // ══════════════════════════════════════════════════════════════

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Alice: 2 DM rooms + ≥1 group room
            let a_final_rooms = a3.get_rooms(alice_pub.clone()).await.unwrap();
            let a_dm_count = a_final_rooms.iter().filter(|r| r.room_type == RoomType::Dm).count();
            let a_grp_count = a_final_rooms.iter().filter(|r| r.room_type == RoomType::SignalGroup).count();
            assert_eq!(a_dm_count, 2, "Alice should have 2 DM rooms, got {a_dm_count}");
            assert!(a_grp_count >= 1, "Alice should have ≥1 group room, got {a_grp_count}");

            // Bob: 2 DM rooms + ≥1 group room
            let b_final_rooms = b3.get_rooms(bob_pub.clone()).await.unwrap();
            let b_dm_count = b_final_rooms.iter().filter(|r| r.room_type == RoomType::Dm).count();
            let b_grp_count = b_final_rooms.iter().filter(|r| r.room_type == RoomType::SignalGroup).count();
            assert_eq!(b_dm_count, 2, "Bob should have 2 DM rooms, got {b_dm_count}");
            assert!(b_grp_count >= 1, "Bob should have ≥1 group room, got {b_grp_count}");

            // Tom: 2 DM rooms + ≥1 group room
            let t_final_rooms = t3.get_rooms(tom_pub.clone()).await.unwrap();
            let t_dm_count = t_final_rooms.iter().filter(|r| r.room_type == RoomType::Dm).count();
            let t_grp_count = t_final_rooms.iter().filter(|r| r.room_type == RoomType::SignalGroup).count();
            assert_eq!(t_dm_count, 2, "Tom should have 2 DM rooms, got {t_dm_count}");
            assert!(t_grp_count >= 1, "Tom should have ≥1 group room, got {t_grp_count}");

            // Group members still intact
            let final_members = a3.get_signal_group_members(gid.clone()).await.unwrap();
            assert_eq!(final_members.len(), 3, "Group should still have 3 members after double restart");

            // Contacts still intact
            let a_final_contacts = a3.get_contacts(alice_pub.clone()).await.unwrap();
            assert!(a_final_contacts.iter().any(|c| c.pubkey == bob_pub), "Alice should still have Bob after restart");
            assert!(a_final_contacts.iter().any(|c| c.pubkey == tom_pub), "Alice should still have Tom after restart");

            // Message counts: all DM rooms should have messages spanning pre- and post-restart
            let a_bob_room = a_final_rooms.iter().find(|r| r.to_main_pubkey == bob_pub).unwrap();
            let a_bob_msg_count = a3.get_message_count(a_bob_room.id.clone()).await.unwrap();
            assert!(a_bob_msg_count >= 4, "Alice↔Bob should have ≥4 messages (pre+post restart), got {a_bob_msg_count}");

            // Group message count — find the actual group room ID from DB
            let a_grp_msg_count = if let Some(grp_room) = a_final_rooms.iter().find(|r| r.room_type == RoomType::SignalGroup) {
                let a_grp_msgs = a3.get_messages(grp_room.id.clone(), 100, 0).await.unwrap();
                let a_grp_text: Vec<_> = a_grp_msgs.iter().filter(|m| !m.content.starts_with('[')).collect();
                eprintln!("[Phase8] Alice group messages: {} (room_id={}…)", a_grp_text.len(), &grp_room.id[..16.min(grp_room.id.len())]);
                assert!(a_grp_text.len() >= 2, "Alice should see ≥2 group text messages, got {}", a_grp_text.len());
                a_grp_text.len()
            } else {
                0
            };

            eprintln!("[Phase8] Final DB state:");
            eprintln!("  Alice: {a_dm_count} DMs, {a_grp_count} groups, {} contacts", a_final_contacts.len());
            eprintln!("  Bob:   {b_dm_count} DMs, {b_grp_count} groups");
            eprintln!("  Tom:   {t_dm_count} DMs, {t_grp_count} groups");
            eprintln!("  Group: {} members, {} messages (text)", final_members.len(), a_grp_msg_count);
            eprintln!("[Phase8] All DB assertions ✓");

            // Cleanup
            a3.stop_event_loop().await;
            b3.stop_event_loop().await;
            t3.stop_event_loop().await;
            a3.disconnect().await.unwrap();
            b3.disconnect().await.unwrap();
            t3.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || { drop(a3); drop(b3); drop(t3); }).await.unwrap();

            eprintln!("══════════════════════════════════════════════════════");
            eprintln!("  COMPREHENSIVE E2E WITH DOUBLE RESTART PASSED");
            eprintln!("══════════════════════════════════════════════════════");
        });
    })
    .join()
    .unwrap();
}
