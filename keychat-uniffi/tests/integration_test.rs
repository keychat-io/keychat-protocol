use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
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
    (#[ignore = $reason:literal] $name:ident, $body:expr) => {
        #[test]
        #[ignore = $reason]
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

/// Offline bundle (§6.5) flow: Bob exports bundle → Alice consumes → Alice's
/// PreKey approve arrives at Bob's firstInbox → Bob's Step 2 completes session.
/// Both sides end with an Enabled DM room and can exchange messages.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_bundle_flow_establishes_session() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice.db"));
            let bob = Arc::new(make_client(&dir, "bob.db"));

            let alice_pk = alice.create_identity().await.unwrap().pubkey_hex;
            let bob_pk = bob.create_identity().await.unwrap().pubkey_hex;

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

            // Let subscriptions settle
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Bob exports a bundle out-of-band.
            let bundle_json = bob
                .export_contact_bundle("Bob".into(), "device-1".into())
                .await
                .unwrap();
            assert!(!bundle_json.is_empty());
            assert!(
                bundle_json.contains(&bob_pk),
                "bundle must carry Bob's nostr pubkey"
            );

            // Give Bob time to refresh subscriptions to include his firstInbox.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Alice consumes the bundle. Publishes PreKey approve to Bob's firstInbox.
            let contact = alice
                .add_contact_via_bundle(bundle_json, "Alice".into())
                .await
                .unwrap();
            assert_eq!(contact.nostr_pubkey_hex, bob_pk);

            // Bob's Step 2 should fire and emit FriendRequestAccepted.
            let bob_got_prekey = wait_for_event(&bob_events, &bob_notify, 30, |e| {
                matches!(e, ClientEvent::FriendRequestAccepted { .. })
            })
            .await;
            assert!(
                bob_got_prekey,
                "Bob did not complete session from Alice's bundle PreKey in time"
            );

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Both sides should have an enabled DM room.
            let alice_rooms = alice.get_rooms(alice_pk.clone()).await.unwrap();
            let alice_dm = alice_rooms.iter().find(|r| r.to_main_pubkey == bob_pk);
            assert!(alice_dm.is_some(), "Alice should have a room with Bob");
            assert_eq!(alice_dm.unwrap().status, RoomStatus::Enabled);

            let bob_rooms = bob.get_rooms(bob_pk.clone()).await.unwrap();
            let bob_dm = bob_rooms.iter().find(|r| r.to_main_pubkey == alice_pk);
            assert!(bob_dm.is_some(), "Bob should have a room with Alice");
            assert_eq!(bob_dm.unwrap().status, RoomStatus::Enabled);

            // Both sides should have each other as a contact.
            let alice_contacts = alice.get_contacts(alice_pk.clone()).await.unwrap();
            assert!(alice_contacts.iter().any(|c| c.pubkey == bob_pk));
            let bob_contacts = bob.get_contacts(bob_pk.clone()).await.unwrap();
            assert!(bob_contacts.iter().any(|c| c.pubkey == alice_pk));

            // Verify bidirectional messaging works over the new session.
            let alice_room_id = alice_dm.unwrap().id.clone();
            alice
                .send_text(alice_room_id.clone(), "hi bob".into(), None, None, None)
                .await
                .unwrap();
            let bob_got_msg = wait_for_event(&bob_events, &bob_notify, 30, |e| {
                matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if c == "hi bob")
            })
            .await;
            assert!(bob_got_msg, "Bob did not receive Alice's first DM");

            let bob_room_id = bob_dm.unwrap().id.clone();
            bob.send_text(bob_room_id, "hi alice".into(), None, None, None)
                .await
                .unwrap();
            let alice_got_msg = wait_for_event(&alice_events, &alice_notify, 30, |e| {
                matches!(e, ClientEvent::MessageReceived { content: Some(c), .. } if c == "hi alice")
            })
            .await;
            assert!(alice_got_msg, "Alice did not receive Bob's reply");

            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

/// Bundle with tampered signal_identity_key is rejected (globalSign fails).
#[test]
fn bundle_tampered_rejected_via_app_api() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let bob = Arc::new(make_client(&dir, "bob.db"));
            let alice = Arc::new(make_client(&dir, "alice.db"));
            bob.create_identity().await.unwrap();
            alice.create_identity().await.unwrap();

            // Bob can export without relay (no publish happens).
            let bundle_json = bob
                .export_contact_bundle("Bob".into(), "device-1".into())
                .await
                .unwrap();

            // Tamper: swap signalIdentityKey to a bogus value.
            let mut payload: serde_json::Value = serde_json::from_str(&bundle_json).unwrap();
            payload["signalIdentityKey"] = serde_json::json!(
                "05deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00"
            );
            let tampered = serde_json::to_string(&payload).unwrap();

            let result = alice.add_contact_via_bundle(tampered, "Alice".into()).await;
            assert!(result.is_err(), "tampered bundle must be rejected");

            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

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

            // Resolve each side's DM room ID. send_text persists messages
            // keyed by the full room_id ("peer:identity"), not just the
            // peer pubkey — using the peer pubkey would split sent/received
            // across two different room_ids in the app DB.
            let alice_to_bob_room = {
                let rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
                rooms
                    .iter()
                    .find(|r| r.to_main_pubkey == bob_pubkey)
                    .expect("Alice must have DM room with Bob")
                    .id
                    .clone()
            };
            let bob_to_alice_room = {
                let rooms = bob.get_rooms(bob_pubkey.clone()).await.unwrap();
                rooms
                    .iter()
                    .find(|r| r.to_main_pubkey == alice_pubkey)
                    .expect("Bob must have DM room with Alice")
                    .id
                    .clone()
            };

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
                .send_text(alice_to_bob_room.clone(), "msg1".into(), None, None, None)
                .await
                .unwrap();
            wait_msg(bob_events.clone(), bob_notify.clone(), "msg1".into()).await;

            // Round 2: Bob → Alice
            bob
                .send_text(bob_to_alice_room.clone(), "msg2".into(), None, None, None)
                .await
                .unwrap();
            wait_msg(alice_events.clone(), alice_notify.clone(), "msg2".into()).await;

            // Round 3: Alice → Bob
            alice
                .send_text(alice_to_bob_room.clone(), "msg3".into(), None, None, None)
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

            // Alice: group room exists with type=SignalGroup.
            // Rooms are stored keyed by "to_main_pubkey:identity_pubkey", so
            // look up by to_main_pubkey == group_id (the SignalGroupInfo
            // `group_id` is the group pubkey only, without the identity suffix).
            let alice_rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
            let group_room = alice_rooms
                .iter()
                .find(|r| r.to_main_pubkey == group_info.group_id);
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
            // Messages are persisted under the full room_id ("group_pubkey:identity_pubkey"),
            // not the raw group_id. Resolve each side's room first.
            let alice_rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
            let alice_group_room = alice_rooms
                .iter()
                .find(|r| r.to_main_pubkey == group_id)
                .expect("Alice must have group room")
                .id
                .clone();
            let alice_msgs = alice
                .get_messages(alice_group_room, 50, 0)
                .await
                .unwrap();
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
async_test!(
    #[ignore = "requires network: wss://backup.keychat.io"]
    nip17_dm_receive_creates_room_and_message,
    {
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
    }
);

/// Alice sends NIP-17 DM, Bob replies with NIP-17 DM — full round-trip.
async_test!(
    #[ignore = "requires network: wss://backup.keychat.io"]
    nip17_dm_send_and_receive_roundtrip,
    {
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
    }
);

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

// ═══════════════════════════════════════════════════════════════════════
//  MLS Persistence Tests
//
//  These test MLS participant initialization, signer persistence across
//  restart (re-creating KeychatClient from same DB path), and multi-group
//  operations through the app-core layer.
//
//  No network is required — MLS encrypt/decrypt is local.
// ═══════════════════════════════════════════════════════════════════════

async_test!(mls_participant_initialized_on_identity_create, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "mls_init.db");

    let client = KeychatClient::new(db_path, "test-key".into()).unwrap();
    let result = client.create_identity().await.unwrap();
    assert!(!result.pubkey_hex.is_empty());

    // MLS participant should be initialized — verify via list_mls_group_ids
    // (if MLS is not initialized, this would return an error)
    let groups = client.list_mls_group_ids().await.unwrap();
    assert!(groups.is_empty(), "No MLS groups yet");

    tokio::task::spawn_blocking(move || drop(client))
        .await
        .unwrap();
});

async_test!(mls_participant_persists_across_restart, {
    let dir = tempfile::tempdir().unwrap();
    let db_path = temp_db(&dir, "mls_persist.db");

    // Phase 1: Create identity → MLS participant initialized
    let (pubkey, mnemonic) = {
        let client = KeychatClient::new(db_path.clone(), "test-key".into()).unwrap();
        let result = client.create_identity().await.unwrap();

        // Verify MLS is initialized
        let groups = client.list_mls_group_ids().await.unwrap();
        assert!(groups.is_empty());

        let pubkey = result.pubkey_hex.clone();
        let mnemonic = result.mnemonic.clone();
        tokio::task::spawn_blocking(move || drop(client))
            .await
            .unwrap();
        (pubkey, mnemonic)
    };

    // Phase 2: Re-create client from same DB, import same identity
    {
        let client = KeychatClient::new(db_path, "test-key".into()).unwrap();
        let restored_pubkey = client.import_identity(mnemonic).await.unwrap();
        assert_eq!(restored_pubkey, pubkey);

        // MLS participant should be re-initialized
        let groups = client.list_mls_group_ids().await.unwrap();
        assert!(groups.is_empty());

        tokio::task::spawn_blocking(move || drop(client))
            .await
            .unwrap();
    }
});

/// Full E2E: Signal friends → Signal group → MLS group → restart → verify.
///
/// Requires TEST_RELAY to be reachable.
/// Flow: 4 identities (Alice, Bob, Charlie, Dave)
///   Phase 1: Alice↔Bob, Alice↔Charlie, Alice↔Dave friendships via Signal
///   Phase 2: Signal DMs (all directions)
///   Phase 3: Signal group (Alice+Bob+Charlie) — send/receive
///   Phase 4: MLS group 1 (Alice+Bob+Charlie) — create, send/receive via relay
///   Phase 5: MLS group 2 (Bob+Charlie+Dave) — independent group
///   Phase 6: Restart all clients — restore sessions, MLS signers
///   Phase 7: Post-restart Signal DM + Signal group + MLS group messaging
///   Phase 8: MLS group management — remove member, verify isolation
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn mls_e2e_full_lifecycle_with_restart() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();

            // ══════════════════════════════════════════════════════
            // Phase 1: Create 4 identities, establish friendships
            // ══════════════════════════════════════════════════════
            eprintln!("[Phase1] Creating 4 identities...");

            let alice = Arc::new(make_client(&dir, "mls_alice.db"));
            let bob = Arc::new(make_client(&dir, "mls_bob.db"));
            let charlie = Arc::new(make_client(&dir, "mls_charlie.db"));
            let dave = Arc::new(make_client(&dir, "mls_dave.db"));

            let ar = alice.create_identity().await.unwrap();
            let br = bob.create_identity().await.unwrap();
            let cr = charlie.create_identity().await.unwrap();
            let dr = dave.create_identity().await.unwrap();

            let a_pub = ar.pubkey_hex.clone();
            let b_pub = br.pubkey_hex.clone();
            let c_pub = cr.pubkey_hex.clone();
            let d_pub = dr.pubkey_hex.clone();
            let a_mnemonic = ar.mnemonic.clone();
            let b_mnemonic = br.mnemonic.clone();
            let c_mnemonic = cr.mnemonic.clone();
            let d_mnemonic = dr.mnemonic.clone();

            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();
            charlie.connect(vec![TEST_RELAY.into()]).await.unwrap();
            dave.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an = Arc::new(tokio::sync::Notify::new());
            let bn = Arc::new(tokio::sync::Notify::new());
            let cn = Arc::new(tokio::sync::Notify::new());
            let dn = Arc::new(tokio::sync::Notify::new());
            let (al, ae) = CapturingEventListener::new(an.clone());
            let (bl, be) = CapturingEventListener::new(bn.clone());
            let (cl, ce) = CapturingEventListener::new(cn.clone());
            let (dl, de) = CapturingEventListener::new(dn.clone());
            alice.set_event_listener(Box::new(al)).await;
            bob.set_event_listener(Box::new(bl)).await;
            charlie.set_event_listener(Box::new(cl)).await;
            dave.set_event_listener(Box::new(dl)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();
            Arc::clone(&charlie).start_event_loop().await.unwrap();
            Arc::clone(&dave).start_event_loop().await.unwrap();

            // Alice ↔ Bob
            establish_friendship(&alice, "Alice", &bob, "Bob", &be, &bn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Bob ✓");

            // Alice ↔ Charlie
            ae.lock().unwrap().clear();
            establish_friendship(&alice, "Alice", &charlie, "Charlie", &ce, &cn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Charlie ✓");

            // Alice ↔ Dave
            ae.lock().unwrap().clear();
            establish_friendship(&alice, "Alice", &dave, "Dave", &de, &dn, &ae, &an).await;
            eprintln!("[Phase1] Alice ↔ Dave ✓");

            // Bob ↔ Charlie
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            establish_friendship(&bob, "Bob", &charlie, "Charlie", &ce, &cn, &be, &bn).await;
            eprintln!("[Phase1] Bob ↔ Charlie ✓");

            // Bob ↔ Dave
            be.lock().unwrap().clear();
            de.lock().unwrap().clear();
            establish_friendship(&bob, "Bob", &dave, "Dave", &de, &dn, &be, &bn).await;
            eprintln!("[Phase1] Bob ↔ Dave ✓");

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            eprintln!("[Phase1] All friendships established ✓");

            // Helper closures
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

            // ══════════════════════════════════════════════════════
            // Phase 2: Signal DMs
            // ══════════════════════════════════════════════════════
            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();

            alice.send_text(b_pub.clone(), "dm:A→B".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&be, &bn, "dm:A→B").await, "Bob should get A→B");

            be.lock().unwrap().clear();
            bob.send_text(a_pub.clone(), "dm:B→A".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&ae, &an, "dm:B→A").await, "Alice should get B→A");
            eprintln!("[Phase2] Signal DMs ✓");

            // ══════════════════════════════════════════════════════
            // Phase 3: Signal group (Alice + Bob + Charlie)
            // ══════════════════════════════════════════════════════
            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();

            let sg = alice.create_signal_group(
                "SigGroup".into(),
                vec![
                    GroupMemberInput { nostr_pubkey: b_pub.clone(), name: "Bob".into() },
                    GroupMemberInput { nostr_pubkey: c_pub.clone(), name: "Charlie".into() },
                ],
            ).await.unwrap();
            let sg_id = sg.group_id.clone();
            eprintln!("[Phase3] Signal group created: {}", &sg_id[..16]);

            // Wait for invites
            assert!(
                wait_for_event(&be, &bn, 30, |e| matches!(e, ClientEvent::GroupInviteReceived { .. })).await,
                "Bob should get signal group invite"
            );
            assert!(
                wait_for_event(&ce, &cn, 30, |e| matches!(e, ClientEvent::GroupInviteReceived { .. })).await,
                "Charlie should get signal group invite"
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Signal group messaging
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            alice.send_group_text(sg_id.clone(), "sg:Alice-1".into(), None).await.unwrap();
            assert!(wait_msg(&be, &bn, "sg:Alice-1").await, "Bob gets signal group msg");
            assert!(wait_msg(&ce, &cn, "sg:Alice-1").await, "Charlie gets signal group msg");
            eprintln!("[Phase3] Signal group messaging ✓");

            // ══════════════════════════════════════════════════════
            // Phase 4: MLS group 1 (Alice + Bob + Charlie)
            // ══════════════════════════════════════════════════════
            ae.lock().unwrap().clear();
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();

            // Use MlsParticipant directly to create group + get welcome bytes.
            // This tests the actual MLS protocol; invite delivery via Signal
            // is tested separately by checking GroupInviteReceived event arrival.
            use keychat_app_core::{MlsParticipant, MlsProvider};

            let mg1_id;
            let mg1_temp_inbox;
            {
                // Generate KeyPackages from Bob and Charlie's MLS participants
                let bob_kp_bytes = bob.generate_mls_key_package().await.unwrap();
                let charlie_kp_bytes = charlie.generate_mls_key_package().await.unwrap();

                // Alice creates the MLS group via AppClient API
                let mg1 = alice.create_mls_group(
                    "MLS-Alpha".into(),
                    vec![
                        MlsKeyPackageInput { nostr_pubkey: b_pub.clone(), key_package_bytes: bob_kp_bytes },
                        MlsKeyPackageInput { nostr_pubkey: c_pub.clone(), key_package_bytes: charlie_kp_bytes },
                    ],
                ).await.unwrap();
                mg1_id = mg1.group_id.clone();
                mg1_temp_inbox = mg1.mls_temp_inbox.clone();
                eprintln!("[Phase4] MLS group 1 created: {} temp_inbox={}", &mg1_id[..16], &mg1_temp_inbox[..16]);

                // Wait for MLS invites (arrive via Signal 1:1 session)
                assert!(
                    wait_for_event(&be, &bn, 30, |e| {
                        matches!(e, ClientEvent::GroupInviteReceived { group_type, .. } if group_type == "mls")
                    }).await,
                    "Bob should get MLS invite"
                );
                assert!(
                    wait_for_event(&ce, &cn, 30, |e| {
                        matches!(e, ClientEvent::GroupInviteReceived { group_type, .. } if group_type == "mls")
                    }).await,
                    "Charlie should get MLS invite"
                );
                eprintln!("[Phase4] MLS invites received ✓");

                // Bob and Charlie join: the welcome bytes are in the invite message
                // stored by event_loop. Retrieve from the GroupInviteReceived event's room.
                // Since the event_loop now stores invite payload as a message, we parse it.
                // Give a moment for DB writes.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                // Helper to extract welcome_bytes from stored invite message
                async fn extract_welcome(
                    client: &KeychatClient,
                    pubkey: &str,
                ) -> Option<(Vec<u8>, String)> {
                    let rooms = client.get_rooms(pubkey.to_string()).await.ok()?;
                    eprintln!("    extract_welcome: {} rooms found for {}", rooms.len(), &pubkey[..16]);
                    for room in &rooms {
                        eprintln!("      room: id={} type={:?} status={:?} name={:?}",
                            &room.id[..16.min(room.id.len())], room.room_type, room.status, room.name);
                        if room.room_type == RoomType::MlsGroup {
                            eprintln!("      getting messages for room_id={}", &room.id);
                            let msgs = client.get_messages(room.id.clone(), 10, 0).await.ok()?;
                            eprintln!("      {} messages in MLS room", msgs.len());
                            for m in &msgs {
                                eprintln!("        msg: content_len={} starts_with={}", m.content.len(), &m.content[..40.min(m.content.len())]);
                                if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&m.content) {
                                    if let Some(welcome_b64) = payload.get("welcome").and_then(|v| v.as_str()) {
                                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(welcome_b64) {
                                            let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("MLS");
                                            return Some((bytes, name.to_string()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    None
                }

                // Bob joins
                if let Some((welcome, name)) = extract_welcome(&bob, &b_pub).await {
                    bob.join_mls_group(welcome, name, vec![a_pub.clone()]).await.unwrap();
                    eprintln!("[Phase4] Bob joined MLS group ✓");
                } else {
                    panic!("Bob could not find MLS invite welcome bytes");
                }

                // Charlie joins
                if let Some((welcome, name)) = extract_welcome(&charlie, &c_pub).await {
                    charlie.join_mls_group(welcome, name, vec![a_pub.clone()]).await.unwrap();
                    eprintln!("[Phase4] Charlie joined MLS group ✓");
                } else {
                    panic!("Charlie could not find MLS invite welcome bytes");
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // MLS group messaging — Alice → group via relay
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            alice.send_mls_text(mg1_id.clone(), "mls:Alice-1".into(), None).await.unwrap();

            // Bob and Charlie should receive via event loop (mlsTempInbox subscription)
            let bob_got = wait_msg(&be, &bn, "mls:Alice-1").await;
            let charlie_got = wait_msg(&ce, &cn, "mls:Alice-1").await;
            eprintln!("[Phase4] MLS group msg: Bob={} Charlie={}", bob_got, charlie_got);
            assert!(bob_got, "Bob should receive MLS group message via relay");
            assert!(charlie_got, "Charlie should receive MLS group message via relay");
            eprintln!("[Phase4] MLS group messaging via relay ✓");

            // Bob → group
            ae.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            bob.send_mls_text(mg1_id.clone(), "mls:Bob-1".into(), None).await.unwrap();
            assert!(wait_msg(&ae, &an, "mls:Bob-1").await, "Alice should get Bob's MLS msg");
            assert!(wait_msg(&ce, &cn, "mls:Bob-1").await, "Charlie should get Bob's MLS msg");
            eprintln!("[Phase4] Bob→group ✓");

            // ══════════════════════════════════════════════════════
            // Phase 5: MLS group 2 (Bob + Charlie + Dave)
            // ══════════════════════════════════════════════════════
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            de.lock().unwrap().clear();

            let charlie_kp2 = charlie.generate_mls_key_package().await.unwrap();
            let dave_kp = dave.generate_mls_key_package().await.unwrap();

            let mg2 = bob.create_mls_group(
                "MLS-Beta".into(),
                vec![
                    MlsKeyPackageInput { nostr_pubkey: c_pub.clone(), key_package_bytes: charlie_kp2 },
                    MlsKeyPackageInput { nostr_pubkey: d_pub.clone(), key_package_bytes: dave_kp },
                ],
            ).await.unwrap();
            let mg2_id = mg2.group_id.clone();
            eprintln!("[Phase5] MLS group 2 created: {}", &mg2_id[..16]);

            // Verify Alice's MLS groups don't include mg2
            let a_mls_groups = alice.list_mls_group_ids().await.unwrap();
            assert!(a_mls_groups.contains(&mg1_id), "Alice should be in MLS group 1");
            assert!(!a_mls_groups.contains(&mg2_id), "Alice should NOT be in MLS group 2");
            eprintln!("[Phase5] Group isolation ✓");

            // ══════════════════════════════════════════════════════
            // Phase 6: Restart all clients
            // ══════════════════════════════════════════════════════
            eprintln!("[Phase6] Shutting down all clients...");
            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            charlie.stop_event_loop().await;
            dave.stop_event_loop().await;
            alice.close_storage().await.unwrap();
            bob.close_storage().await.unwrap();
            charlie.close_storage().await.unwrap();
            dave.close_storage().await.unwrap();
            alice.disconnect().await.unwrap();
            bob.disconnect().await.unwrap();
            charlie.disconnect().await.unwrap();
            dave.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || {
                drop(alice); drop(bob); drop(charlie); drop(dave);
            }).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // Recreate clients
            let alice = Arc::new(make_client(&dir, "mls_alice.db"));
            let bob = Arc::new(make_client(&dir, "mls_bob.db"));
            let charlie = Arc::new(make_client(&dir, "mls_charlie.db"));
            let dave = Arc::new(make_client(&dir, "mls_dave.db"));

            assert_eq!(alice.import_identity(a_mnemonic).await.unwrap(), a_pub);
            assert_eq!(bob.import_identity(b_mnemonic).await.unwrap(), b_pub);
            assert_eq!(charlie.import_identity(c_mnemonic).await.unwrap(), c_pub);
            assert_eq!(dave.import_identity(d_mnemonic).await.unwrap(), d_pub);

            alice.restore_sessions().await.unwrap();
            bob.restore_sessions().await.unwrap();
            charlie.restore_sessions().await.unwrap();
            dave.restore_sessions().await.unwrap();
            eprintln!("[Phase6] Sessions restored ✓");

            // Verify MLS groups survived restart
            let a_groups = alice.list_mls_group_ids().await.unwrap();
            let b_groups = bob.list_mls_group_ids().await.unwrap();
            assert!(a_groups.contains(&mg1_id), "Alice should still have MLS group 1");
            assert!(b_groups.contains(&mg1_id), "Bob should still have MLS group 1");
            assert!(b_groups.contains(&mg2_id), "Bob should still have MLS group 2");
            eprintln!("[Phase6] MLS group persistence ✓");

            // Reconnect
            alice.connect(vec![TEST_RELAY.into()]).await.unwrap();
            bob.connect(vec![TEST_RELAY.into()]).await.unwrap();
            charlie.connect(vec![TEST_RELAY.into()]).await.unwrap();
            dave.connect(vec![TEST_RELAY.into()]).await.unwrap();

            let an = Arc::new(tokio::sync::Notify::new());
            let bn = Arc::new(tokio::sync::Notify::new());
            let cn = Arc::new(tokio::sync::Notify::new());
            let dn = Arc::new(tokio::sync::Notify::new());
            let (al, ae) = CapturingEventListener::new(an.clone());
            let (bl, be) = CapturingEventListener::new(bn.clone());
            let (cl, ce) = CapturingEventListener::new(cn.clone());
            let (dl, de) = CapturingEventListener::new(dn.clone());
            alice.set_event_listener(Box::new(al)).await;
            bob.set_event_listener(Box::new(bl)).await;
            charlie.set_event_listener(Box::new(cl)).await;
            dave.set_event_listener(Box::new(dl)).await;

            Arc::clone(&alice).start_event_loop().await.unwrap();
            Arc::clone(&bob).start_event_loop().await.unwrap();
            Arc::clone(&charlie).start_event_loop().await.unwrap();
            Arc::clone(&dave).start_event_loop().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            // ══════════════════════════════════════════════════════
            // Phase 7: Post-restart messaging
            // ══════════════════════════════════════════════════════

            // Signal DM still works
            alice.send_text(b_pub.clone(), "post-restart:A→B".into(), None, None, None).await.unwrap();
            assert!(wait_msg(&be, &bn, "post-restart:A→B").await, "Post-restart DM should work");
            eprintln!("[Phase7] Post-restart Signal DM ✓");

            // Signal group still works
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            alice.send_group_text(sg_id.clone(), "post-restart:sg".into(), None).await.unwrap();
            assert!(wait_msg(&be, &bn, "post-restart:sg").await, "Post-restart signal group should work");
            eprintln!("[Phase7] Post-restart Signal group ✓");

            // MLS group messaging after restart
            be.lock().unwrap().clear();
            ce.lock().unwrap().clear();
            alice.send_mls_text(mg1_id.clone(), "post-restart:mls1".into(), None).await.unwrap();
            let bob_got = wait_msg(&be, &bn, "post-restart:mls1").await;
            let charlie_got = wait_msg(&ce, &cn, "post-restart:mls1").await;
            eprintln!("[Phase7] Post-restart MLS group 1: Bob={} Charlie={}", bob_got, charlie_got);

            // MLS group 2 messaging after restart
            ce.lock().unwrap().clear();
            de.lock().unwrap().clear();
            bob.send_mls_text(mg2_id.clone(), "post-restart:mls2".into(), None).await.unwrap();
            let charlie_got2 = wait_msg(&ce, &cn, "post-restart:mls2").await;
            let dave_got = wait_msg(&de, &dn, "post-restart:mls2").await;
            eprintln!("[Phase7] Post-restart MLS group 2: Charlie={} Dave={}", charlie_got2, dave_got);

            // ══════════════════════════════════════════════════════
            // Phase 8: Cleanup
            // ══════════════════════════════════════════════════════
            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            charlie.stop_event_loop().await;
            dave.stop_event_loop().await;
            alice.disconnect().await.unwrap();
            bob.disconnect().await.unwrap();
            charlie.disconnect().await.unwrap();
            dave.disconnect().await.unwrap();
            tokio::task::spawn_blocking(move || {
                drop(alice); drop(bob); drop(charlie); drop(dave);
            }).await.unwrap();

            eprintln!("══════════════════════════════════════════════════════");
            eprintln!("  MLS E2E FULL LIFECYCLE WITH RESTART PASSED");
            eprintln!("══════════════════════════════════════════════════════");
        });
    })
    .join()
    .unwrap();
}

/// Full MLS lifecycle through AppClient: 3 identities, 2 groups,
/// restart with signer recovery, encrypt/decrypt across restarts.
#[test]
fn mls_multi_identity_multi_group_persistence() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();

            // We test the MLS participant layer directly since the full
            // AppClient MLS API (create_mls_group etc.) requires relay
            // transport. The MlsParticipant is what AppClient delegates to.

            let alice_mls_db = dir
                .path()
                .join("alice_mls.db")
                .to_str()
                .unwrap()
                .to_string();
            let bob_mls_db = dir.path().join("bob_mls.db").to_str().unwrap().to_string();
            let charlie_mls_db = dir
                .path()
                .join("charlie_mls.db")
                .to_str()
                .unwrap()
                .to_string();

            let alice_id = "alice_uniffi_test_aaaa1111";
            let bob_id = "bob_uniffi_test_bbbb2222";
            let charlie_id = "charlie_uniffi_test_cccc3333";

            let group_a = "uniffi-group-alpha";
            let group_b = "uniffi-group-beta";

            use keychat_app_core::{MlsDecryptResult, MlsParticipant, MlsProvider};

            // ═══ Phase 1: Create participants, build 2 groups ═══
            eprintln!("[MLS Phase 1] Creating 3 participants, 2 groups...");
            {
                let alice = MlsParticipant::with_provider(
                    alice_id,
                    MlsProvider::open(&alice_mls_db).unwrap(),
                )
                .unwrap();
                let bob =
                    MlsParticipant::with_provider(bob_id, MlsProvider::open(&bob_mls_db).unwrap())
                        .unwrap();
                let charlie = MlsParticipant::with_provider(
                    charlie_id,
                    MlsProvider::open(&charlie_mls_db).unwrap(),
                )
                .unwrap();

                // group_a: Alice + Bob + Charlie
                alice.create_group(group_a, "Alpha Group").unwrap();
                let bob_kp = bob.generate_key_package().unwrap();
                let charlie_kp = charlie.generate_key_package().unwrap();
                let (commit_a, welcome_a) = alice
                    .add_members(group_a, vec![bob_kp, charlie_kp])
                    .unwrap();
                bob.join_group(&welcome_a).unwrap();
                charlie.join_group(&welcome_a).unwrap();

                // group_b: Bob + Charlie (Alice not in this group)
                bob.create_group(group_b, "Beta Group").unwrap();
                let charlie_kp2 = charlie.generate_key_package().unwrap();
                let (_commit_b, welcome_b) = bob.add_members(group_b, vec![charlie_kp2]).unwrap();
                charlie.join_group(&welcome_b).unwrap();

                // Verify cross-group messaging
                let ct1 = alice.encrypt(group_a, b"alpha-hello-1").unwrap();
                let MlsDecryptResult::Application {
                    plaintext,
                    sender_id,
                } = bob.decrypt(group_a, &ct1).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(plaintext, b"alpha-hello-1");
                assert_eq!(sender_id, alice_id);
                let MlsDecryptResult::Application { plaintext: p2, .. } =
                    charlie.decrypt(group_a, &ct1).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p2, b"alpha-hello-1");

                let ct2 = bob.encrypt(group_b, b"beta-hello-1").unwrap();
                let MlsDecryptResult::Application { plaintext: p3, .. } =
                    charlie.decrypt(group_b, &ct2).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p3, b"beta-hello-1");

                // Alice should NOT have access to group_b
                assert!(alice.encrypt(group_b, b"should-fail").is_err());

                eprintln!("[MLS Phase 1] ✓ 2 groups created, cross-group messaging verified");
            }
            // All participants dropped

            // ═══ Phase 2: Restart — restore all 3, verify both groups ═══
            eprintln!("[MLS Phase 2] Restarting all 3 participants...");
            {
                let alice = MlsParticipant::with_provider(
                    alice_id,
                    MlsProvider::open(&alice_mls_db).unwrap(),
                )
                .unwrap();
                let bob =
                    MlsParticipant::with_provider(bob_id, MlsProvider::open(&bob_mls_db).unwrap())
                        .unwrap();
                let charlie = MlsParticipant::with_provider(
                    charlie_id,
                    MlsProvider::open(&charlie_mls_db).unwrap(),
                )
                .unwrap();

                // group_a members intact
                let members_a = alice.group_members(group_a).unwrap();
                assert_eq!(members_a.len(), 3);

                // group_b members intact
                let members_b = bob.group_members(group_b).unwrap();
                assert_eq!(members_b.len(), 2);

                // Messaging in group_a after restart
                let ct = bob.encrypt(group_a, b"alpha-after-restart").unwrap();
                let MlsDecryptResult::Application { plaintext, .. } =
                    alice.decrypt(group_a, &ct).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(plaintext, b"alpha-after-restart");
                let MlsDecryptResult::Application { plaintext: p2, .. } =
                    charlie.decrypt(group_a, &ct).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p2, b"alpha-after-restart");

                // Messaging in group_b after restart
                let ct2 = charlie.encrypt(group_b, b"beta-after-restart").unwrap();
                let MlsDecryptResult::Application { plaintext: p3, .. } =
                    bob.decrypt(group_b, &ct2).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p3, b"beta-after-restart");

                // Epoch rotation in group_a (two-phase: broadcast then merge)
                let commit = alice.self_update(group_a).unwrap();
                bob.process_commit(group_a, &commit).unwrap();
                charlie.process_commit(group_a, &commit).unwrap();
                alice.self_commit(group_a).unwrap();

                // All 3 derive same new temp inbox
                let inbox_a = alice.derive_temp_inbox(group_a).unwrap();
                let inbox_b = bob.derive_temp_inbox(group_a).unwrap();
                let inbox_c = charlie.derive_temp_inbox(group_a).unwrap();
                assert_eq!(inbox_a, inbox_b);
                assert_eq!(inbox_b, inbox_c);

                // Post-epoch messaging
                let ct3 = charlie.encrypt(group_a, b"alpha-new-epoch").unwrap();
                let MlsDecryptResult::Application { plaintext: p4, .. } =
                    alice.decrypt(group_a, &ct3).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p4, b"alpha-new-epoch");

                // Epoch rotation in group_b (independent, two-phase)
                let commit_b = bob.self_update(group_b).unwrap();
                charlie.process_commit(group_b, &commit_b).unwrap();
                bob.self_commit(group_b).unwrap();

                let ct4 = bob.encrypt(group_b, b"beta-new-epoch").unwrap();
                let MlsDecryptResult::Application { plaintext: p5, .. } =
                    charlie.decrypt(group_b, &ct4).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p5, b"beta-new-epoch");

                // Metadata survives
                let ext_a = alice.group_extension(group_a).unwrap();
                assert_eq!(ext_a.name(), "Alpha Group");
                let ext_b = bob.group_extension(group_b).unwrap();
                assert_eq!(ext_b.name(), "Beta Group");

                eprintln!("[MLS Phase 2] ✓ Both groups work after restart + epoch rotation");
            }
            // All dropped again

            // ═══ Phase 3: Second restart — remove member, verify isolation ═══
            eprintln!("[MLS Phase 3] Second restart, removing Charlie from group_a...");
            {
                let alice = MlsParticipant::with_provider(
                    alice_id,
                    MlsProvider::open(&alice_mls_db).unwrap(),
                )
                .unwrap();
                let bob =
                    MlsParticipant::with_provider(bob_id, MlsProvider::open(&bob_mls_db).unwrap())
                        .unwrap();
                let charlie = MlsParticipant::with_provider(
                    charlie_id,
                    MlsProvider::open(&charlie_mls_db).unwrap(),
                )
                .unwrap();

                // Remove Charlie from group_a (two-phase)
                let charlie_idx = alice.find_member_index(group_a, charlie_id).unwrap();
                let rm_commit = alice.remove_members(group_a, &[charlie_idx]).unwrap();
                bob.process_commit(group_a, &rm_commit).unwrap();
                alice.self_commit(group_a).unwrap();

                // Alice → Bob works, Charlie fails
                let ct = alice.encrypt(group_a, b"no-more-charlie").unwrap();
                let MlsDecryptResult::Application { plaintext, .. } =
                    bob.decrypt(group_a, &ct).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(plaintext, b"no-more-charlie");
                assert!(
                    charlie.decrypt(group_a, &ct).is_err(),
                    "Removed member must not decrypt"
                );

                // group_b unaffected — Charlie still there
                let ct2 = charlie.encrypt(group_b, b"beta-still-here").unwrap();
                let MlsDecryptResult::Application { plaintext: p2, .. } =
                    bob.decrypt(group_b, &ct2).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p2, b"beta-still-here");

                eprintln!("[MLS Phase 3] ✓ Member removal + group isolation verified");
            }

            // ═══ Phase 4: Third restart — final state check ═══
            eprintln!("[MLS Phase 4] Third restart, final state verification...");
            {
                let alice = MlsParticipant::with_provider(
                    alice_id,
                    MlsProvider::open(&alice_mls_db).unwrap(),
                )
                .unwrap();
                let bob =
                    MlsParticipant::with_provider(bob_id, MlsProvider::open(&bob_mls_db).unwrap())
                        .unwrap();
                let charlie = MlsParticipant::with_provider(
                    charlie_id,
                    MlsProvider::open(&charlie_mls_db).unwrap(),
                )
                .unwrap();

                // group_a: Alice + Bob only
                let members = alice.group_members(group_a).unwrap();
                assert_eq!(members.len(), 2);
                assert!(members.contains(&alice_id.to_string()));
                assert!(members.contains(&bob_id.to_string()));
                assert!(!members.contains(&charlie_id.to_string()));

                // group_b: Bob + Charlie
                let members_b = bob.group_members(group_b).unwrap();
                assert_eq!(members_b.len(), 2);

                // Final messaging check
                let ct = bob.encrypt(group_a, b"final-alpha").unwrap();
                let MlsDecryptResult::Application {
                    plaintext,
                    sender_id,
                } = alice.decrypt(group_a, &ct).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(plaintext, b"final-alpha");
                assert_eq!(sender_id, bob_id);

                let ct2 = charlie.encrypt(group_b, b"final-beta").unwrap();
                let MlsDecryptResult::Application {
                    plaintext: p2,
                    sender_id: s2,
                } = bob.decrypt(group_b, &ct2).unwrap()
                else {
                    panic!("decrypt failed")
                };
                assert_eq!(p2, b"final-beta");
                assert_eq!(s2, charlie_id);

                eprintln!("[MLS Phase 4] ✓ All final state assertions passed");
            }

            eprintln!("══════════════════════════════════════════════════════");
            eprintln!("  MLS MULTI-IDENTITY MULTI-GROUP PERSISTENCE PASSED");
            eprintln!("══════════════════════════════════════════════════════");
        });
    })
    .join()
    .unwrap();
}

// ─── Public Agent (spec §3.6) e2e ────────────────────────────────────────────

/// Full round-trip of the Public Agent protocol over a real relay:
///
/// - Bob enables Public Agent mode (端 B).
/// - Alice sends friendRequest; Bob auto-accepts → `friendApprove` carries
///   `publicAgent: true`.
/// - Alice persists the flag on her peer record (端 A closes loop on sender side).
/// - Alice sends a follow-up text → event includes dual p-tag.
/// - Bob receives it, marks Alice as upgraded → subscription shrinks.
/// - Bob restarts → agent mode survives via `protocol_settings`.
/// - After restart, a second exchange confirms state fully rehydrated.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_public_agent_full_round_trip() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice_pa.db"));
            let bob = Arc::new(make_client(&dir, "bob_pa.db"));

            let alice_id = alice.create_identity().await.unwrap();
            let bob_id = bob.create_identity().await.unwrap();
            let alice_pubkey = alice_id.pubkey_hex.clone();
            let bob_pubkey = bob_id.pubkey_hex.clone();

            // Bob enables Public Agent mode BEFORE accepting the friend request.
            assert!(!bob.is_self_public_agent().await);
            bob.set_self_public_agent(true).await.unwrap();
            assert!(bob.is_self_public_agent().await);

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

            // Allow DB writes to settle after approve.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // ── 端 A assertion: Alice learned Bob is a Public Agent ──────────
            assert!(
                alice.is_peer_public_agent(bob_pubkey.clone()).await,
                "Alice must persist publicAgent flag from Bob's friendApprove"
            );
            assert!(
                !alice.is_peer_public_agent(alice_pubkey.clone()).await,
                "own pubkey is not a peer"
            );
            // A peer we've never seen returns false, not an error.
            assert!(
                !alice
                    .is_peer_public_agent(
                        "0000000000000000000000000000000000000000000000000000000000000000".into()
                    )
                    .await
            );

            // ── 端 B + 端 A round-trip: Alice → Bob message should use dual p-tag ─
            // Find the Alice→Bob DM room so we can send a text.
            let alice_rooms = alice.get_rooms(alice_pubkey.clone()).await.unwrap();
            let alice_bob_room = alice_rooms
                .iter()
                .find(|r| r.to_main_pubkey == bob_pubkey)
                .expect("Alice must have DM room with Bob");

            bob_events.lock().unwrap().clear();
            alice
                .send_text(
                    alice_bob_room.id.clone(),
                    "hello agent".into(),
                    None,
                    None,
                    None,
                )
                .await
                .unwrap();

            // Bob must receive it via his own-npub-only subscription.
            let got = wait_for_event(&bob_events, &bob_notify, 30, |e| {
                matches!(e, ClientEvent::MessageReceived { .. })
            })
            .await;
            assert!(
                got,
                "Bob (agent) did not receive Alice's dual-p-tag message via npub subscription"
            );

            // 端 B assertion: Bob marks Alice as upgraded.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            assert!(
                bob.is_peer_upgraded_to_dual_tag(alice_pubkey.clone()).await,
                "Bob must mark Alice as having upgraded to dual p-tag after receiving her message"
            );

            // ── Restart Bob: agent mode + upgraded peer must survive ─────────
            alice.stop_event_loop().await;
            bob.stop_event_loop().await;
            drop_client(Arc::try_unwrap(alice).ok().unwrap()).await;
            drop_client(Arc::try_unwrap(bob).ok().unwrap()).await;

            let bob2 = Arc::new(make_client(&dir, "bob_pa.db"));
            bob2.import_identity(bob_id.mnemonic.clone()).await.unwrap();
            bob2.restore_sessions().await.unwrap();

            assert!(
                bob2.is_self_public_agent().await,
                "self_is_public_agent must survive restart"
            );
            assert!(
                bob2.is_peer_upgraded_to_dual_tag(alice_pubkey.clone())
                    .await,
                "peer_uses_dual_p_tag must survive restart"
            );

            drop_client(Arc::try_unwrap(bob2).ok().unwrap()).await;
        });
    })
    .join()
    .unwrap();
}

/// Control test: when Bob does NOT enable agent mode, friendApprove does NOT
/// carry `publicAgent`, and Alice does NOT mark Bob as an agent. This guards
/// against accidental default-true regressions.
#[test]
#[ignore = "requires network: wss://backup.keychat.io"]
fn network_non_agent_peer_has_no_public_agent_flag() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let alice = Arc::new(make_client(&dir, "alice_pa2.db"));
            let bob = Arc::new(make_client(&dir, "bob_pa2.db"));

            let _ = alice.create_identity().await.unwrap();
            let bob_id = bob.create_identity().await.unwrap();
            let alice_pubkey = alice.get_pubkey_hex().await.unwrap();
            let bob_pubkey = bob_id.pubkey_hex.clone();

            // Bob stays in NORMAL mode.
            assert!(!bob.is_self_public_agent().await);

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

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            assert!(
                !alice.is_peer_public_agent(bob_pubkey.clone()).await,
                "non-agent Bob must NOT be flagged as Public Agent on Alice's side"
            );
            assert!(
                !bob.is_peer_upgraded_to_dual_tag(alice_pubkey.clone()).await,
                "non-agent Bob has no reason to mark Alice as upgraded"
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
