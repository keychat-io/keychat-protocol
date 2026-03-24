use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

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
