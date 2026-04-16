//! V1 migration integration tests.
//!
//! Creates mock v1 data (Isar JSON + Signal SQLite), runs migration,
//! then verifies all data was correctly imported into the new encrypted DBs.

#[cfg(test)]
mod tests {
    use keychat_app_core::app_storage::AppStorage;
    use keychat_app_core::v1_migration::migrate_from_v1;
    use rusqlite::{params, Connection};
    use std::collections::HashMap;
    use tempfile::TempDir;

    /// Create a mock v1 signal_protocol.db with test data.
    fn create_mock_signal_db(path: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE identity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nextPrekeyId INTEGER,
                registrationId INTEGER,
                device INTEGER,
                address TEXT,
                privateKey TEXT,
                publicKey TEXT,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT,
                device INTEGER,
                record TEXT,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE pre_key (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyId INTEGER,
                record TEXT,
                used BOOL DEFAULT false,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE signed_key (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyId INTEGER,
                record TEXT,
                used BOOL DEFAULT false,
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();

        // Insert test data (hex-encoded dummy bytes)
        conn.execute(
            "INSERT INTO identity (address, publicKey, privateKey) VALUES (?1, ?2, ?3)",
            params!["test-peer", "05aabbccdd", "1122334455"],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO session (address, device, record) VALUES (?1, ?2, ?3)",
            params!["test-peer", 1, "deadbeef0102030405"],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO pre_key (keyId, record, used) VALUES (?1, ?2, ?3)",
            params![42, "aabb0102", false],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO signed_key (keyId, record) VALUES (?1, ?2)",
            params![1, "ccdd0506"],
        )
        .unwrap();
    }

    /// Create mock Isar JSON export data.
    fn create_mock_isar_json() -> String {
        let mut collections: HashMap<String, String> = HashMap::new();

        // Identity
        collections.insert(
            "Identity".to_string(),
            serde_json::to_string(&serde_json::json!([
                {
                    "id": 1,
                    "name": "Alice",
                    "npub": "npub1test123456789abcdef",
                    "secp256k1PKHex": "aabb1122334455667788990011223344aabb1122334455667788990011223344",
                    "curve25519PkHex": "05deadbeef",
                    "isDefault": true,
                    "index": 0,
                    "createdAt": 1700000000000_i64
                }
            ]))
            .unwrap(),
        );

        // Contact
        collections.insert(
            "Contact".to_string(),
            serde_json::to_string(&serde_json::json!([
                {
                    "id": 10,
                    "pubkey": "bbcc2233445566778899001122334455bbcc2233445566778899001122334455",
                    "npubkey": "npub1contact123",
                    "identityId": 1,
                    "curve25519PkHex": "05cafebabe",
                    "petname": "Bob",
                    "name": "Bob Keychat",
                    "about": "Test contact",
                    "createdAt": 1700000001000_i64,
                    "updatedAt": 1700000002000_i64
                }
            ]))
            .unwrap(),
        );

        // Room
        collections.insert(
            "Room".to_string(),
            serde_json::to_string(&serde_json::json!([
                {
                    "id": 100,
                    "toMainPubkey": "bbcc2233445566778899001122334455bbcc2233445566778899001122334455",
                    "identityId": 1,
                    "npub": "npub1contact123",
                    "status": 3,
                    "type": 0,
                    "name": "Bob",
                    "curve25519PkHex": "05cafebabe",
                    "createdAt": 1700000001000_i64
                }
            ]))
            .unwrap(),
        );

        // Message
        collections.insert(
            "Message".to_string(),
            serde_json::to_string(&serde_json::json!([
                {
                    "id": 1000,
                    "msgid": "msg-001",
                    "identityId": 1,
                    "roomId": 100,
                    "idPubkey": "aabb1122334455667788990011223344aabb1122334455667788990011223344",
                    "from": "aabb1122334455667788990011223344aabb1122334455667788990011223344",
                    "content": "{\"c\":\"signal\",\"type\":100,\"msg\":\"Hello Bob\"}",
                    "realMessage": "Hello Bob",
                    "createdAt": 1700000010000_i64,
                    "isMeSend": true,
                    "isRead": true,
                    "sent": 1
                },
                {
                    "id": 1001,
                    "msgid": "msg-002",
                    "identityId": 1,
                    "roomId": 100,
                    "from": "bbcc2233445566778899001122334455bbcc2233445566778899001122334455",
                    "content": "Hi Alice!",
                    "realMessage": "Hi Alice!",
                    "createdAt": 1700000020000_i64,
                    "isMeSend": false,
                    "isRead": true,
                    "sent": 1
                },
                {
                    "id": 1002,
                    "msgid": "msg-003",
                    "identityId": 1,
                    "roomId": 100,
                    "from": "aabb1122334455667788990011223344aabb1122334455667788990011223344",
                    "realMessage": "不容易啊",
                    "createdAt": 1700000030000_i64,
                    "isMeSend": true,
                    "isRead": true,
                    "sent": 1
                }
            ]))
            .unwrap(),
        );

        // Relay
        collections.insert(
            "Relay".to_string(),
            serde_json::to_string(&serde_json::json!([
                { "id": 1, "url": "wss://relay.keychat.io" },
                { "id": 2, "url": "wss://relay.damus.io" }
            ]))
            .unwrap(),
        );

        serde_json::to_string(&collections).unwrap()
    }

    #[test]
    fn test_full_v1_migration() {
        let tmp = TempDir::new().unwrap();
        let tmp_path = tmp.path();

        // Create mock v1 signal DB
        let signal_db_path = tmp_path.join("signal_protocol.db");
        create_mock_signal_db(signal_db_path.to_str().unwrap());

        // Create new app.db
        let app_db_path = tmp_path.join("app.db");
        let protocol_db_path = tmp_path.join("protocol.db");
        let db_key = "test-key-123";

        // Open app storage (creates tables)
        let app_storage =
            AppStorage::open(app_db_path.to_str().unwrap(), db_key).unwrap();

        // We also need protocol.db to exist with tables
        // Use libkeychat's SecureStorage to create it
        let _protocol_storage = libkeychat::storage::SecureStorage::open(
            protocol_db_path.to_str().unwrap(),
            db_key,
        )
        .unwrap();

        // Create mock Isar JSON
        let isar_json = create_mock_isar_json();

        // Run migration
        let report = migrate_from_v1(
            &isar_json,
            signal_db_path.to_str().unwrap(),
            &app_storage,
            protocol_db_path.to_str().unwrap(),
            db_key,
        )
        .expect("migration should succeed");

        // ─── Verify Results ─────────────────────────────

        // 1. Identity
        assert_eq!(report.identities, 1, "should migrate 1 identity");
        let identities = app_storage.get_app_identities().unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "Alice");
        assert_eq!(identities[0].npub, "npub1test123456789abcdef");
        assert!(identities[0].is_default);

        // 2. Contact
        assert_eq!(report.contacts, 1, "should migrate 1 contact");
        let contacts = app_storage
            .get_app_contacts("aabb1122334455667788990011223344aabb1122334455667788990011223344")
            .unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].npubkey, "npub1contact123");

        // 3. Room
        assert_eq!(report.rooms, 1, "should migrate 1 room");
        let rooms = app_storage
            .get_app_rooms("aabb1122334455667788990011223344aabb1122334455667788990011223344")
            .unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0].status, 3); // enabled
        assert_eq!(rooms[0].name.as_deref(), Some("Bob"));

        // 4. Messages
        assert_eq!(report.messages, 3, "should migrate 3 messages");
        let room_id = &rooms[0].id;
        let messages = app_storage.get_app_messages(room_id, 10, 0).unwrap();
        assert_eq!(messages.len(), 3);
        // Check last message is "不容易啊"
        assert!(messages.iter().any(|m| m.content == "不容易啊"));
        // Check first message
        assert!(messages.iter().any(|m| m.content == "Hello Bob"));

        // 5. Room should have last_message updated
        let updated_rooms = app_storage
            .get_app_rooms("aabb1122334455667788990011223344aabb1122334455667788990011223344")
            .unwrap();
        assert!(updated_rooms[0].last_message_content.is_some());
        assert!(updated_rooms[0].last_message_at.is_some());

        // 6. Signal sessions
        assert_eq!(
            report.signal_sessions, 1,
            "should migrate 1 signal session"
        );

        // Verify signal data in protocol.db
        let protocol_conn = Connection::open(protocol_db_path.to_str().unwrap()).unwrap();
        protocol_conn
            .execute_batch(&format!("PRAGMA key = '{db_key}';"))
            .unwrap();

        let session_count: i64 = protocol_conn
            .query_row("SELECT COUNT(*) FROM signal_sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(session_count, 1);

        let prekey_count: i64 = protocol_conn
            .query_row("SELECT COUNT(*) FROM pre_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(prekey_count, 1);

        let signed_count: i64 = protocol_conn
            .query_row("SELECT COUNT(*) FROM signed_pre_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(signed_count, 1);

        let identity_count: i64 = protocol_conn
            .query_row("SELECT COUNT(*) FROM identity_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(identity_count, 1);

        // 7. Relays
        assert_eq!(report.relays, 2, "should migrate 2 relays");
        let relay_count: i64 = protocol_conn
            .query_row("SELECT COUNT(*) FROM relays", [], |r| r.get(0))
            .unwrap();
        assert_eq!(relay_count, 2);

        println!("✓ All migration tests passed!");
    }

    #[test]
    fn test_migration_empty_data() {
        let tmp = TempDir::new().unwrap();
        let app_db_path = tmp.path().join("app.db");
        let protocol_db_path = tmp.path().join("protocol.db");
        let db_key = "test-key-empty";

        let app_storage =
            AppStorage::open(app_db_path.to_str().unwrap(), db_key).unwrap();
        let _protocol_storage = libkeychat::storage::SecureStorage::open(
            protocol_db_path.to_str().unwrap(),
            db_key,
        )
        .unwrap();

        let empty_json = "{}";
        let report = migrate_from_v1(
            empty_json,
            "",
            &app_storage,
            protocol_db_path.to_str().unwrap(),
            db_key,
        )
        .expect("empty migration should succeed");

        assert_eq!(report.identities, 0);
        assert_eq!(report.contacts, 0);
        assert_eq!(report.rooms, 0);
        assert_eq!(report.messages, 0);
        assert_eq!(report.signal_sessions, 0);
        assert_eq!(report.relays, 0);

        println!("✓ Empty migration test passed!");
    }

    #[test]
    fn test_migration_malformed_json() {
        let tmp = TempDir::new().unwrap();
        let app_db_path = tmp.path().join("app.db");
        let protocol_db_path = tmp.path().join("protocol.db");
        let db_key = "test-key-bad";

        let app_storage =
            AppStorage::open(app_db_path.to_str().unwrap(), db_key).unwrap();
        let _protocol_storage = libkeychat::storage::SecureStorage::open(
            protocol_db_path.to_str().unwrap(),
            db_key,
        )
        .unwrap();

        // Malformed outer JSON should fail
        let bad_json = "not json at all";
        let result = migrate_from_v1(
            bad_json,
            "",
            &app_storage,
            protocol_db_path.to_str().unwrap(),
            db_key,
        );
        assert!(result.is_err());

        // Malformed inner JSON should be gracefully handled (empty migration)
        let bad_inner = r#"{"Identity": "not a json array"}"#;
        let report = migrate_from_v1(
            bad_inner,
            "",
            &app_storage,
            protocol_db_path.to_str().unwrap(),
            db_key,
        )
        .expect("bad inner JSON should not crash");
        assert_eq!(report.identities, 0);

        println!("✓ Malformed JSON test passed!");
    }
}
