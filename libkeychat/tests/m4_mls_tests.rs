use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use libkeychat::identity::generate_random_nostr_keypair;
use libkeychat::mls::transport::{fetch_key_package, publish_key_package};
use libkeychat::mls::{
    add_member, create_key_package, create_mls_group, decrypt_group_message, encrypt_group_message,
    get_group_listen_key, init_mls, join_group_from_welcome, leave_group, list_groups,
    process_commit, process_mls_message, remove_member, CommitTypeResult, ProcessedMlsMessage,
};
use libkeychat::transport::relay::RelayConnection;
use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls::prelude::{KeyPackageIn, ProtocolVersion};
use openmls_traits::OpenMlsProvider;

fn temp_db_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("libkeychat-m4-{label}-{nonce}"));
    fs::create_dir_all(&dir).expect("mkdir");
    dir.join("mls.sqlite")
}

#[test]
fn init_mls_creates_user_identity() {
    let db = temp_db_path("init");
    init_mls(db.to_str().expect("db path"), "alice").expect("init");
    let key_package = create_key_package("alice").expect("key package");
    assert!(!key_package.key_package.is_empty());
}

#[test]
fn create_key_package_returns_valid_hex_encoded_tls_bytes() {
    let db = temp_db_path("kp");
    init_mls(db.to_str().expect("db path"), "alice-kp").expect("init");
    let key_package = create_key_package("alice-kp").expect("key package");
    let bytes = hex::decode(&key_package.key_package).expect("hex");
    assert!(!bytes.is_empty());
    assert_eq!(key_package.mls_protocol_version, "1.0");
}

#[test]
fn parse_key_package_roundtrip() {
    let db = temp_db_path("parse-kp");
    init_mls(db.to_str().expect("db path"), "alice-parse").expect("init");
    let key_package = create_key_package("alice-parse").expect("key package");
    let bytes = hex::decode(&key_package.key_package).expect("hex");
    let key_package_in =
        KeyPackageIn::tls_deserialize(&mut bytes.as_slice()).expect("tls deserialize");
    let provider = kc::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto::default();
    let validated = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect("validate");
    assert_eq!(
        String::from_utf8(
            validated
                .leaf_node()
                .credential()
                .serialized_content()
                .to_vec()
        )
        .expect("credential"),
        "alice-parse"
    );
}

#[test]
fn create_mls_group_succeeds_and_returns_group_id() {
    let db = temp_db_path("create-group");
    init_mls(db.to_str().expect("db path"), "alice-group").expect("init");
    let group_id = create_mls_group("alice-group", "Study Group").expect("group");
    assert_eq!(group_id.len(), 64);
    assert_eq!(list_groups("alice-group").expect("groups"), vec![group_id]);
}

#[test]
fn add_member_produces_welcome_bytes() {
    let alice_db = temp_db_path("add-alice");
    let bob_db = temp_db_path("add-bob");
    init_mls(alice_db.to_str().expect("db path"), "alice-add").expect("init alice");
    init_mls(bob_db.to_str().expect("db path"), "bob-add").expect("init bob");

    let bob_key_package = create_key_package("bob-add").expect("bob key package");
    let group_id = create_mls_group("alice-add", "Team").expect("group");
    let result = add_member("alice-add", &group_id, &bob_key_package.key_package).expect("add");
    assert!(!result.commit_message.is_empty());
    assert!(!result.welcome.is_empty());
}

#[test]
fn join_group_from_welcome_joins_second_identity() {
    let alice_db = temp_db_path("join-alice");
    let bob_db = temp_db_path("join-bob");
    init_mls(alice_db.to_str().expect("db path"), "alice-join").expect("init alice");
    init_mls(bob_db.to_str().expect("db path"), "bob-join").expect("init bob");

    let bob_key_package = create_key_package("bob-join").expect("bob key package");
    let group_id = create_mls_group("alice-join", "Team").expect("group");
    let result = add_member("alice-join", &group_id, &bob_key_package.key_package).expect("add");
    let joined_group_id =
        join_group_from_welcome("bob-join", &result.welcome).expect("join from welcome");
    assert_eq!(joined_group_id, group_id);
    assert_eq!(list_groups("bob-join").expect("groups"), vec![group_id]);
}

#[test]
fn encrypt_decrypt_roundtrip_within_group() {
    let (group_id, _commit, _welcome) = setup_two_person_group("roundtrip");
    let ciphertext =
        encrypt_group_message("alice-roundtrip", &group_id, "Hello Bob!").expect("encrypt");
    let decrypted =
        decrypt_group_message("bob-roundtrip", &group_id, &ciphertext).expect("decrypt");
    assert_eq!(decrypted.plaintext, "Hello Bob!");
    assert_eq!(decrypted.sender_nostr_id, "alice-roundtrip");
}

#[test]
fn process_commit_after_add_member() {
    let alice_db = temp_db_path("commit-alice");
    let bob_db = temp_db_path("commit-bob");
    let charlie_db = temp_db_path("commit-charlie");
    init_mls(alice_db.to_str().expect("db path"), "alice-commit").expect("init alice");
    init_mls(bob_db.to_str().expect("db path"), "bob-commit").expect("init bob");
    init_mls(charlie_db.to_str().expect("db path"), "charlie-commit").expect("init charlie");

    let bob_key_package = create_key_package("bob-commit").expect("bob key package");
    let charlie_key_package = create_key_package("charlie-commit").expect("charlie key package");
    let group_id = create_mls_group("alice-commit", "Team").expect("group");
    let bob_add =
        add_member("alice-commit", &group_id, &bob_key_package.key_package).expect("add bob");
    join_group_from_welcome("bob-commit", &bob_add.welcome).expect("join bob");

    let charlie_add = add_member("alice-commit", &group_id, &charlie_key_package.key_package)
        .expect("add charlie");
    let commit =
        process_commit("bob-commit", &group_id, &charlie_add.commit_message).expect("commit");
    assert_eq!(commit.sender, "alice-commit");
    assert_eq!(commit.commit_type, CommitTypeResult::Add);
    assert_eq!(
        commit.operated_members.expect("members"),
        vec!["charlie-commit".to_owned()]
    );
}

#[test]
fn get_group_listen_key_is_consistent() {
    let (group_id, _commit, _welcome) = setup_two_person_group("listen");
    let first = get_group_listen_key("alice-listen", &group_id).expect("listen key");
    let second = get_group_listen_key("alice-listen", &group_id).expect("listen key");
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
}

#[test]
fn list_groups_returns_correct_groups_after_create_and_join() {
    let alice_db = temp_db_path("groups-alice");
    let bob_db = temp_db_path("groups-bob");
    init_mls(alice_db.to_str().expect("db path"), "alice-groups").expect("init alice");
    init_mls(bob_db.to_str().expect("db path"), "bob-groups").expect("init bob");

    let bob_key_package = create_key_package("bob-groups").expect("bob key package");
    let group_one = create_mls_group("alice-groups", "One").expect("group one");
    let group_two = create_mls_group("alice-groups", "Two").expect("group two");
    let add = add_member("alice-groups", &group_one, &bob_key_package.key_package).expect("add");
    join_group_from_welcome("bob-groups", &add.welcome).expect("join");

    let alice_groups = list_groups("alice-groups").expect("alice groups");
    assert_eq!(alice_groups.len(), 2);
    assert!(alice_groups.contains(&group_one));
    assert!(alice_groups.contains(&group_two));
    assert_eq!(
        list_groups("bob-groups").expect("bob groups"),
        vec![group_one]
    );
}

#[test]
fn full_two_person_mls_group_flow() {
    let (group_id, _commit, _welcome) = setup_two_person_group("integration");

    let alice_ciphertext =
        encrypt_group_message("alice-integration", &group_id, "Hello Bob!").expect("encrypt");
    let bob_plaintext =
        decrypt_group_message("bob-integration", &group_id, &alice_ciphertext).expect("decrypt");
    assert_eq!(bob_plaintext.plaintext, "Hello Bob!");
    assert_eq!(bob_plaintext.sender_nostr_id, "alice-integration");

    let bob_ciphertext =
        encrypt_group_message("bob-integration", &group_id, "Hello Alice!").expect("encrypt");
    let alice_plaintext =
        decrypt_group_message("alice-integration", &group_id, &bob_ciphertext).expect("decrypt");
    assert_eq!(alice_plaintext.plaintext, "Hello Alice!");
    assert_eq!(alice_plaintext.sender_nostr_id, "bob-integration");
}

#[test]
fn remove_member_produces_commit() {
    let alice_db = temp_db_path("remove-alice");
    let bob_db = temp_db_path("remove-bob");
    let charlie_db = temp_db_path("remove-charlie");
    init_mls(alice_db.to_str().expect("db path"), "alice-remove").expect("init alice");
    init_mls(bob_db.to_str().expect("db path"), "bob-remove").expect("init bob");
    init_mls(charlie_db.to_str().expect("db path"), "charlie-remove").expect("init charlie");

    let bob_key_package = create_key_package("bob-remove").expect("bob key package");
    let charlie_key_package = create_key_package("charlie-remove").expect("charlie key package");
    let group_id = create_mls_group("alice-remove", "Team").expect("group");

    let bob_add =
        add_member("alice-remove", &group_id, &bob_key_package.key_package).expect("add bob");
    join_group_from_welcome("bob-remove", &bob_add.welcome).expect("join bob");

    let charlie_add = add_member("alice-remove", &group_id, &charlie_key_package.key_package)
        .expect("add charlie");
    join_group_from_welcome("charlie-remove", &charlie_add.welcome).expect("join charlie");
    process_commit("bob-remove", &group_id, &charlie_add.commit_message).expect("process add");

    let remove = remove_member("alice-remove", &group_id, "charlie-remove").expect("remove");
    assert!(!remove.commit_message.is_empty());

    let commit =
        process_commit("bob-remove", &group_id, &remove.commit_message).expect("process remove");
    assert_eq!(commit.sender, "alice-remove");
    assert_eq!(commit.commit_type, CommitTypeResult::Remove);
}

#[test]
fn leave_group_removes_from_local_state() {
    let (group_id, _commit, _welcome) = setup_two_person_group("leave");
    let leave_commit = leave_group("bob-leave", &group_id).expect("leave");
    assert!(!leave_commit.is_empty());

    let groups = list_groups("bob-leave").expect("groups");
    assert!(!groups.contains(&group_id));
}

#[tokio::test]
#[ignore = "requires a running relay (example: ws://127.0.0.1:10547)"]
async fn publish_and_fetch_key_package_roundtrip() {
    let relay_url = std::env::var("LIBKEYCHAT_TEST_RELAY")
        .unwrap_or_else(|_| "ws://127.0.0.1:10547".to_owned());
    let relay = RelayConnection::connect(relay_url)
        .await
        .expect("relay connect");
    let keypair = generate_random_nostr_keypair();
    let key_package_hex = "deadbeefcafebabe";

    publish_key_package(&relay, &keypair, key_package_hex)
        .await
        .expect("publish");
    let fetched = fetch_key_package(&relay, &keypair.public_key_hex())
        .await
        .expect("fetch");
    assert_eq!(fetched, key_package_hex);

    relay.disconnect().await.expect("disconnect");
}

#[test]
fn process_mls_message_unified_api() {
    // Setup: Alice + Bob in group, then Alice adds Charlie
    let alice_db = temp_db_path("unified-alice");
    let bob_db = temp_db_path("unified-bob");
    let charlie_db = temp_db_path("unified-charlie");
    init_mls(alice_db.to_str().expect("path"), "alice-unified").expect("init");
    init_mls(bob_db.to_str().expect("path"), "bob-unified").expect("init");
    init_mls(charlie_db.to_str().expect("path"), "charlie-unified").expect("init");

    let bob_kp = create_key_package("bob-unified").expect("bob kp");
    let charlie_kp = create_key_package("charlie-unified").expect("charlie kp");
    let group_id = create_mls_group("alice-unified", "Unified").expect("group");
    let bob_add = add_member("alice-unified", &group_id, &bob_kp.key_package).expect("add bob");
    join_group_from_welcome("bob-unified", &bob_add.welcome).expect("join bob");

    // Alice adds Charlie — Bob processes this commit via unified API
    let charlie_add =
        add_member("alice-unified", &group_id, &charlie_kp.key_package).expect("add charlie");
    let result = process_mls_message("bob-unified", &group_id, &charlie_add.commit_message)
        .expect("process commit");
    match &result {
        ProcessedMlsMessage::Commit {
            sender,
            commit_type,
            ..
        } => {
            assert_eq!(sender, "alice-unified");
            assert_eq!(*commit_type, CommitTypeResult::Add);
        }
        _ => panic!("expected Commit, got {:?}", result),
    }

    // Alice sends application message — Bob processes via unified API
    let ciphertext =
        encrypt_group_message("alice-unified", &group_id, "hello unified").expect("encrypt");
    let result = process_mls_message("bob-unified", &group_id, &ciphertext).expect("process msg");
    match &result {
        ProcessedMlsMessage::Application {
            plaintext,
            sender_nostr_id,
            ..
        } => {
            assert_eq!(plaintext, "hello unified");
            assert_eq!(sender_nostr_id, "alice-unified");
        }
        _ => panic!("expected Application, got {:?}", result),
    }
}

fn setup_two_person_group(label: &str) -> (String, Vec<u8>, Vec<u8>) {
    let alice_id = format!("alice-{label}");
    let bob_id = format!("bob-{label}");
    let alice_db = temp_db_path(&format!("{label}-alice"));
    let bob_db = temp_db_path(&format!("{label}-bob"));
    init_mls(alice_db.to_str().expect("db path"), &alice_id).expect("init alice");
    init_mls(bob_db.to_str().expect("db path"), &bob_id).expect("init bob");

    let bob_key_package = create_key_package(&bob_id).expect("bob key package");
    let group_id = create_mls_group(&alice_id, "Group").expect("group");
    let add = add_member(&alice_id, &group_id, &bob_key_package.key_package).expect("add");
    let joined_group_id = join_group_from_welcome(&bob_id, &add.welcome).expect("join");
    assert_eq!(joined_group_id, group_id);

    (group_id, add.commit_message, add.welcome)
}
