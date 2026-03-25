//! Integration tests for libkeychat Phase 1: Identity & Transport.
//!
//! These tests verify the public API works correctly end-to-end.

use libkeychat::{create_gift_wrap, unwrap_gift_wrap, EphemeralKeypair, Identity};

#[test]
fn identity_generate_and_reimport() {
    let gen = Identity::generate().unwrap();
    let id = gen.identity;
    let mnemonic = gen.mnemonic;

    // Re-import from mnemonic (as retrieved from secure storage)
    let id2 = Identity::from_mnemonic_str(&mnemonic).unwrap();
    assert_eq!(id.pubkey_hex(), id2.pubkey_hex());
    assert_eq!(id.secret_hex(), id2.secret_hex());
    assert_eq!(id.npub().unwrap(), id2.npub().unwrap());
    assert_eq!(id.nsec().unwrap(), id2.nsec().unwrap());
}

#[test]
fn identity_24_word_mnemonic() {
    let gen = Identity::generate_with_word_count(24).unwrap();
    let words: Vec<&str> = gen.mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);

    // Round-trip
    let id2 = Identity::from_mnemonic_str(&gen.mnemonic).unwrap();
    assert_eq!(gen.identity.pubkey_hex(), id2.pubkey_hex());
}

#[test]
fn identity_known_mnemonic_is_deterministic() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let id1 = Identity::from_mnemonic_str(phrase).unwrap();
    let id2 = Identity::from_mnemonic_str(phrase).unwrap();
    assert_eq!(id1.pubkey_hex(), id2.pubkey_hex());
    assert_eq!(id1.secret_hex(), id2.secret_hex());
    // Pubkey should be valid hex, 64 chars, lowercase
    assert_eq!(id1.pubkey_hex().len(), 64);
    assert_eq!(id1.pubkey_hex(), id1.pubkey_hex().to_lowercase());
}

#[test]
fn ephemeral_keypairs_are_unique() {
    let ek1 = EphemeralKeypair::generate();
    let ek2 = EphemeralKeypair::generate();
    let ek3 = EphemeralKeypair::generate();
    assert_ne!(ek1.pubkey_hex(), ek2.pubkey_hex());
    assert_ne!(ek2.pubkey_hex(), ek3.pubkey_hex());
    assert_ne!(ek1.pubkey_hex(), ek3.pubkey_hex());
}

#[test]
fn nip44_encrypt_decrypt_roundtrip() {
    let sender = Identity::generate().unwrap().identity;
    let receiver = Identity::generate().unwrap().identity;

    let plaintext = "Keychat Protocol v2 test message 🔐";
    let ciphertext =
        libkeychat::nip44::encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();

    let decrypted =
        libkeychat::nip44::decrypt(receiver.secret_key(), &sender.public_key(), &ciphertext)
            .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn nip44_cross_direction_symmetry() {
    // Either side can encrypt/decrypt with the correct key pair
    let alice = Identity::generate().unwrap().identity;
    let bob = Identity::generate().unwrap().identity;

    // Alice encrypts to Bob
    let ct1 = libkeychat::nip44::encrypt(alice.secret_key(), &bob.public_key(), "hello from alice")
        .unwrap();

    // Bob encrypts to Alice
    let ct2 = libkeychat::nip44::encrypt(bob.secret_key(), &alice.public_key(), "hello from bob")
        .unwrap();

    // Bob decrypts Alice's message
    let d1 = libkeychat::nip44::decrypt(bob.secret_key(), &alice.public_key(), &ct1).unwrap();
    assert_eq!(d1, "hello from alice");

    // Alice decrypts Bob's message
    let d2 = libkeychat::nip44::decrypt(alice.secret_key(), &bob.public_key(), &ct2).unwrap();
    assert_eq!(d2, "hello from bob");
}

#[tokio::test]
async fn gift_wrap_full_roundtrip() {
    let alice = Identity::generate().unwrap().identity;
    let bob = Identity::generate().unwrap().identity;

    let content = r#"{"v":2,"id":"test-uuid-123","kind":"friendRequest","friendRequest":{"name":"Alice","nostrIdentityKey":"abc123"}}"#;

    let gift_wrap = create_gift_wrap(alice.keys(), &bob.public_key(), content)
        .await
        .unwrap();

    // Verify the outer event
    assert_eq!(gift_wrap.kind, nostr::Kind::GiftWrap);
    // Pubkey should be ephemeral (NOT Alice's)
    assert_ne!(gift_wrap.pubkey, alice.public_key());

    // Unwrap as Bob
    let unwrapped = unwrap_gift_wrap(bob.keys(), &gift_wrap).unwrap();
    assert_eq!(unwrapped.sender_pubkey, alice.public_key());
    assert_eq!(unwrapped.content, content);
    assert_eq!(unwrapped.rumor_kind, nostr::Kind::from(14));
}

#[tokio::test]
async fn gift_wrap_wrong_receiver_fails() {
    let alice = Identity::generate().unwrap().identity;
    let bob = Identity::generate().unwrap().identity;
    let eve = Identity::generate().unwrap().identity;

    let gift_wrap = create_gift_wrap(alice.keys(), &bob.public_key(), "secret for bob only")
        .await
        .unwrap();

    // Eve cannot unwrap
    let result = unwrap_gift_wrap(eve.keys(), &gift_wrap);
    assert!(result.is_err());
}

#[tokio::test]
async fn gift_wrap_uses_real_timestamps() {
    let alice = Identity::generate().unwrap().identity;
    let bob = Identity::generate().unwrap().identity;

    let before = nostr::Timestamp::now();
    let gift_wrap = create_gift_wrap(alice.keys(), &bob.public_key(), "timestamp test")
        .await
        .unwrap();
    let after = nostr::Timestamp::now();

    // Real timestamp should be between before and after
    assert!(gift_wrap.created_at >= before);
    assert!(gift_wrap.created_at <= after);
}

// ─── Phase 6A: Signal Group integration tests ──────────────────────────────

#[test]
fn group_create_and_invite_roundtrip() {
    use libkeychat::{create_signal_group, receive_group_invite, RoomProfile};

    let group = create_signal_group(
        "Integration Test Group",
        "alice_sig",
        "alice_npub",
        "Alice",
        vec![
            ("bob_sig".into(), "bob_npub".into(), "Bob".into()),
            (
                "charlie_sig".into(),
                "charlie_npub".into(),
                "Charlie".into(),
            ),
        ],
    );

    assert_eq!(group.name, "Integration Test Group");
    assert_eq!(group.members.len(), 3);
    assert!(group.is_admin("alice_sig"));

    // Convert to RoomProfile and back
    let profile = group.to_room_profile();
    let json = serde_json::to_string(&profile).unwrap();
    let parsed: RoomProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "Integration Test Group");
    assert_eq!(parsed.members.len(), 3);

    // Build invite message and receive it
    let mut invite_msg = libkeychat::KCMessage::empty();
    invite_msg.kind = libkeychat::KCMessageKind::SignalGroupInvite;
    invite_msg.group_id = Some(group.group_id.clone());
    invite_msg.extra.insert(
        "signalGroupInvite".to_string(),
        serde_json::to_value(&profile).unwrap(),
    );

    let dave_group = receive_group_invite(&invite_msg, "dave_sig").unwrap();
    assert_eq!(dave_group.group_id, group.group_id);
    assert_eq!(dave_group.name, "Integration Test Group");
    assert_eq!(dave_group.my_signal_id, "dave_sig");
}

#[test]
fn group_manager_lifecycle() {
    use libkeychat::{create_signal_group, GroupManager};

    let mut mgr = GroupManager::new();

    let g1 = create_signal_group("G1", "a", "an", "A", vec![]);
    let g2 = create_signal_group("G2", "b", "bn", "B", vec![]);
    let g1_id = g1.group_id.clone();
    let g2_id = g2.group_id.clone();

    mgr.add_group(g1);
    mgr.add_group(g2);
    assert_eq!(mgr.group_count(), 2);

    assert!(mgr.get_group(&g1_id).is_some());
    assert!(mgr.get_group(&g2_id).is_some());

    mgr.remove_group(&g1_id);
    assert_eq!(mgr.group_count(), 1);
    assert!(mgr.get_group(&g1_id).is_none());
}

#[tokio::test]
async fn group_send_receive_e2e() {
    use libkeychat::{
        create_signal_group, receive_group_message, send_group_message, AddressManager,
        GroupManager, KCMessage, KCMessageKind, SignalParticipant,
    };
    use libsignal_protocol::{DeviceId, ProtocolAddress};

    // Set up Alice and Bob with established Signal sessions
    let mut alice = SignalParticipant::new("alice", 1).unwrap();
    let mut bob = SignalParticipant::new("bob", 1).unwrap();

    let alice_id = alice.identity_public_key_hex();
    let bob_id = bob.identity_public_key_hex();

    let bob_addr = ProtocolAddress::new(bob_id.clone(), DeviceId::new(1).unwrap());
    let alice_addr = ProtocolAddress::new(alice_id.clone(), DeviceId::new(1).unwrap());

    // Establish bidirectional session
    let bob_bundle = bob.prekey_bundle().unwrap();
    alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();
    let ct = alice.encrypt_bytes(&bob_addr, b"init").unwrap();
    bob.decrypt_bytes(&alice_addr, &ct).unwrap();
    let ct2 = bob.encrypt_bytes(&alice_addr, b"ack").unwrap();
    alice.decrypt_bytes(&bob_addr, &ct2).unwrap();

    // Set up address manager
    let mut addr_mgr = AddressManager::new();
    let inbox = libkeychat::EphemeralKeypair::generate();
    addr_mgr.add_peer(&bob_id, Some(inbox.pubkey_hex()), None);

    // Create group
    let group = create_signal_group(
        "E2E Group",
        &alice_id,
        "alice_npub",
        "Alice",
        vec![(bob_id.clone(), "bob_npub".into(), "Bob".into())],
    );

    // Alice sends group message
    let mut msg = KCMessage::text("E2E group message!");
    msg.group_id = Some(group.group_id.clone());

    let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
        .await
        .unwrap();
    assert_eq!(results.len(), 1); // Only Bob

    // Bob receives
    let mut bob_groups = GroupManager::new();
    let mut bob_group = group.clone();
    bob_group.my_signal_id = bob_id.clone();
    bob_groups.add_group(bob_group);

    let (received, metadata) =
        receive_group_message(&mut bob, &alice_addr, &results[0].1, &bob_groups).unwrap();

    assert_eq!(received.kind, KCMessageKind::Text);
    assert_eq!(received.text.unwrap().content, "E2E group message!");
    assert_eq!(metadata.group_id, group.group_id);
    assert_eq!(metadata.sender_signal_id, alice_id);
    assert_eq!(metadata.sender_name, "Alice");
}

#[tokio::test]
async fn transport_deduplication() {
    use libkeychat::Transport;

    let keys = nostr::Keys::generate();
    let transport = Transport::new(&keys).await.unwrap();

    let event = nostr::EventBuilder::text_note("dedup test")
        .sign(&keys)
        .await
        .unwrap();

    // First pass: new event
    let first = transport.deduplicate(event.clone()).await;
    assert!(first.is_some());

    // Second pass: duplicate
    let second = transport.deduplicate(event.clone()).await;
    assert!(second.is_none());

    // Confirm tracking
    assert!(transport.is_processed(&event.id).await);
}
