//! Cross-implementation interoperability tests.
//!
//! impl_a = Claude's implementation (libkeychat)
//! impl_b = Codex's implementation (libkeychat-b)

use nostr::prelude::*;

// ============================================================
// Test 1: NIP-44 cross-implementation encrypt/decrypt
// ============================================================

#[test]
fn nip44_a_encrypts_b_decrypts() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let plaintext = "Hello from impl A to impl B!";

    // impl_a encrypts (takes &SecretKey, &PublicKey)
    let ciphertext = impl_a::nip44::encrypt(
        sender.secret_key(),
        &receiver.public_key(),
        plaintext,
    )
    .expect("impl_a encrypt failed");

    // impl_b decrypts (takes &str hex)
    let decrypted = impl_b::nip44::decrypt(
        &receiver.secret_key().to_secret_hex(),
        &sender.public_key().to_hex(),
        &ciphertext,
    )
    .expect("impl_b decrypt failed");

    assert_eq!(decrypted, plaintext);
    eprintln!("✅ NIP-44: impl_a encrypts → impl_b decrypts");
}

#[test]
fn nip44_b_encrypts_a_decrypts() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let plaintext = "Hello from impl B to impl A!";

    // impl_b encrypts (takes &str hex)
    let ciphertext = impl_b::nip44::encrypt(
        &sender.secret_key().to_secret_hex(),
        &receiver.public_key().to_hex(),
        plaintext,
    )
    .expect("impl_b encrypt failed");

    // impl_a decrypts (takes &SecretKey, &PublicKey)
    let decrypted = impl_a::nip44::decrypt(
        receiver.secret_key(),
        &sender.public_key(),
        &ciphertext,
    )
    .expect("impl_a decrypt failed");

    assert_eq!(decrypted, plaintext);
    eprintln!("✅ NIP-44: impl_b encrypts → impl_a decrypts");
}

#[test]
fn nip44_unicode_cross_impl() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let plaintext = "你好世界 🌍 مرحبا Привет";

    let ct = impl_a::nip44::encrypt(sender.secret_key(), &receiver.public_key(), plaintext).unwrap();
    let dec = impl_b::nip44::decrypt(&receiver.secret_key().to_secret_hex(), &sender.public_key().to_hex(), &ct).unwrap();
    assert_eq!(dec, plaintext);
    eprintln!("✅ NIP-44: unicode cross-impl OK");
}

// ============================================================
// Test 2: NIP-17 Gift Wrap cross-implementation
// ============================================================

#[tokio::test]
async fn giftwrap_a_wraps_b_unwraps() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let content = r#"{"v":2,"kind":"text","text":{"content":"cross-impl test"}}"#;

    // impl_a wraps
    let event = impl_a::create_gift_wrap(&sender, &receiver.public_key(), content)
        .await
        .expect("impl_a wrap failed");

    assert_eq!(event.kind, Kind::GiftWrap);

    // impl_b unwraps (different struct: UnwrappedGift with .sender and .rumor)
    let unwrapped = impl_b::giftwrap::unwrap_gift_wrap(&receiver, &event)
        .expect("impl_b unwrap failed");

    assert_eq!(unwrapped.sender, sender.public_key());
    assert_eq!(unwrapped.rumor.content, content);
    eprintln!("✅ Gift Wrap: impl_a wraps → impl_b unwraps");
}

#[tokio::test]
async fn giftwrap_b_wraps_a_unwraps() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let content = r#"{"v":2,"kind":"friendRequest","id":"test-123"}"#;

    // impl_b wraps
    let event = impl_b::giftwrap::create_gift_wrap(&sender, &receiver.public_key(), content)
        .await
        .expect("impl_b wrap failed");

    assert_eq!(event.kind, Kind::GiftWrap);

    // impl_a unwraps (UnwrappedMessage with .sender_pubkey and .content)
    let unwrapped = impl_a::unwrap_gift_wrap(&receiver, &event)
        .expect("impl_a unwrap failed");

    assert_eq!(unwrapped.sender_pubkey, sender.public_key());
    assert_eq!(unwrapped.content, content);
    eprintln!("✅ Gift Wrap: impl_b wraps → impl_a unwraps");
}

// ============================================================
// Test 3: KCMessage v2 cross-implementation serialize/deserialize
// ============================================================

#[test]
fn kcmessage_text_a_to_b() {
    let msg_a = impl_a::message::KCMessage::text("Hello cross-impl!");
    let json = serde_json::to_string(&msg_a).expect("impl_a serialize failed");

    let msg_b: impl_b::message::KCMessage =
        serde_json::from_str(&json).expect("impl_b deserialize failed");

    assert_eq!(msg_b.v, 2);
    assert!(json.contains("Hello cross-impl!"));
    eprintln!("✅ KCMessage text: impl_a → impl_b");
}

#[test]
fn kcmessage_text_b_to_a() {
    let msg_b = impl_b::message::KCMessage::text("Hello from B!");
    let json = serde_json::to_string(&msg_b).expect("impl_b serialize failed");

    let msg_a: impl_a::message::KCMessage =
        serde_json::from_str(&json).expect("impl_a deserialize failed");

    assert_eq!(msg_a.v, 2);
    assert!(json.contains("Hello from B!"));
    eprintln!("✅ KCMessage text: impl_b → impl_a");
}

// ============================================================
// Test 4: Signal session PQXDH cross-implementation
// ============================================================

#[tokio::test]
async fn signal_pqxdh_a_initiates_b_responds() {
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    // Create participants
    let mut alice = ParticipantA::new("alice", 1).expect("create alice failed");
    let mut bob = ParticipantB::new("bob", 1).expect("create bob failed");

    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(),
        libsignal_protocol::DeviceId::from(1),
    );
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(),
        libsignal_protocol::DeviceId::from(1),
    );

    // Alice (impl_a) processes Bob's (impl_b) prekey bundle
    let bob_bundle = bob.prekey_bundle().expect("bob bundle failed");
    
    // Verify Bob's bundle has Kyber (PQXDH)
    assert!(bob_bundle.has_kyber_pre_key(), "Bob's bundle should have Kyber prekey for PQXDH");
    
    alice
        .process_prekey_bundle(&bob_addr, &bob_bundle)
        .expect("alice process bob's bundle failed");

    // Alice encrypts → Bob decrypts (PrekeyMessage)
    let plaintext = b"Hello Bob from impl A via PQXDH!";
    let ciphertext = alice
        .encrypt(&bob_addr, plaintext)
        .expect("alice encrypt failed");

    assert!(ParticipantA::is_prekey_message(&ciphertext), "First message should be PrekeyMessage");

    let decrypted = bob
        .decrypt(&alice_addr, &ciphertext)
        .expect("bob decrypt prekey failed");

    assert_eq!(decrypted, plaintext);
    eprintln!("✅ Signal PQXDH: impl_a encrypts → impl_b decrypts (PrekeyMessage)");

    // Bob replies → Alice decrypts
    let reply = b"Hi Alice from impl B!";
    let reply_ct = bob
        .encrypt(&alice_addr, reply)
        .expect("bob encrypt failed");

    let decrypted_reply = alice
        .decrypt(&bob_addr, &reply_ct)
        .expect("alice decrypt failed");

    assert_eq!(decrypted_reply, reply);
    eprintln!("✅ Signal PQXDH: impl_b encrypts → impl_a decrypts (normal message)");
}

#[tokio::test]
async fn signal_pqxdh_b_initiates_a_responds() {
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    // This time Bob (impl_b) initiates to Alice (impl_a)
    let mut alice = ParticipantA::new("alice", 1).expect("create alice failed");
    let mut bob = ParticipantB::new("bob", 1).expect("create bob failed");

    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(),
        libsignal_protocol::DeviceId::from(1),
    );
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(),
        libsignal_protocol::DeviceId::from(1),
    );

    // Bob (impl_b) processes Alice's (impl_a) prekey bundle
    let alice_bundle = alice.prekey_bundle().expect("alice bundle failed");
    assert!(alice_bundle.has_kyber_pre_key(), "Alice's bundle should have Kyber prekey");
    
    bob.process_prekey_bundle(&alice_addr, &alice_bundle)
        .expect("bob process alice's bundle failed");

    // Bob encrypts → Alice decrypts
    let plaintext = b"Hello Alice from impl B!";
    let ciphertext = bob.encrypt(&alice_addr, plaintext).expect("bob encrypt failed");
    let decrypted = alice.decrypt(&bob_addr, &ciphertext).expect("alice decrypt failed");
    assert_eq!(decrypted, plaintext);
    eprintln!("✅ Signal PQXDH: impl_b initiates → impl_a responds");

    // Alice replies
    let reply = b"Hi Bob from impl A!";
    let reply_ct = alice.encrypt(&bob_addr, reply).expect("alice encrypt failed");
    let decrypted_reply = bob.decrypt(&alice_addr, &reply_ct).expect("bob decrypt failed");
    assert_eq!(decrypted_reply, reply);
    eprintln!("✅ Signal PQXDH: bidirectional OK (B initiates)");
}

// ============================================================
// Test 5: Multiple rounds of messaging across implementations
// ============================================================

#[tokio::test]
async fn signal_multi_round_cross_impl() {
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let mut alice = ParticipantA::new("alice", 1).unwrap();
    let mut bob = ParticipantB::new("bob", 1).unwrap();

    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));

    let bob_bundle = bob.prekey_bundle().unwrap();
    alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

    // Initial PrekeyMessage
    let ct = alice.encrypt(&bob_addr, b"init").unwrap();
    bob.decrypt(&alice_addr, &ct).unwrap();

    // 10 rounds: alternating directions (triggers DH ratchet)
    for i in 0..10 {
        let msg_ab = format!("A→B round {}", i);
        let ct = alice.encrypt(&bob_addr, msg_ab.as_bytes()).unwrap();
        let dec = bob.decrypt(&alice_addr, &ct).unwrap();
        assert_eq!(dec, msg_ab.as_bytes());

        let msg_ba = format!("B→A round {}", i);
        let ct = bob.encrypt(&alice_addr, msg_ba.as_bytes()).unwrap();
        let dec = alice.decrypt(&bob_addr, &ct).unwrap();
        assert_eq!(dec, msg_ba.as_bytes());
    }
    eprintln!("✅ Signal: 10 bidirectional rounds cross-impl OK");

    // 5 consecutive same-direction (tests chain key advancement)
    for i in 0..5 {
        let msg = format!("A→B consecutive {}", i);
        let ct = alice.encrypt(&bob_addr, msg.as_bytes()).unwrap();
        let dec = bob.decrypt(&alice_addr, &ct).unwrap();
        assert_eq!(dec, msg.as_bytes());
    }
    eprintln!("✅ Signal: 5 consecutive same-direction cross-impl OK");
}

// ============================================================
// Test 6: Phase 4 — Chat transport cross-implementation
// ============================================================

#[tokio::test]
async fn chat_send_a_receive_b() {
    use impl_a::chat as chat_a;
    use impl_b::chat as chat_b;
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let mut alice = ParticipantA::new("alice", 1).unwrap();
    let mut bob = ParticipantB::new("bob", 1).unwrap();

    let bob_bundle = bob.prekey_bundle().unwrap();
    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));

    alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

    // init + ack to complete session
    let ct = alice.encrypt(&bob_addr, b"init").unwrap();
    bob.decrypt(&alice_addr, &ct).unwrap();
    let ct2 = bob.encrypt(&alice_addr, b"ack").unwrap();
    alice.decrypt(&bob_addr, &ct2).unwrap();

    // Alice (impl_a) sends via chat_a
    let recv_keys = Keys::generate();
    let msg_a = impl_a::message::KCMessage::text("Cross-impl chat test!");
    let event = chat_a::send_encrypted_message(
        &mut alice, &bob_addr, &msg_a, &recv_keys.public_key().to_hex(),
    ).await.unwrap();

    assert_eq!(event.kind, Kind::GiftWrap);

    // Bob (impl_b) receives via chat_b
    let (received, metadata) = chat_b::receive_encrypted_message(
        &mut bob, &alice_addr, &event,
    ).unwrap();

    assert_eq!(received.kind, impl_b::message::KCMessageKind::Text);
    assert_eq!(received.text.as_ref().unwrap().content, "Cross-impl chat test!");
    assert!(!metadata.is_prekey_message);
    eprintln!("✅ Phase 4 Chat: impl_a sends → impl_b receives");
}

#[tokio::test]
async fn chat_send_b_receive_a() {
    use impl_a::chat as chat_a;
    use impl_b::chat as chat_b;
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let mut alice = ParticipantA::new("alice", 1).unwrap();
    let mut bob = ParticipantB::new("bob", 1).unwrap();

    let alice_bundle = alice.prekey_bundle().unwrap();
    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));

    bob.process_prekey_bundle(&alice_addr, &alice_bundle).unwrap();

    let ct = bob.encrypt(&alice_addr, b"init").unwrap();
    alice.decrypt(&bob_addr, &ct).unwrap();
    let ct2 = alice.encrypt(&bob_addr, b"ack").unwrap();
    bob.decrypt(&alice_addr, &ct2).unwrap();

    // Bob (impl_b) sends via chat_b
    let recv_keys = Keys::generate();
    let msg_b = impl_b::message::KCMessage::text("Reply from impl B!");
    let event = chat_b::send_encrypted_message(
        &mut bob, &alice_addr, &msg_b, &recv_keys.public_key().to_hex(),
    ).await.unwrap();

    // Alice (impl_a) receives via chat_a
    let (received, metadata) = chat_a::receive_encrypted_message(
        &mut alice, &bob_addr, &event,
    ).unwrap();

    assert_eq!(received.kind, impl_a::message::KCMessageKind::Text);
    assert_eq!(received.text.as_ref().unwrap().content, "Reply from impl B!");
    assert!(!metadata.is_prekey_message);
    eprintln!("✅ Phase 4 Chat: impl_b sends → impl_a receives");
}

#[tokio::test]
async fn chat_bidirectional_multi_round() {
    use impl_a::chat as chat_a;
    use impl_b::chat as chat_b;
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let mut alice = ParticipantA::new("alice", 1).unwrap();
    let mut bob = ParticipantB::new("bob", 1).unwrap();

    let bob_bundle = bob.prekey_bundle().unwrap();
    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));

    alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();
    let ct = alice.encrypt(&bob_addr, b"init").unwrap();
    bob.decrypt(&alice_addr, &ct).unwrap();
    let ct2 = bob.encrypt(&alice_addr, b"ack").unwrap();
    alice.decrypt(&bob_addr, &ct2).unwrap();

    for i in 0..5 {
        // A→B via chat transport
        let recv = Keys::generate();
        let msg = impl_a::message::KCMessage::text(&format!("A→B round {}", i));
        let ev = chat_a::send_encrypted_message(
            &mut alice, &bob_addr, &msg, &recv.public_key().to_hex(),
        ).await.unwrap();
        let (dec, _) = chat_b::receive_encrypted_message(&mut bob, &alice_addr, &ev).unwrap();
        assert_eq!(dec.text.as_ref().unwrap().content, format!("A→B round {}", i));

        // B→A via chat transport
        let recv2 = Keys::generate();
        let msg2 = impl_b::message::KCMessage::text(&format!("B→A round {}", i));
        let ev2 = chat_b::send_encrypted_message(
            &mut bob, &alice_addr, &msg2, &recv2.public_key().to_hex(),
        ).await.unwrap();
        let (dec2, _) = chat_a::receive_encrypted_message(&mut alice, &bob_addr, &ev2).unwrap();
        assert_eq!(dec2.text.as_ref().unwrap().content, format!("B→A round {}", i));
    }
    eprintln!("✅ Phase 4 Chat: 5 bidirectional rounds cross-impl OK");
}

#[test]
fn message_routing_cross_impl() {
    // Route impl_a's serialized message through impl_b's router
    let msg_a = impl_a::message::KCMessage::text("Route test");
    let json = serde_json::to_string(&msg_a).unwrap();
    let action = impl_b::chat::parse_and_route(&json);
    assert_eq!(action, impl_b::chat::MessageAction::DisplayText {
        content: "Route test".into(),
        format: None,
    });

    // Route impl_b's serialized message through impl_a's router
    let msg_b = impl_b::message::KCMessage::text("Route test B");
    let json_b = serde_json::to_string(&msg_b).unwrap();
    let action_b = impl_a::chat::parse_and_route(&json_b);
    assert_eq!(action_b, impl_a::chat::MessageAction::DisplayText {
        content: "Route test B".into(),
        format: None,
    });
    eprintln!("✅ Phase 4: KCMessage routing cross-impl OK");
}

// ============================================================
// Test 8: Phase 5 — Address rotation cross-implementation
// ============================================================

#[test]
fn address_derivation_cross_impl() {
    // Same ratchet key → same derived address in both implementations
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let mut alice = ParticipantA::new("alice", 1).unwrap();
    let mut bob = ParticipantB::new("bob", 1).unwrap();

    let bob_bundle = bob.prekey_bundle().unwrap();
    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));

    alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

    let enc = alice.encrypt(&bob_addr, b"test").unwrap();
    bob.decrypt(&alice_addr, &enc.bytes).unwrap();

    if let Some(ref ratchet_key) = enc.sender_address {
        let addr_a = impl_a::signal_session::derive_nostr_address_from_ratchet(ratchet_key).unwrap();
        let addr_b = impl_b::signal_session::derive_nostr_address_from_ratchet(ratchet_key).unwrap();
        assert_eq!(addr_a, addr_b, "same ratchet key must derive same address in both impls");
        eprintln!("✅ Phase 5: Address derivation matches across implementations");
    }
}

#[test]
fn address_manager_cross_impl_compat() {
    // Both implementations' AddressManager should handle the same ratchet keys identically
    use impl_a::address::AddressManager as MgrA;
    use impl_b::address::AddressManager as MgrB;
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let mut mgr_a = MgrA::new();
    let mut mgr_b = MgrB::new();
    mgr_a.add_peer("peer1", None, None);
    mgr_b.add_peer("peer1", None, None);

    let mut alice = ParticipantA::new("alice", 1).unwrap();
    let mut bob = ParticipantB::new("bob", 1).unwrap();
    let bob_bundle = bob.prekey_bundle().unwrap();
    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

    let enc = alice.encrypt(&bob_addr, b"test").unwrap();
    bob.decrypt(&alice_addr, &enc.bytes).unwrap();

    if let Some(ref sa) = enc.sender_address {
        let update_a = mgr_a.on_encrypt("peer1", Some(sa)).unwrap();
        let update_b = mgr_b.on_encrypt("peer1", Some(sa)).unwrap();

        // Both should produce the same derived addresses
        assert_eq!(update_a.new_receiving.len(), update_b.new_receiving.len());
        if !update_a.new_receiving.is_empty() {
            assert_eq!(update_a.new_receiving[0], update_b.new_receiving[0],
                "derived addresses must match across impls");
        }
        eprintln!("✅ Phase 5: AddressManager produces same results in both impls");
    }
}

#[tokio::test]
async fn chat_session_cross_impl() {
    // ChatSession A sends → ChatSession B receives with full address rotation
    use impl_a::session::ChatSession as SessionA;
    use impl_b::session::ChatSession as SessionB;
    use impl_a::address::AddressManager as MgrA;
    use impl_b::address::AddressManager as MgrB;
    use impl_a::signal_session::SignalParticipant as ParticipantA;
    use impl_b::signal_session::SignalParticipant as ParticipantB;

    let alice_id = impl_a::Identity::generate().unwrap();
    let bob_id = impl_b::identity::Identity::generate().unwrap();

    let mut alice_signal = ParticipantA::new("alice", 1).unwrap();
    let mut bob_signal = ParticipantB::new("bob", 1).unwrap();

    let bob_bundle = bob_signal.prekey_bundle().unwrap();
    let alice_addr = libsignal_protocol::ProtocolAddress::new(
        alice_signal.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));
    let bob_addr = libsignal_protocol::ProtocolAddress::new(
        bob_signal.identity_public_key_hex(), libsignal_protocol::DeviceId::from(1));

    alice_signal.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();

    let bob_inbox = Keys::generate();
    let alice_inbox = Keys::generate();

    let alice_peer_id = bob_signal.identity_public_key_hex();
    let bob_peer_id = alice_signal.identity_public_key_hex();

    let mut alice_mgr = MgrA::new();
    alice_mgr.add_peer(&alice_peer_id, Some(bob_inbox.public_key().to_hex()), None);
    let mut bob_mgr = MgrB::new();
    bob_mgr.add_peer(&bob_peer_id, Some(alice_inbox.public_key().to_hex()), None);

    let mut alice_session = SessionA::new(alice_signal, alice_mgr, alice_id);
    let mut bob_session = SessionB::new(bob_signal, bob_mgr, bob_id);

    // msg1: Alice (impl_a) → Bob (impl_b)
    let msg1 = impl_a::message::KCMessage::text("Cross-impl session test!");
    let (ev1, _) = alice_session.send_message(&alice_peer_id, &bob_addr, &msg1).await.unwrap();
    let (received1, meta1, _) = bob_session.receive_message(&bob_peer_id, &alice_addr, &ev1).unwrap();
    assert_eq!(received1.text.as_ref().unwrap().content, "Cross-impl session test!");
    assert!(meta1.is_prekey_message);

    // msg2: Bob (impl_b) → Alice (impl_a)
    let msg2 = impl_b::message::KCMessage::text("Reply from B session!");
    let (ev2, _) = bob_session.send_message(&bob_peer_id, &alice_addr, &msg2).await.unwrap();
    let (received2, meta2, _) = alice_session.receive_message(&alice_peer_id, &bob_addr, &ev2).unwrap();
    assert_eq!(received2.text.as_ref().unwrap().content, "Reply from B session!");
    assert!(!meta2.is_prekey_message);

    // msg3: Alice → Bob (ratchet should be advancing)
    let msg3 = impl_a::message::KCMessage::text("Second from A");
    let (ev3, _) = alice_session.send_message(&alice_peer_id, &bob_addr, &msg3).await.unwrap();
    let (received3, _, _) = bob_session.receive_message(&bob_peer_id, &alice_addr, &ev3).unwrap();
    assert_eq!(received3.text.as_ref().unwrap().content, "Second from A");

    eprintln!("✅ Phase 5: ChatSession cross-impl with address rotation OK");
}
