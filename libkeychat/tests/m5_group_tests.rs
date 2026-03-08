use libkeychat::group::{
    build_dissolve_message, build_group_message, build_invite_message, build_nickname_message,
    build_remove_member_message, build_rename_message, create_group, parse_group_message,
    types::{GroupEvent, GroupProfile},
};
use libkeychat::signal::SignalParticipant;

/// Helper: establish a bidirectional Signal session between two participants.
fn establish_session(alice: &mut SignalParticipant, bob: &mut SignalParticipant) {
    let bob_bundle = bob.prekey_bundle().expect("bob bundle");
    alice
        .process_prekey_bundle(bob.address(), &bob_bundle)
        .expect("process bundle");
    // Send initial message to complete session establishment
    let ct = alice.encrypt(bob.address(), b"init").expect("encrypt");
    bob.decrypt(alice.address(), &ct).expect("decrypt");
}

/// Helper: send a group payload through Signal and return decrypted string.
fn signal_roundtrip(
    sender: &mut SignalParticipant,
    receiver: &mut SignalParticipant,
    payload: &str,
) -> String {
    let ct = sender
        .encrypt(receiver.address(), payload.as_bytes())
        .expect("encrypt");
    let pt = receiver.decrypt(sender.address(), &ct).expect("decrypt");
    String::from_utf8(pt).expect("utf8")
}

#[test]
fn group_invite_through_signal_session() {
    let mut admin = SignalParticipant::new("admin", 1).unwrap();
    let mut member = SignalParticipant::new("member", 1).unwrap();
    establish_session(&mut admin, &mut member);

    // Admin creates group
    let result = create_group("admin_pubkey_hex", "Admin", "Test Group").unwrap();
    let invite_payload = build_invite_message(&result.profile, "Join my group!", "alice_pubkey");

    // Send invite through Signal session
    let decrypted = signal_roundtrip(&mut admin, &mut member, &invite_payload);

    // Member parses the invite
    let event =
        parse_group_message(&decrypted, "admin_pubkey_hex", &result.profile.pubkey).unwrap();
    match event {
        GroupEvent::Invite { profile, inviter } => {
            assert_eq!(profile.name, "Test Group");
            assert_eq!(profile.pubkey, result.profile.pubkey);
            assert_eq!(inviter, "admin_pubkey_hex");
            assert_eq!(profile.users.len(), 1);
        }
        other => panic!("expected Invite, got {:?}", other),
    }
}

#[test]
fn group_message_fanout_to_multiple_members() {
    let mut admin = SignalParticipant::new("admin-fanout", 1).unwrap();
    let mut bob = SignalParticipant::new("bob-fanout", 1).unwrap();
    let mut charlie = SignalParticipant::new("charlie-fanout", 1).unwrap();

    establish_session(&mut admin, &mut bob);
    establish_session(&mut admin, &mut charlie);

    let group_pubkey = "group_abc123";
    let msg_payload = build_group_message(group_pubkey, "admin_pk", "Hello everyone!");

    // Admin sends to Bob
    let bob_decrypted = signal_roundtrip(&mut admin, &mut bob, &msg_payload);
    let bob_event = parse_group_message(&bob_decrypted, "admin_pk", group_pubkey).unwrap();

    // Admin sends to Charlie
    let charlie_decrypted = signal_roundtrip(&mut admin, &mut charlie, &msg_payload);
    let charlie_event = parse_group_message(&charlie_decrypted, "admin_pk", group_pubkey).unwrap();

    // Both should receive the same content
    match (&bob_event, &charlie_event) {
        (
            GroupEvent::Message {
                content: bc,
                sender: bs,
                ..
            },
            GroupEvent::Message {
                content: cc,
                sender: cs,
                ..
            },
        ) => {
            assert_eq!(bc, "Hello everyone!");
            assert_eq!(cc, "Hello everyone!");
            assert_eq!(bs, "admin_pk");
            assert_eq!(cs, "admin_pk");
        }
        _ => panic!("expected Message events"),
    }
}

#[test]
fn group_management_events_through_signal() {
    let mut admin = SignalParticipant::new("admin-mgmt", 1).unwrap();
    let mut member = SignalParticipant::new("member-mgmt", 1).unwrap();
    establish_session(&mut admin, &mut member);

    let group_pubkey = "group_mgmt_test";

    // Test rename
    let rename_payload = build_rename_message("test_group_pubkey", "New Group Name");
    let decrypted = signal_roundtrip(&mut admin, &mut member, &rename_payload);
    let event = parse_group_message(&decrypted, "admin_pk", group_pubkey).unwrap();
    match event {
        GroupEvent::RoomNameChanged { new_name, .. } => {
            assert_eq!(new_name, "New Group Name");
        }
        other => panic!("expected RoomNameChanged, got {:?}", other),
    }

    // Test remove member
    let remove_payload = build_remove_member_message(group_pubkey, "kicked_member_pubkey");
    let decrypted = signal_roundtrip(&mut admin, &mut member, &remove_payload);
    let event = parse_group_message(&decrypted, "admin_pk", group_pubkey).unwrap();
    match event {
        GroupEvent::MemberRemoved { member_pubkey, .. } => {
            assert_eq!(member_pubkey, "kicked_member_pubkey");
        }
        other => panic!("expected MemberRemoved, got {:?}", other),
    }

    // Test dissolve
    let dissolve_payload = build_dissolve_message(group_pubkey);
    let decrypted = signal_roundtrip(&mut admin, &mut member, &dissolve_payload);
    let event = parse_group_message(&decrypted, "admin_pk", group_pubkey).unwrap();
    match event {
        GroupEvent::Dissolved { by, .. } => {
            assert_eq!(by, "admin_pk");
        }
        other => panic!("expected Dissolved, got {:?}", other),
    }

    // Test nickname change
    let nickname_payload = build_nickname_message("test_group_pubkey", "Cool Name");
    let decrypted = signal_roundtrip(&mut admin, &mut member, &nickname_payload);
    let event = parse_group_message(&decrypted, "admin_pk", group_pubkey).unwrap();
    match event {
        GroupEvent::NicknameChanged { new_name, .. } => {
            assert_eq!(new_name, "Cool Name");
        }
        other => panic!("expected NicknameChanged, got {:?}", other),
    }
}

#[test]
fn group_profile_serialization_matches_keychat_format() {
    let result = create_group("abc123def456", "Alice", "My Group").unwrap();
    let json = serde_json::to_string(&result.profile).unwrap();

    // Verify the JSON contains expected Keychat-compatible fields
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("pubkey").is_some());
    assert!(parsed.get("name").is_some());
    assert!(parsed.get("users").is_some());
    assert!(parsed.get("groupType").is_some()); // camelCase
    assert!(parsed.get("updatedAt").is_some()); // camelCase
    assert_eq!(parsed["groupType"], "sendAll");
    assert_eq!(parsed["name"], "My Group");

    // Verify deserialization roundtrip
    let deserialized: GroupProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.pubkey, result.profile.pubkey);
    assert_eq!(deserialized.name, "My Group");
}

#[test]
fn multiple_messages_maintain_signal_ratchet() {
    let mut admin = SignalParticipant::new("admin-ratchet", 1).unwrap();
    let mut member = SignalParticipant::new("member-ratchet", 1).unwrap();
    establish_session(&mut admin, &mut member);

    let group_pubkey = "group_ratchet_test";

    // Send 10 group messages — verify ratchet advances correctly
    for i in 0..10 {
        let msg = build_group_message(group_pubkey, "admin_pk", &format!("Message #{i}"));
        let decrypted = signal_roundtrip(&mut admin, &mut member, &msg);
        let event = parse_group_message(&decrypted, "admin_pk", group_pubkey).unwrap();
        match event {
            GroupEvent::Message { content, .. } => {
                assert_eq!(content, format!("Message #{i}"));
            }
            _ => panic!("expected Message"),
        }
    }

    // Member replies (bidirectional ratchet)
    let reply = build_group_message(group_pubkey, "member_pk", "Got all 10!");
    let decrypted = signal_roundtrip(&mut member, &mut admin, &reply);
    let event = parse_group_message(&decrypted, "member_pk", group_pubkey).unwrap();
    match event {
        GroupEvent::Message {
            content, sender, ..
        } => {
            assert_eq!(content, "Got all 10!");
            assert_eq!(sender, "member_pk");
        }
        _ => panic!("expected Message"),
    }
}
