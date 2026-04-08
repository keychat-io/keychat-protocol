//! Full-flow integration test: friend requests, Signal messaging, groups, MLS, persistence.
//!
//! Covers:
//! 1. Alice adds Bob and Tom; both approve the friend requests.
//! 2. All three exchange Signal 1:1 messages.
//! 3. Alice creates a Signal small group and an MLS large group, invites both,
//!    each member sends messages, others decrypt.
//! 4. Persistence: sessions survive simulated restart (drop → reopen storage),
//!    ratchets continue without reset.

use std::sync::{Arc, Mutex};

use base64::Engine;
use libkeychat::{
    accept_friend_request_persistent, create_signal_group, generate_prekey_material,
    receive_friend_request, receive_group_message, receive_signal_message,
    send_friend_request_persistent, send_signal_message, serialize_prekey_material,
    AddressManager, EphemeralKeypair, GroupManager, Identity, KCMessage, KCMessageKind,
    MlsParticipant, ProtocolAddress, SecureStorage, SignalParticipant,
};
use libsignal_protocol::DeviceId;

fn device_id_1() -> DeviceId {
    DeviceId::new(1).unwrap()
}

/// A test participant that holds all state needed for the test.
struct TestUser {
    name: String,
    identity: Identity,
    /// Map: peer_signal_id → (SignalParticipant, ProtocolAddress, AddressManager)
    sessions: std::collections::HashMap<String, SessionEntry>,
    storage: Arc<Mutex<SecureStorage>>,
    db_path: String,
}

struct SessionEntry {
    signal: SignalParticipant,
    remote_addr: ProtocolAddress,
    addr_mgr: AddressManager,
}

impl TestUser {
    fn new(name: &str, dir: &std::path::Path) -> Self {
        let db_path = dir.join(format!("{name}.db")).to_string_lossy().to_string();
        let storage = Arc::new(Mutex::new(
            SecureStorage::open(&db_path, "test-key-123").unwrap(),
        ));
        Self {
            name: name.to_string(),
            identity: Identity::generate().unwrap().identity,
            sessions: std::collections::HashMap::new(),
            storage,
            db_path,
        }
    }

}

// ─── Part 1: Friend Requests ──────────────────────────────────────────────

/// Simulate Alice sending a friend request to Bob, Bob receiving and approving it.
/// Returns (alice_peer_signal_id (Bob's signal id seen by Alice),
///          bob_peer_signal_id (Alice's signal id seen by Bob)).
async fn do_friend_request(
    sender: &mut TestUser,
    receiver: &mut TestUser,
) -> (String, String) {
    // 1. Sender sends friend request (persistent)
    let keys = generate_prekey_material().unwrap();
    let (ser_pub, ser_priv, reg_id, spk_id, spk_rec, _pk_id, _pk_rec, _kpk_id, _kpk_rec) =
        serialize_prekey_material(&keys).unwrap();

    // Save participant data to storage
    let signal_id_hex = hex::encode(keys.identity_key_pair.identity_key().serialize());
    {
        let store = sender.storage.lock().unwrap();
        store
            .save_signal_participant(&signal_id_hex, 1, &ser_pub, &ser_priv, reg_id, spk_id, &spk_rec)
            .unwrap();
    }

    let (gift_wrap, fr_state) = send_friend_request_persistent(
        &sender.identity,
        &receiver.identity.pubkey_hex(),
        &sender.name,
        "device-1",
        keys,
        sender.storage.clone(),
        1,
    )
    .await
    .unwrap();

    // 2. Receiver receives friend request
    let received = receive_friend_request(&receiver.identity, &gift_wrap).unwrap();
    assert_eq!(received.payload.name, sender.name);

    // 3. Receiver accepts (persistent)
    let accept_keys = generate_prekey_material().unwrap();
    let (a_pub, a_priv, a_reg, a_spk_id, a_spk_rec, _, _, _, _) =
        serialize_prekey_material(&accept_keys).unwrap();
    let accept_signal_id = hex::encode(accept_keys.identity_key_pair.identity_key().serialize());
    {
        let store = receiver.storage.lock().unwrap();
        store
            .save_signal_participant(&accept_signal_id, 1, &a_pub, &a_priv, a_reg, a_spk_id, &a_spk_rec)
            .unwrap();
    }

    let accepted = accept_friend_request_persistent(
        &receiver.identity,
        &received,
        &receiver.name,
        accept_keys,
        receiver.storage.clone(),
        1,
    )
    .await
    .unwrap();

    // 4. Sender decrypts the approval
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&accepted.event.content)
        .unwrap();
    let bob_signal_id = accepted.signal_participant.identity_public_key_hex();
    let bob_signal_addr = ProtocolAddress::new(bob_signal_id.clone(), device_id_1());

    let mut alice_signal = fr_state.signal_participant;
    let decrypt_result = alice_signal.decrypt_bytes(&bob_signal_addr, &ciphertext).unwrap();

    let approve_json = String::from_utf8(decrypt_result).unwrap();
    let approve_msg = KCMessage::try_parse(&approve_json).unwrap();
    assert_eq!(approve_msg.kind, KCMessageKind::FriendApprove);

    let alice_signal_id = alice_signal.identity_public_key_hex();
    let alice_signal_addr = ProtocolAddress::new(alice_signal_id.clone(), device_id_1());

    // Set up address managers with firstInbox
    let bob_inbox = EphemeralKeypair::generate();
    let alice_inbox_hex = fr_state.first_inbox_keys.pubkey_hex();

    let mut sender_addr_mgr = AddressManager::new();
    sender_addr_mgr.add_peer(&bob_signal_id, Some(bob_inbox.pubkey_hex()), None);

    let mut receiver_addr_mgr = AddressManager::new();
    receiver_addr_mgr.add_peer(&alice_signal_id, Some(alice_inbox_hex), None);

    // Store sessions
    sender.sessions.insert(
        bob_signal_id.clone(),
        SessionEntry {
            signal: alice_signal,
            remote_addr: bob_signal_addr,
            addr_mgr: sender_addr_mgr,
        },
    );

    receiver.sessions.insert(
        alice_signal_id.clone(),
        SessionEntry {
            signal: accepted.signal_participant,
            remote_addr: alice_signal_addr,
            addr_mgr: receiver_addr_mgr,
        },
    );

    (bob_signal_id, alice_signal_id)
}

// ─── Part 2: 1:1 Signal Messaging ─────────────────────────────────────────

/// Send a message from sender to receiver and verify decryption.
async fn send_and_verify(
    sender: &mut TestUser,
    receiver: &mut TestUser,
    peer_signal_id_at_sender: &str,   // receiver's signal ID (key in sender's sessions)
    peer_signal_id_at_receiver: &str,  // sender's signal ID (key in receiver's sessions)
    text: &str,
) {
    let entry = sender.sessions.get_mut(peer_signal_id_at_sender).unwrap();
    let to_address = entry.addr_mgr.resolve_send_address(peer_signal_id_at_sender).unwrap();
    let msg = KCMessage::text(text);
    let event = send_signal_message(
        &mut entry.signal,
        &entry.remote_addr,
        &msg,
        &to_address,
    )
    .await
    .unwrap();

    let recv_entry = receiver.sessions.get_mut(peer_signal_id_at_receiver).unwrap();
    let (received, _dr) = receive_signal_message(
        &mut recv_entry.signal,
        &recv_entry.remote_addr,
        &event,
    )
    .unwrap();

    assert_eq!(received.kind, KCMessageKind::Text);
    assert_eq!(received.text.as_ref().unwrap().content, text);
}

// ─── Part 3: Signal Small Group ────────────────────────────────────────────

/// Create a Signal small group, send messages, verify decryption.
async fn test_signal_small_group(
    alice: &mut TestUser,
    bob: &mut TestUser,
    tom: &mut TestUser,
    // Alice's signal IDs as seen from her per-peer sessions
    alice_bob_signal_id: &str, // bob's signal id at alice
    alice_tom_signal_id: &str, // tom's signal id at alice
    bob_alice_signal_id: &str, // alice's signal id at bob
    tom_alice_signal_id: &str, // alice's signal id at tom
) {
    let bob_signal_id = alice_bob_signal_id.to_string();
    let tom_signal_id = alice_tom_signal_id.to_string();

    // In the per-peer identity architecture, Alice uses different Signal identities
    // for each peer. So each receiver's group view must list Alice with the signal ID
    // that receiver knows Alice by.

    // Bob's view of the group: Alice identified by bob_alice_signal_id
    let bob_group = create_signal_group(
        "Test Signal Group",
        &bob_alice_signal_id,
        &alice.identity.pubkey_hex(),
        &alice.name,
        vec![
            (bob_signal_id.clone(), "bob_npub".into(), bob.name.clone()),
            (tom_signal_id.clone(), "tom_npub".into(), tom.name.clone()),
        ],
    );
    // Override group_id so both views share the same ID
    let group_id = bob_group.group_id.clone();

    let mut bob_groups = GroupManager::new();
    let mut bg = bob_group.clone();
    bg.my_signal_id = bob_signal_id.clone();
    bob_groups.add_group(bg);

    // Tom's view: Alice identified by tom_alice_signal_id
    let tom_group = create_signal_group(
        "Test Signal Group",
        &tom_alice_signal_id,
        &alice.identity.pubkey_hex(),
        &alice.name,
        vec![
            (bob_signal_id.clone(), "bob_npub".into(), bob.name.clone()),
            (tom_signal_id.clone(), "tom_npub".into(), tom.name.clone()),
        ],
    );

    let mut tom_groups = GroupManager::new();
    let mut tg = tom_group.clone();
    tg.my_signal_id = tom_signal_id.clone();
    // Override the group_id to match
    tg.group_id = group_id.clone();
    tom_groups.add_group(tg);

    // Alice sends a group message to Bob (via her per-peer session with Bob)
    let mut group_msg = KCMessage::text("Hello Signal group from Alice!");
    group_msg.group_id = Some(group_id.clone());

    let alice_bob_entry = alice.sessions.get_mut(alice_bob_signal_id).unwrap();
    let bob_event = libkeychat::encrypt_for_group_member(
        &mut alice_bob_entry.signal,
        &bob_signal_id,
        &group_msg,
        &alice_bob_entry.addr_mgr,
    )
    .await
    .unwrap();

    let bob_entry = bob.sessions.get_mut(bob_alice_signal_id).unwrap();
    let (received, metadata) = receive_group_message(
        &mut bob_entry.signal,
        &bob_entry.remote_addr,
        &bob_event,
        &bob_groups,
    )
    .unwrap();
    assert_eq!(received.text.as_ref().unwrap().content, "Hello Signal group from Alice!");
    assert_eq!(metadata.group_id, group_id);

    // Alice sends the same group message to Tom (via her per-peer session with Tom)
    let mut group_msg_tom = KCMessage::text("Hello Signal group from Alice!");
    group_msg_tom.group_id = Some(group_id.clone());

    let alice_tom_entry = alice.sessions.get_mut(alice_tom_signal_id).unwrap();
    let tom_event = libkeychat::encrypt_for_group_member(
        &mut alice_tom_entry.signal,
        &tom_signal_id,
        &group_msg_tom,
        &alice_tom_entry.addr_mgr,
    )
    .await
    .unwrap();

    let tom_entry = tom.sessions.get_mut(tom_alice_signal_id).unwrap();
    let (received_tom, metadata_tom) = receive_group_message(
        &mut tom_entry.signal,
        &tom_entry.remote_addr,
        &tom_event,
        &tom_groups,
    )
    .unwrap();
    assert_eq!(received_tom.text.as_ref().unwrap().content, "Hello Signal group from Alice!");
    assert_eq!(metadata_tom.group_id, group_id);

    println!("[Signal Group] All members received group messages successfully");
}

// ─── Part 4: MLS Large Group ──────────────────────────────────────────────

fn test_mls_large_group() {
    let alice_mls = MlsParticipant::new("alice_mls").unwrap();
    let bob_mls = MlsParticipant::new("bob_mls").unwrap();
    let tom_mls = MlsParticipant::new("tom_mls").unwrap();

    let group_id = "mls-test-group-001";

    // Alice creates MLS group
    alice_mls.create_group(group_id, "MLS Test Group").unwrap();

    // Bob and Tom generate key packages
    let bob_kp = bob_mls.generate_key_package().unwrap();
    let tom_kp = tom_mls.generate_key_package().unwrap();

    // Alice adds Bob and Tom
    let (_commit, welcome) = alice_mls.add_members(group_id, vec![bob_kp, tom_kp]).unwrap();

    // Bob and Tom join
    let joined_bob = bob_mls.join_group(&welcome).unwrap();
    assert_eq!(joined_bob, group_id);
    let joined_tom = tom_mls.join_group(&welcome).unwrap();
    assert_eq!(joined_tom, group_id);

    // Alice sends a message
    let msg = KCMessage::text("Hello MLS group from Alice!");
    let plaintext = msg.to_json().unwrap();
    let ciphertext = alice_mls.encrypt(group_id, plaintext.as_bytes()).unwrap();

    // Bob decrypts
    let (decrypted_bob, sender_bob) = bob_mls.decrypt(group_id, &ciphertext).unwrap();
    let dec_msg_bob = KCMessage::try_parse(&String::from_utf8(decrypted_bob).unwrap()).unwrap();
    assert_eq!(dec_msg_bob.text.as_ref().unwrap().content, "Hello MLS group from Alice!");
    assert_eq!(sender_bob, "alice_mls");

    // Tom decrypts
    let (decrypted_tom, sender_tom) = tom_mls.decrypt(group_id, &ciphertext).unwrap();
    let dec_msg_tom = KCMessage::try_parse(&String::from_utf8(decrypted_tom).unwrap()).unwrap();
    assert_eq!(dec_msg_tom.text.as_ref().unwrap().content, "Hello MLS group from Alice!");
    assert_eq!(sender_tom, "alice_mls");

    // Bob sends a message
    let bob_msg = KCMessage::text("Bob reporting in MLS!");
    let bob_pt = bob_msg.to_json().unwrap();
    let bob_ct = bob_mls.encrypt(group_id, bob_pt.as_bytes()).unwrap();

    let (dec_alice, sender) = alice_mls.decrypt(group_id, &bob_ct).unwrap();
    let dec_alice_msg = KCMessage::try_parse(&String::from_utf8(dec_alice).unwrap()).unwrap();
    assert_eq!(dec_alice_msg.text.as_ref().unwrap().content, "Bob reporting in MLS!");
    assert_eq!(sender, "bob_mls");

    let (dec_tom2, sender2) = tom_mls.decrypt(group_id, &bob_ct).unwrap();
    let dec_tom2_msg = KCMessage::try_parse(&String::from_utf8(dec_tom2).unwrap()).unwrap();
    assert_eq!(dec_tom2_msg.text.as_ref().unwrap().content, "Bob reporting in MLS!");
    assert_eq!(sender2, "bob_mls");

    // Tom sends a message
    let tom_msg = KCMessage::text("Tom here in MLS!");
    let tom_pt = tom_msg.to_json().unwrap();
    let tom_ct = tom_mls.encrypt(group_id, tom_pt.as_bytes()).unwrap();

    let (dec_a3, s3) = alice_mls.decrypt(group_id, &tom_ct).unwrap();
    let dec_a3_msg = KCMessage::try_parse(&String::from_utf8(dec_a3).unwrap()).unwrap();
    assert_eq!(dec_a3_msg.text.as_ref().unwrap().content, "Tom here in MLS!");
    assert_eq!(s3, "tom_mls");

    let (dec_b3, s4) = bob_mls.decrypt(group_id, &tom_ct).unwrap();
    let dec_b3_msg = KCMessage::try_parse(&String::from_utf8(dec_b3).unwrap()).unwrap();
    assert_eq!(dec_b3_msg.text.as_ref().unwrap().content, "Tom here in MLS!");
    assert_eq!(s4, "tom_mls");

    println!("[MLS Group] All members sent and received messages successfully");
}

// ─── Part 5: Persistence / Restart ────────────────────────────────────────

/// Simulate restart: drop the SignalParticipant, reopen storage, restore_persistent,
/// and continue messaging. The ratchet should advance from where it left off.
async fn test_persistence_restart(
    sender: &mut TestUser,
    receiver: &mut TestUser,
    peer_id_at_sender: &str,
    peer_id_at_receiver: &str,
) {
    // Record ratchet state before restart — encrypt a message to advance ratchet
    let pre_restart_msg = KCMessage::text("pre-restart canary");
    let entry = sender.sessions.get_mut(peer_id_at_sender).unwrap();
    let to_addr = entry.addr_mgr.resolve_send_address(peer_id_at_sender).unwrap();
    let event = send_signal_message(
        &mut entry.signal,
        &entry.remote_addr,
        &pre_restart_msg,
        &to_addr,
    )
    .await
    .unwrap();

    let recv_entry = receiver.sessions.get_mut(peer_id_at_receiver).unwrap();
    let (dec, _) = receive_signal_message(
        &mut recv_entry.signal,
        &recv_entry.remote_addr,
        &event,
    )
    .unwrap();
    assert_eq!(dec.text.as_ref().unwrap().content, "pre-restart canary");

    // Save sender's participant to persistent storage, then "restart"
    let entry = sender.sessions.get(peer_id_at_sender).unwrap();
    let ikp = entry.signal.identity_key_pair();
    let id_pub = ikp.identity_key().serialize().to_vec();
    let id_priv = ikp.private_key().serialize().to_vec();
    let reg_id = 1u32; // simplified for test
    {
        let store = sender.storage.lock().unwrap();
        store
            .save_signal_participant(
                peer_id_at_sender,
                1,
                &id_pub,
                &id_priv,
                reg_id,
                1, // spk_id
                &[], // spk_rec — not needed for restore_persistent
            )
            .unwrap();
    }

    // Simulate process restart: replace storage with freshly opened DB
    let new_storage = Arc::new(Mutex::new(
        SecureStorage::open(&sender.db_path, "test-key-123").unwrap(),
    ));
    sender.storage = new_storage.clone();

    // Restore participant from persistent storage
    let identity_key = libsignal_protocol::IdentityKey::decode(&id_pub).unwrap();
    let private_key = libsignal_protocol::PrivateKey::deserialize(&id_priv).unwrap();
    let identity_key_pair = libsignal_protocol::IdentityKeyPair::new(identity_key, private_key);

    let restored_signal = SignalParticipant::restore_persistent(
        sender.identity.pubkey_hex(),
        1,
        identity_key_pair,
        reg_id,
        new_storage,
    )
    .unwrap();

    // Replace the session with the restored one (keep the same addr_mgr + remote_addr)
    let entry = sender.sessions.get_mut(peer_id_at_sender).unwrap();
    let old_remote = entry.remote_addr.clone();
    let old_addr_mgr = entry.addr_mgr.clone();
    *entry = SessionEntry {
        signal: restored_signal,
        remote_addr: old_remote,
        addr_mgr: old_addr_mgr,
    };

    // Post-restart: sender sends another message — ratchet must continue, NOT reset
    let post_restart_msg = KCMessage::text("post-restart message");
    let entry = sender.sessions.get_mut(peer_id_at_sender).unwrap();
    let to_addr = entry.addr_mgr.resolve_send_address(peer_id_at_sender).unwrap();
    let post_event = send_signal_message(
        &mut entry.signal,
        &entry.remote_addr,
        &post_restart_msg,
        &to_addr,
    )
    .await
    .unwrap();

    // Receiver decrypts post-restart message
    let recv_entry = receiver.sessions.get_mut(peer_id_at_receiver).unwrap();
    let (dec2, _) = receive_signal_message(
        &mut recv_entry.signal,
        &recv_entry.remote_addr,
        &post_event,
    )
    .unwrap();
    assert_eq!(dec2.text.as_ref().unwrap().content, "post-restart message");

    // Verify bidirectional: receiver sends back after sender's restart
    let reply_msg = KCMessage::text("reply after your restart");
    let recv_entry = receiver.sessions.get_mut(peer_id_at_receiver).unwrap();
    let recv_to = recv_entry.addr_mgr.resolve_send_address(peer_id_at_receiver).unwrap();
    let reply_event = send_signal_message(
        &mut recv_entry.signal,
        &recv_entry.remote_addr,
        &reply_msg,
        &recv_to,
    )
    .await
    .unwrap();

    let entry = sender.sessions.get_mut(peer_id_at_sender).unwrap();
    let (dec3, _) = receive_signal_message(
        &mut entry.signal,
        &entry.remote_addr,
        &reply_event,
    )
    .unwrap();
    assert_eq!(dec3.text.as_ref().unwrap().content, "reply after your restart");

    println!(
        "[Persistence] {} <-> {}: ratchet survived restart, bidirectional messaging works",
        sender.name, receiver.name
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Main test
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn full_flow_friend_request_messaging_groups_persistence() {
    let tmp = tempfile::tempdir().unwrap();

    let mut alice = TestUser::new("Alice", tmp.path());
    let mut bob = TestUser::new("Bob", tmp.path());
    let mut tom = TestUser::new("Tom", tmp.path());

    println!("=== Phase 1: Friend Requests ===");

    // Alice adds Bob
    let (alice_bob_peer, bob_alice_peer) = do_friend_request(&mut alice, &mut bob).await;
    println!("[FR] Alice <-> Bob established: alice sees bob as {}", &alice_bob_peer[..16]);

    // Alice adds Tom
    let (alice_tom_peer, tom_alice_peer) = do_friend_request(&mut alice, &mut tom).await;
    println!("[FR] Alice <-> Tom established: alice sees tom as {}", &alice_tom_peer[..16]);

    // Bob adds Tom (so all three are friends)
    let (bob_tom_peer, tom_bob_peer) = do_friend_request(&mut bob, &mut tom).await;
    println!("[FR] Bob <-> Tom established: bob sees tom as {}", &bob_tom_peer[..16]);

    println!("\n=== Phase 2: 1:1 Signal Messaging ===");

    // Alice → Bob
    send_and_verify(&mut alice, &mut bob, &alice_bob_peer, &bob_alice_peer, "Hello Bob from Alice!").await;
    // Bob → Alice
    send_and_verify(&mut bob, &mut alice, &bob_alice_peer, &alice_bob_peer, "Hello Alice from Bob!").await;
    println!("[1:1] Alice <-> Bob: bidirectional OK");

    // Alice → Tom
    send_and_verify(&mut alice, &mut tom, &alice_tom_peer, &tom_alice_peer, "Hello Tom from Alice!").await;
    // Tom → Alice
    send_and_verify(&mut tom, &mut alice, &tom_alice_peer, &alice_tom_peer, "Hello Alice from Tom!").await;
    println!("[1:1] Alice <-> Tom: bidirectional OK");

    // Bob → Tom
    send_and_verify(&mut bob, &mut tom, &bob_tom_peer, &tom_bob_peer, "Hello Tom from Bob!").await;
    // Tom → Bob
    send_and_verify(&mut tom, &mut bob, &tom_bob_peer, &bob_tom_peer, "Hello Bob from Tom!").await;
    println!("[1:1] Bob <-> Tom: bidirectional OK");

    // Multiple messages in sequence to exercise ratchet advancement
    for i in 1..=5 {
        let text = format!("Ratchet msg #{i} from Alice");
        send_and_verify(&mut alice, &mut bob, &alice_bob_peer, &bob_alice_peer, &text).await;
    }
    for i in 1..=5 {
        let text = format!("Ratchet msg #{i} from Bob");
        send_and_verify(&mut bob, &mut alice, &bob_alice_peer, &alice_bob_peer, &text).await;
    }
    println!("[1:1] Ratchet advancement (10 messages alternating): OK");

    println!("\n=== Phase 3a: Signal Small Group ===");

    test_signal_small_group(
        &mut alice, &mut bob, &mut tom,
        &alice_bob_peer, &alice_tom_peer,
        &bob_alice_peer, &tom_alice_peer,
    )
    .await;

    println!("\n=== Phase 3b: MLS Large Group ===");

    test_mls_large_group();

    println!("\n=== Phase 4: Persistence / Restart ===");

    // Test persistence for Alice-Bob session
    test_persistence_restart(
        &mut alice, &mut bob,
        &alice_bob_peer, &bob_alice_peer,
    )
    .await;

    // Test persistence for Bob-Tom session
    test_persistence_restart(
        &mut bob, &mut tom,
        &bob_tom_peer, &tom_bob_peer,
    )
    .await;

    println!("\n=== All phases passed! ===");
}
