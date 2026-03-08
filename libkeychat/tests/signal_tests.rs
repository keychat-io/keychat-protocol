use libkeychat::signal::SignalParticipant;

#[test]
fn full_session_establishment_and_roundtrip() {
    let mut alice = SignalParticipant::new("alice", 1).expect("alice");
    let mut bob = SignalParticipant::new("bob", 1).expect("bob");

    let bob_bundle = bob.prekey_bundle().expect("bundle");
    alice
        .process_prekey_bundle(bob.address(), &bob_bundle)
        .expect("process bundle");

    let first = alice.encrypt(bob.address(), b"hello bob").expect("encrypt");
    assert!(SignalParticipant::is_prekey_message(&first));

    let decrypted = bob.decrypt(alice.address(), &first).expect("decrypt");
    assert_eq!(decrypted, b"hello bob");
}

#[test]
fn bidirectional_exchange_advances_ratchet() {
    let mut alice = SignalParticipant::new("alice", 1).expect("alice");
    let mut bob = SignalParticipant::new("bob", 1).expect("bob");

    let bob_bundle = bob.prekey_bundle().expect("bundle");
    alice
        .process_prekey_bundle(bob.address(), &bob_bundle)
        .expect("process bundle");

    let first = alice.encrypt(bob.address(), b"m1").expect("encrypt");
    assert!(SignalParticipant::is_prekey_message(&first));

    let first_plain = bob.decrypt(alice.address(), &first).expect("decrypt");
    assert_eq!(first_plain, b"m1");
    let reply = bob.encrypt(alice.address(), b"reply").expect("encrypt");
    assert!(!SignalParticipant::is_prekey_message(&reply));
    let reply_plain = alice.decrypt(bob.address(), &reply).expect("decrypt");
    assert_eq!(reply_plain, b"reply");

    let second = alice.encrypt(bob.address(), b"m2").expect("encrypt");
    assert!(!SignalParticipant::is_prekey_message(&second));
    assert_ne!(first, second);
    let second_plain = bob.decrypt(alice.address(), &second).expect("decrypt");
    assert_eq!(second_plain, b"m2");
}

#[test]
fn prekey_message_detection_uses_parser() {
    let mut alice = SignalParticipant::new("alice", 1).expect("alice");
    let mut bob = SignalParticipant::new("bob", 1).expect("bob");

    let bob_bundle = bob.prekey_bundle().expect("bundle");
    alice
        .process_prekey_bundle(bob.address(), &bob_bundle)
        .expect("process bundle");

    let prekey_ciphertext = alice.encrypt(bob.address(), b"first").expect("encrypt");
    let _ = bob
        .decrypt(alice.address(), &prekey_ciphertext)
        .expect("decrypt");
    let normal_ciphertext = bob.encrypt(alice.address(), b"second").expect("encrypt");

    assert!(SignalParticipant::is_prekey_message(&prekey_ciphertext));
    assert!(!SignalParticipant::is_prekey_message(&normal_ciphertext));
}
