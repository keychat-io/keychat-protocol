use libkeychat::identity::bech32::{decode_npub, decode_nsec};
use libkeychat::identity::{
    generate_mnemonic, nostr_keypair_from_mnemonic, nostr_keypair_from_mnemonic_with_account,
    recover_mnemonic, InMemorySecretStore, SecretStore,
};

#[test]
fn mnemonic_generation_and_recovery_roundtrip() {
    let mnemonic = generate_mnemonic(12).expect("mnemonic");
    let recovered = recover_mnemonic(&mnemonic.to_string()).expect("recover");

    assert_eq!(mnemonic.to_string(), recovered.to_string());
}

#[test]
fn secret_store_keeps_mnemonic_in_memory() {
    let mnemonic = generate_mnemonic(12).expect("mnemonic");
    let mut store = InMemorySecretStore::default();
    store.store_mnemonic(mnemonic.clone());

    assert_eq!(
        store.load_mnemonic().expect("stored").to_string(),
        mnemonic.to_string()
    );

    store.clear();
    assert!(store.load_mnemonic().is_none());
}

#[test]
fn deterministic_nostr_key_derivation() {
    let mnemonic = recover_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .expect("recover");

    let default = nostr_keypair_from_mnemonic(&mnemonic).expect("keypair");
    let account_zero = nostr_keypair_from_mnemonic_with_account(&mnemonic, 0).expect("keypair");
    let account_one = nostr_keypair_from_mnemonic_with_account(&mnemonic, 1).expect("keypair");

    assert_eq!(default.secret_key_hex(), account_zero.secret_key_hex());
    assert_eq!(default.public_key_hex(), account_zero.public_key_hex());
    assert_ne!(account_zero.secret_key_hex(), account_one.secret_key_hex());
    assert_eq!(account_zero.public_key_hex().len(), 64);
}

#[test]
fn bech32_encoding_roundtrip() {
    let mnemonic = generate_mnemonic(12).expect("mnemonic");
    let keypair = nostr_keypair_from_mnemonic(&mnemonic).expect("keypair");

    let npub = keypair.npub().expect("npub");
    let nsec = keypair.nsec().expect("nsec");

    assert_eq!(
        decode_npub(&npub).expect("npub decode"),
        keypair.public_key_bytes()
    );
    assert_eq!(
        decode_nsec(&nsec).expect("nsec decode"),
        keypair.secret_key_bytes()
    );
}
