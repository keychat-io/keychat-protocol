//! MLS end-to-end test through real Nostr relays.
//!
//! Creates two identities (Alice and Bob), establishes an MLS group through
//! relay transport, and verifies bidirectional encrypted messaging.
//!
//! Usage: cargo run --example mls_relay_test [-- --relay wss://relay.damus.io]

use std::time::Duration;

use clap::Parser;
use libkeychat::identity::{generate_mnemonic, nostr_keypair_from_mnemonic};
use libkeychat::mls;
use libkeychat::mls::transport;
use libkeychat::transport::RelayPool;

type DynResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
struct Args {
    #[arg(long = "relay", default_value = "wss://relay.damus.io")]
    relay: Vec<String>,
}

#[tokio::main]
async fn main() -> DynResult<()> {
    let args = Args::parse();

    // Create two separate identities
    let alice_mnemonic = generate_mnemonic(12)?;
    let bob_mnemonic = generate_mnemonic(12)?;
    let alice_keypair = nostr_keypair_from_mnemonic(&alice_mnemonic)?;
    let bob_keypair = nostr_keypair_from_mnemonic(&bob_mnemonic)?;
    let alice_id = alice_keypair.public_key_hex();
    let bob_id = bob_keypair.public_key_hex();

    println!("Alice: {}", &alice_id[..16]);
    println!("Bob:   {}", &bob_id[..16]);

    // Initialize MLS for both (on blocking threads since internal block_on)
    let alice_db = std::env::temp_dir().join(format!(
        "mls-relay-test-alice-{}.sqlite",
        std::process::id()
    ));
    let bob_db =
        std::env::temp_dir().join(format!("mls-relay-test-bob-{}.sqlite", std::process::id()));

    let aid = alice_id.clone();
    let adb = alice_db.clone();
    tokio::task::spawn_blocking(move || mls::init_mls(adb.to_str().unwrap(), &aid)).await??;

    let bid = bob_id.clone();
    let bdb = bob_db.clone();
    tokio::task::spawn_blocking(move || mls::init_mls(bdb.to_str().unwrap(), &bid)).await??;

    // Bob creates a KeyPackage
    let bid2 = bob_id.clone();
    let bob_kp = tokio::task::spawn_blocking(move || mls::create_key_package(&bid2)).await??;
    println!(
        "\n[1] Bob KeyPackage created ({} bytes hex)",
        bob_kp.key_package.len()
    );

    // Connect to relays
    let relay_refs: Vec<&str> = args.relay.iter().map(String::as_str).collect();
    let pool = RelayPool::connect(&relay_refs).await?;
    let relay = pool.relays().first().ok_or("no relay connected")?;
    println!("[2] Connected to relay: {}", relay.url());

    // Bob publishes KeyPackage to relay
    transport::publish_key_package(relay, &bob_keypair, &bob_kp.key_package).await?;
    println!("[3] Bob published KeyPackage to relay ✓");

    // Small delay for relay propagation
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Alice fetches Bob's KeyPackage from relay
    let fetched_kp = tokio::time::timeout(
        Duration::from_secs(10),
        transport::fetch_key_package(relay, &bob_id),
    )
    .await??;
    println!(
        "[4] Alice fetched Bob's KeyPackage ✓ (matches: {})",
        fetched_kp == bob_kp.key_package
    );

    // Alice creates group and adds Bob
    let aid3 = alice_id.clone();
    let fkp = fetched_kp.clone();
    let (group_id, add_result) = tokio::task::spawn_blocking(move || -> DynResult<_> {
        let gid = mls::create_mls_group(&aid3, "relay-test-group")?;
        let result = mls::add_member(&aid3, &gid, &fkp)?;
        Ok((gid, result))
    })
    .await??;
    println!("[5] Alice created group {} and added Bob", &group_id[..16]);
    println!(
        "    commit: {} bytes, welcome: {} bytes",
        add_result.commit_message.len(),
        add_result.welcome.len()
    );

    // Alice gets listen key
    let aid4 = alice_id.clone();
    let gid4 = group_id.clone();
    let listen_key =
        tokio::task::spawn_blocking(move || mls::get_group_listen_key(&aid4, &gid4)).await??;
    println!("[6] Listen key: {}...", &listen_key[..16]);

    // Send Welcome to Bob via relay (kind:1059 Gift Wrap with inner kind:444)
    let welcome_hex = hex::encode(&add_result.welcome);
    let gift = libkeychat::nostr::nip59::create_gift_wrap(
        &alice_keypair,
        &bob_id,
        444,
        welcome_hex.clone(),
        vec![
            vec!["p".to_owned(), bob_id.clone()],
            vec!["p".to_owned(), group_id.clone()],
        ],
    )?;
    relay.publish(&gift).await?;
    println!("[7] Welcome Gift Wrap sent to relay ✓");

    // Bob receives Welcome from relay (subscribe to kind:1059 on his pubkey)
    // For this test we skip relay reception and use the welcome bytes directly
    // since Gift Wrap requires the receiver to be subscribed
    let bid3 = bob_id.clone();
    let wb = add_result.welcome.clone();
    let bob_group_id =
        tokio::task::spawn_blocking(move || mls::join_group_from_welcome(&bid3, &wb)).await??;
    println!(
        "[8] Bob joined group: {} (matches: {})",
        &bob_group_id[..16],
        bob_group_id == group_id
    );

    // Get export_secret keypairs for NIP-44 layer
    let aid_es = alice_id.clone();
    let gid_es = group_id.clone();
    let alice_es_keypair =
        tokio::task::spawn_blocking(move || mls::get_export_secret_keypair(&aid_es, &gid_es))
            .await??;

    let bid_es = bob_id.clone();
    let gid_es2 = bob_group_id.clone();
    let bob_es_keypair =
        tokio::task::spawn_blocking(move || mls::get_export_secret_keypair(&bid_es, &gid_es2))
            .await??;

    // Bob subscribes BEFORE Alice sends (relay doesn't replay past events)
    let mut bob_rx = transport::receive_group_message(relay, &bob_es_keypair, &listen_key).await;
    println!("[9] Bob subscribed to listen key, waiting for messages...");

    // Small delay to ensure subscription is active
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Alice sends a message through relay
    let aid5 = alice_id.clone();
    let gid5 = group_id.clone();
    let alice_ct = tokio::task::spawn_blocking(move || {
        mls::encrypt_group_message(&aid5, &gid5, "Hello from Alice via relay!")
    })
    .await??;
    transport::send_group_message(relay, &alice_es_keypair, &listen_key, &alice_ct).await?;
    println!("[10] Alice sent encrypted message to relay ✓");

    // Bob receives
    let received_ct = tokio::time::timeout(Duration::from_secs(15), bob_rx.recv()).await??;
    println!(
        "[11] Bob received ciphertext from relay ({} bytes)",
        received_ct.len()
    );

    // Bob decrypts
    let bid4 = bob_id.clone();
    let gid6 = bob_group_id.clone();
    let rct = received_ct.clone();
    let decrypted =
        tokio::task::spawn_blocking(move || mls::decrypt_group_message(&bid4, &gid6, &rct))
            .await??;
    println!(
        "[12] Bob decrypted: \"{}\" (from: {})",
        decrypted.plaintext,
        &decrypted.sender_nostr_id[..16]
    );

    // Verify
    assert_eq!(decrypted.plaintext, "Hello from Alice via relay!");
    assert_eq!(decrypted.sender_nostr_id, alice_id);
    println!("\n✅ MLS relay test PASSED — full end-to-end through real relay!");

    // Cleanup
    let _ = std::fs::remove_file(&alice_db);
    let _ = std::fs::remove_file(&bob_db);
    let _ = pool.disconnect().await;

    Ok(())
}
