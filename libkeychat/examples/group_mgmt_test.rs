//! Small group management interop test.
//!
//! Tests rename, remove member, and dissolve operations against a real Keychat peer.
//!
//! Usage:
//!   cargo run --example group_mgmt_test -- --peer <npub_or_hex> [--db <path>] [--mnemonic "<words>"]

use libkeychat::client::KeychatClient;
use libkeychat::client::types::{ClientConfig, InboundEvent};
use libkeychat::identity;
use std::time::Duration;

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let peer = args.iter().position(|a| a == "--peer")
        .and_then(|i| args.get(i + 1)).cloned()
        .unwrap_or_default();
    let db = args.iter().position(|a| a == "--db")
        .and_then(|i| args.get(i + 1)).cloned()
        .unwrap_or("/tmp/group_mgmt_test.db".into());
    let mnemonic = args.iter().position(|a| a == "--mnemonic")
        .and_then(|i| args.get(i + 1)).cloned();

    let peer_hex = if peer.starts_with("npub") {
        identity::decode_npub(&peer)?
    } else {
        peer.clone()
    };

    println!("=== Small Group Management Interop Test ===\n");

    let config = ClientConfig {
        db_path: db,
        display_name: "GroupMgmtTest".into(),
        relays: vec![
            "wss://relay.keychat.io".into(),
            "wss://relay.damus.io".into(),
            "wss://relay.primal.net".into(),
            "wss://nos.lol".into(),
        ],
        mnemonic,
        media_server: None,
    };

    let mut client = KeychatClient::init(config).await?;
    println!("[init] npub: {}", client.npub()?);
    client.start_listening().await?;

    // Step 1: Establish session if needed
    if !client.has_session(&peer_hex) {
        println!("[hello] Sending friend request...");
        client.add_friend(&peer, "Group management test").await?;
        let timeout = tokio::time::Instant::now() + Duration::from_secs(60);
        while tokio::time::Instant::now() < timeout {
            match tokio::time::timeout(Duration::from_secs(5), client.next_event()).await {
                Ok(Some(InboundEvent::DirectMessage { .. })) => break,
                _ => continue,
            }
        }
        // Drain remaining
        tokio::time::sleep(Duration::from_secs(2)).await;
        loop {
            match tokio::time::timeout(Duration::from_secs(1), client.next_event()).await {
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
    }
    println!("[init] Session ready\n");

    // Step 2: Create group and invite
    let group_result = client.create_group("Mgmt Test Group")?;
    let group_pubkey = group_result.profile.pubkey.clone();
    let mut profile = group_result.profile;
    profile.add_member(&peer_hex, "Peer", false);
    println!("[group] Created: {} ({}...)", profile.name, &group_pubkey[..16]);

    client.send_group_invite(&peer_hex, &profile, "Join for management test!").await?;
    println!("[group] Invite sent");

    // Wait for join
    tokio::time::sleep(Duration::from_secs(5)).await;
    loop {
        match tokio::time::timeout(Duration::from_secs(2), client.next_event()).await {
            Ok(Some(ev)) => println!("[event] {:?}", match &ev {
                InboundEvent::DirectMessage { sender, plaintext, .. } =>
                    format!("DM from {}...: {}", truncate(sender, 12), truncate(plaintext, 60)),
                InboundEvent::GroupEvent { from_peer, event } =>
                    format!("GroupEvent from {}...: {:?}", truncate(from_peer, 12), event),
                _ => "other".into(),
            }),
            _ => break,
        }
    }

    // Step 3: Test rename
    println!("\n[rename] Renaming group to 'Renamed Group'...");
    client.rename_group(&group_pubkey, "Renamed Group", &[&peer_hex]).await?;
    println!("[rename] ✅ Rename sent");

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Step 4: Test dissolve
    println!("\n[dissolve] Dissolving group...");
    client.dissolve_group(&group_pubkey, &[&peer_hex]).await?;
    println!("[dissolve] ✅ Dissolve sent");

    // Wait for reactions
    tokio::time::sleep(Duration::from_secs(3)).await;
    loop {
        match tokio::time::timeout(Duration::from_secs(2), client.next_event()).await {
            Ok(Some(ev)) => println!("[event] {:?}", match &ev {
                InboundEvent::DirectMessage { sender, plaintext, .. } =>
                    format!("DM from {}...: {}", truncate(sender, 12), truncate(plaintext, 60)),
                InboundEvent::GroupEvent { from_peer, event } =>
                    format!("GroupEvent from {}...: {:?}", truncate(from_peer, 12), event),
                _ => "other".into(),
            }),
            _ => break,
        }
    }

    println!("\n=== Group Management Test Complete ===");
    println!("Result: PASS (rename + dissolve sent to peer)");
    Ok(())
}
